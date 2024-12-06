# frozen_string_literal: true

module AtprotoAuth
  # Main client class for AT Protocol OAuth implementation. Handles the complete
  # OAuth flow including authorization, token management, and identity verification.
  class Client
    # Error raised when authorization callback fails
    class CallbackError < Error; end

    # Error raised when token operations fail
    class TokenError < Error; end

    # Error raised when session operations fail
    class SessionError < Error
      attr_reader :session_id

      def initialize(message, session_id: nil)
        @session_id = session_id
        super(message)
      end
    end

    # @return [String] OAuth client ID
    attr_reader :client_id
    # @return [String] OAuth redirect URI
    attr_reader :redirect_uri
    # @return [ClientMetadata] Validated client metadata
    attr_reader :client_metadata
    # @return [SessionManager] Session state manager
    attr_reader :session_manager
    # @return [Identity::Resolver] Identity resolver
    attr_reader :identity_resolver
    # @return [DPoP::Client] DPoP client
    attr_reader :dpop_client

    # Creates a new AT Protocol OAuth client
    # @param client_id [String] OAuth client ID URL
    # @param redirect_uri [String] OAuth redirect URI
    # @param metadata [Hash, nil] Optional pre-loaded client metadata
    # @param dpop_key [Hash, nil] Optional existing DPoP key in JWK format
    # @raise [Error] if configuration is invalid
    def initialize(client_id:, redirect_uri:, metadata: nil, dpop_key: nil)
      @client_id = client_id
      @redirect_uri = redirect_uri

      # Initialize core dependencies
      @client_metadata = load_client_metadata(metadata)
      validate_redirect_uri!

      @session_manager = State::SessionManager.new
      @identity_resolver = Identity::Resolver.new
      @dpop_client = initialize_dpop(dpop_key)
    end

    # Begins an authorization flow and generates authorization URL
    # @param handle [String, nil] Optional user handle
    # @param pds_url [String, nil] Optional PDS URL
    # @param scope [String] OAuth scope (must include "atproto")
    # @return [Hash] Authorization details including :url and :session_id
    # @raise [Error] if parameters are invalid or resolution fails
    def authorize(handle: nil, pds_url: nil, scope: "atproto")
      validate_auth_params!(handle, pds_url, scope)

      # Create new session
      session = session_manager.create_session(
        client_id: client_id,
        scope: scope
      )

      # Store session with storage backend
      session_manager.update_session(session)

      # Resolve identity and authorization server if handle provided
      if handle
        auth_info = resolve_from_handle(handle, session)
      elsif pds_url
        auth_info = resolve_from_pds(pds_url, session)
      else
        raise Error, "Either handle or pds_url must be provided"
      end

      # Generate authorization URL
      auth_url = generate_authorization_url(
        auth_info[:server],
        session,
        login_hint: handle
      )

      {
        url: auth_url,
        session_id: session.session_id
      }
    end

    # Handles the authorization callback and completes token exchange
    # @param code [String] Authorization code from callback
    # @param state [String] State parameter from callback
    # @param iss [String] Issuer from callback (required by AT Protocol OAuth)
    # @return [Hash] Token response including :access_token and :session_id
    # @raise [CallbackError] if callback validation fails
    # @raise [TokenError] if token exchange fails
    def handle_callback(code:, state:, iss:)
      # Find and validate session
      session = session_manager.get_session_by_state(state)
      raise CallbackError, "Invalid state parameter" unless session

      # Verify issuer matches session
      raise CallbackError, "Issuer mismatch" unless session.auth_server && session.auth_server.issuer == iss

      AtprotoAuth.storage.with_lock(Storage::KeyBuilder.lock_key("session", session.session_id), ttl: 30) do
        # Exchange code for tokens
        token_response = exchange_code(
          code: code,
          session: session
        )

        # Validate token response
        validate_token_response!(token_response, session)

        # Create token set and store in session
        token_set = State::TokenSet.new(
          access_token: token_response["access_token"],
          token_type: token_response["token_type"],
          expires_in: token_response["expires_in"],
          refresh_token: token_response["refresh_token"],
          scope: token_response["scope"],
          sub: token_response["sub"]
        )
        session.tokens = token_set

        # Update stored session
        session_manager.update_session(session)

        {
          access_token: token_set.access_token,
          token_type: token_set.token_type,
          expires_in: (token_set.expires_at - Time.now).to_i,
          refresh_token: token_set.refresh_token,
          scope: token_set.scope,
          session_id: session.session_id
        }
      end
    end

    # Gets active tokens for a session
    # @param session_id [String] ID of session to get tokens for
    # @return [Hash, nil] Current token information if session exists and is authorized
    def get_tokens(session_id)
      session = session_manager.get_session(session_id)
      return nil unless session&.authorized?

      {
        access_token: session.tokens.access_token,
        token_type: session.tokens.token_type,
        expires_in: (session.tokens.expires_at - Time.now).to_i,
        refresh_token: session.tokens.refresh_token,
        scope: session.tokens.scope
      }
    end

    # Refreshes tokens for a session
    # @param session_id [String] ID of session to refresh
    def refresh_token(session_id)
      session = session_manager.get_session(session_id)
      raise TokenError, "Invalid session" unless session
      raise TokenError, "Session not authorized" unless session.renewable?

      AtprotoAuth.storage.with_lock(Storage::KeyBuilder.lock_key("session", session.session_id), ttl: 30) do
        refresher = Token::Refresh.new(
          session: session,
          dpop_client: @dpop_client,
          auth_server: session.auth_server,
          client_metadata: client_metadata
        )

        new_tokens = refresher.perform!
        session.tokens = new_tokens

        # Update stored session
        session_manager.update_session(session)

        {
          access_token: new_tokens.access_token,
          token_type: new_tokens.token_type,
          expires_in: (new_tokens.expires_at - Time.now).to_i,
          refresh_token: new_tokens.refresh_token,
          scope: new_tokens.scope,
          session_id: session.session_id
        }
      end
    end

    # Checks if a session has valid tokens
    # @param session_id [String] ID of session to check
    # @return [Boolean] true if session exists and has valid tokens
    def authorized?(session_id)
      session = session_manager.get_session(session_id)
      session&.authorized? || false
    end

    # Generates headers for an authenticated request
    # @param session_id [String] ID of session to use
    # @param method [String] HTTP method for the request
    # @param url [String] Full URL for the request
    # @return [Hash] Headers to add to request
    # @raise [TokenError] if session is invalid or unauthorized
    def auth_headers(session_id:, method:, url:)
      session = session_manager.get_session(session_id)
      raise TokenError, "Invalid session" unless session
      raise TokenError, "Session not authorized" unless session.authorized?

      # Generate DPoP proof
      proof = dpop_client.generate_proof(
        http_method: method,
        http_uri: url,
        access_token: session.tokens.access_token
      )

      {
        "Authorization" => "DPoP #{session.tokens.access_token}",
        "DPoP" => proof
      }
    end

    # Removes a session and its stored data
    # @param session_id [String] ID of session to remove
    # @return [void]
    def remove_session(session_id)
      key = Storage::KeyBuilder.session_key(session_id)
      AtprotoAuth.storage.delete(key)
      session_manager.remove_session(session_id)
    end

    # Cleans up expired sessions from storage
    # @return [void]
    def cleanup_expired_sessions
      session_manager.cleanup_expired
    end

    private

    def load_client_metadata(metadata)
      if metadata
        ClientMetadata.new(metadata)
      else
        ClientMetadata.from_url(@client_id)
      end
    end

    def validate_redirect_uri!
      valid = @client_metadata.redirect_uris.include?(@redirect_uri)
      raise Error, "redirect_uri not found in client metadata" unless valid
    end

    def initialize_dpop(key)
      key_manager = if key
                      DPoP::KeyManager.from_jwk(key)
                    else
                      DPoP::KeyManager.new
                    end

      DPoP::Client.new(key_manager: key_manager)
    end

    def validate_auth_params!(handle, pds_url, scope)
      raise Error, "scope must include 'atproto'" unless scope.split.include?("atproto")
      raise Error, "handle or pds_url must be provided" if handle.nil? && pds_url.nil?
      raise Error, "cannot provide both handle and pds_url" if handle && pds_url
    end

    def resolve_from_handle(handle, session)
      # Resolve handle to DID document
      resolution = @identity_resolver.resolve_handle(handle)
      session.did = resolution[:did]

      # Get authorization server from PDS
      server = resolve_auth_server(resolution[:pds])
      session.authorization_server = server

      # Update stored session
      session_manager.update_session(session)

      { server: server, pds: resolution[:pds] }
    end

    def resolve_from_pds(pds_url, session)
      # Get authorization server from PDS
      server = resolve_auth_server(pds_url)
      session.authorization_server = server

      # Update stored session
      session_manager.update_session(session)

      { server: server, pds: pds_url }
    end

    def resolve_auth_server(pds_url)
      # Get resource server metadata
      resource_server = ServerMetadata::ResourceServer.from_url(pds_url)
      auth_server_url = resource_server.authorization_servers.first

      # Get and validate authorization server metadata
      ServerMetadata::AuthorizationServer.from_issuer(auth_server_url)
    end

    def generate_authorization_url(auth_server, session, login_hint: nil)
      # Create PAR client
      par_client = PAR::Client.new(
        endpoint: auth_server.pushed_authorization_request_endpoint,
        dpop_client: @dpop_client
      )

      signing_key = if client_metadata.jwks && !client_metadata.jwks["keys"].empty?
                      key_data = client_metadata.jwks["keys"].first
                      JOSE::JWK.from_map(key_data)
                    else
                      JOSE::JWK.generate_key([:ec, "P-256"])
                    end

      client_assertion = PAR::ClientAssertion.new(
        client_id: client_id,
        signing_key: signing_key
      )

      # Build PAR request
      par_request = PAR::Request.build do |config|
        config.client_id = client_id
        config.redirect_uri = redirect_uri
        config.state = session.state_token
        config.scope = session.scope
        config.login_hint = login_hint if login_hint

        # Add PKCE parameters
        config.code_challenge = session.pkce_challenge
        config.code_challenge_method = "S256"

        # Add client assertion
        config.client_assertion = client_assertion.generate_jwt(
          audience: auth_server.issuer
        )
        config.client_assertion_type = PAR::CLIENT_ASSERTION_TYPE

        # Add DPoP proof
        proof = @dpop_client.generate_proof(
          http_method: "POST",
          http_uri: auth_server.pushed_authorization_request_endpoint
        )
        config.dpop_proof = proof
      end

      # Submit PAR request
      response = par_client.submit(par_request)

      # Build final authorization URL
      par_client.authorization_url(
        authorize_endpoint: auth_server.authorization_endpoint,
        request_uri: response.request_uri,
        client_id: client_id
      )
    end

    def exchange_code(code:, session:)
      # Initial token request without nonce
      response = make_token_request(code, session)

      # Handle DPoP nonce requirement
      if requires_dpop_nonce?(response)
        # Extract and store nonce from error response
        extract_dpop_nonce(response)
        dpop_client.process_response(response[:headers], session.auth_server.issuer)

        # Retry request with nonce
        response = make_token_request(code, session)
      end

      raise TokenError, "Token request failed: #{response[:status]}" unless response[:status] == 200

      begin
        JSON.parse(response[:body])
      rescue JSON::ParserError => e
        raise TokenError, "Invalid token response: #{e.message}"
      end
    end

    def make_token_request(code, session)
      # Generate proof
      proof = dpop_client.generate_proof(
        http_method: "POST",
        http_uri: session.auth_server.token_endpoint
      )

      body = {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri,
        client_id: client_id,
        code_verifier: session.pkce_verifier
      }

      # Add client authentication
      if client_metadata.confidential?
        signing_key = JOSE::JWK.from_map(client_metadata.jwks["keys"].first)
        client_assertion = PAR::ClientAssertion.new(
          client_id: client_id,
          signing_key: signing_key
        )

        body.merge!(
          client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
          client_assertion: client_assertion.generate_jwt(
            audience: session.auth_server.issuer
          )
        )
      end

      AtprotoAuth.configuration.http_client.post(
        session.auth_server.token_endpoint,
        body: body,
        headers: {
          "Content-Type" => "application/x-www-form-urlencoded",
          "DPoP" => proof
        }
      )
    end

    def requires_dpop_nonce?(response)
      return false unless response[:status] == 400

      error_data = JSON.parse(response[:body])
      error_data["error"] == "use_dpop_nonce"
    rescue JSON::ParserError
      false
    end

    def extract_dpop_nonce(response)
      headers = response[:headers]
      nonce = headers["DPoP-Nonce"] ||
              headers["dpop-nonce"] ||
              headers["Dpop-Nonce"]

      raise TokenError, "No DPoP nonce provided in error response" unless nonce

      nonce
    end

    def validate_token_response!(response, session)
      # Required fields
      %w[access_token token_type expires_in scope sub].each do |field|
        raise TokenError, "Missing #{field} in token response" unless response[field]
      end

      # Token type must be DPoP
      raise TokenError, "Invalid token_type: #{response["token_type"]}" unless response["token_type"] == "DPoP"

      # Scope must include atproto
      raise TokenError, "Missing atproto scope in token response" unless response["scope"].split.include?("atproto")

      # If we have a pre-resolved DID, verify it matches
      raise TokenError, "Subject mismatch in token response" if session.did && session.did != response["sub"]

      # Process DPoP-Nonce from response headers if present
      return unless response[:headers] && response[:headers]["DPoP-Nonce"]

      dpop_client.process_response(
        response[:headers],
        session.auth_server.issuer
      )
    end
  end
end
