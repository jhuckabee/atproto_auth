# frozen_string_literal: true

module AtprotoAuth
  module PAR
    # Client for making Pushed Authorization Requests (PAR) according to RFC 9126.
    # Handles submitting authorization parameters to the PAR endpoint and building
    # the subsequent authorization URL.
    #
    # In AT Protocol OAuth, all authorization requests must first go through PAR.
    # This means instead of sending authorization parameters directly to the
    # authorization endpoint, clients:
    # 1. Submit parameters to the PAR endpoint via POST
    # 2. Receive a request_uri in response
    # 3. Use only the request_uri and client_id in the authorization redirect
    #
    # @example Basic PAR flow
    #   client = AtprotoAuth::PAR::Client.new(
    #     endpoint: "https://auth.example.com/par"
    #   )
    #
    #   # Create and submit PAR request using builder pattern
    #   request = AtprotoAuth::PAR::Request.build do |config|
    #     config.client_id = "https://app.example.com/client-metadata.json"
    #     config.redirect_uri = "https://app.example.com/callback"
    #     config.code_challenge = "abc123..."
    #     config.code_challenge_method = "S256"
    #     config.state = "xyz789..."
    #     config.scope = "atproto"
    #   end
    #
    #   response = client.submit(request)
    #
    #   # Build authorization URL using response
    #   auth_url = client.authorization_url(
    #     authorize_endpoint: "https://auth.example.com/authorize",
    #     request_uri: response.request_uri,
    #     client_id: request.client_id
    #   )
    #
    # @example With client authentication (confidential clients)
    #   request = AtprotoAuth::PAR::Request.build do |config|
    #     # ... basic parameters ...
    #     config.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    #     config.client_assertion = jwt_token
    #   end
    #
    # @example With DPoP proof
    #   request = AtprotoAuth::PAR::Request.build do |config|
    #     # ... basic parameters ...
    #     config.dpop_proof = dpop_proof_jwt
    #   end
    #
    # All requests are made using HTTPS and include proper content-type headers.
    # DPoP proofs can be included for enhanced security. The client validates
    # all responses and provides clear error messages for any failures.
    class Client
      attr_reader :endpoint, :dpop_client, :nonce_manager

      def initialize(endpoint:, dpop_client:)
        @endpoint = endpoint
        @dpop_client = dpop_client
        @nonce_manager = dpop_client.nonce_manager
        validate_endpoint!
      end

      # Submits a PAR request, handling DPoP nonce requirements
      # @param request [Request] The request to submit
      # @return [Response] The PAR response
      # @raise [Error] if request fails
      def submit(request)
        # Try the initial request
        response = make_request(request)

        return process_response(response) if response[:status] == 201

        # Handle DPoP nonce requirement
        if requires_nonce?(response)
          nonce = extract_nonce(response)
          store_nonce(nonce)

          # Get stored nonce to verify
          nonce_manager.get(server_origin)

          # Generate new proof with nonce and retry
          response = make_request(request)
          return process_response(response) if response[:status] == 201
        end

        handle_error_response(response)
      rescue StandardError => e
        raise Error, "PAR request failed: #{e.message}"
      end

      def extract_nonce(response)
        # Try all possible header key formats
        headers = response[:headers]
        nonce = headers["DPoP-Nonce"] ||
                headers["dpop-nonce"] ||
                headers["Dpop-Nonce"]

        raise Error, "No DPoP nonce provided in response" unless nonce

        nonce
      end

      # Builds authorization URL from PAR response
      # @param authorize_endpoint [String] Authorization endpoint URL
      # @param request_uri [String] PAR request_uri
      # @param client_id [String] OAuth client_id
      # @return [String] Authorization URL
      def authorization_url(authorize_endpoint:, request_uri:, client_id:)
        uri = URI(authorize_endpoint)
        uri.query = encode_params(
          "request_uri" => request_uri,
          "client_id" => client_id
        )
        uri.to_s
      end

      private

      def validate_endpoint!
        uri = URI(@endpoint)
        raise Error, "endpoint must be HTTPS" unless uri.scheme == "https"
      rescue URI::InvalidURIError => e
        raise Error, "invalid endpoint URL: #{e.message}"
      end

      def make_request(request)
        # Generate DPoP proof for this request
        proof = dpop_client.generate_proof(
          http_method: "POST",
          http_uri: endpoint,
          nonce: nonce_manager.get(server_origin)
        )

        # Build headers including DPoP proof
        headers = build_headers(request, proof)

        # Make the request
        AtprotoAuth.configuration.http_client.post(
          endpoint,
          body: request.to_form,
          headers: headers
        )
      end

      def build_headers(_request, dpop_proof)
        {
          "Content-Type" => "application/x-www-form-urlencoded",
          "DPoP" => dpop_proof
        }
      end

      def requires_nonce?(response)
        body = JSON.parse(response[:body])
        body["error"] == "use_dpop_nonce"
      rescue JSON::ParserError
        false
      end

      def store_nonce(nonce)
        nonce_manager.update(nonce: nonce, server_url: server_origin)
      end

      def server_origin
        uri = URI(@endpoint)
        "#{uri.scheme}://#{uri.host}#{":#{uri.port}" if uri.port != uri.default_port}"
      end

      def handle_error_response(response)
        begin
          error_data = JSON.parse(response[:body])
          error_message = error_data["error_description"] || error_data["error"] || "Unknown error"
        rescue JSON::ParserError
          error_message = "Invalid response from server"
        end

        raise Error, "PAR request failed: #{error_message} (status: #{response[:status]})"
      end

      def process_response(response)
        raise Error, "unexpected response status: #{response[:status]}" unless response[:status] == 201

        begin
          data = JSON.parse(response[:body])
          Response.new(
            request_uri: data["request_uri"],
            expires_in: data["expires_in"]
          )
        rescue JSON::ParserError => e
          raise Error, "invalid JSON response: #{e.message}"
        rescue StandardError => e
          raise Error, "failed to process response: #{e.message}"
        end
      end

      def encode_params(params)
        params.map { |k, v| "#{CGI.escape(k)}=#{CGI.escape(v.to_s)}" }.join("&")
      end
    end
  end
end
