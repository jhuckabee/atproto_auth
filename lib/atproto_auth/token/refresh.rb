# frozen_string_literal: true

module AtprotoAuth
  module Token
    # Base error class for token-related errors
    class Error < AtprotoAuth::Error
      attr_reader :token_type, :error_code, :retry_possible

      def initialize(message, token_type:, error_code:, retry_possible: false)
        @token_type = token_type
        @error_code = error_code
        @retry_possible = retry_possible
        super(message)
      end
    end

    # Specific token error types
    class ExpiredTokenError < Error
      def initialize(token_type:)
        super(
          "Token has expired",
          token_type: token_type,
          error_code: "token_expired",
          retry_possible: true
        )
      end
    end

    # Raised when a token is structurally valid but has been invalidated or revoked
    class InvalidTokenError < Error
      def initialize(token_type:)
        super(
          "Token is invalid",
          token_type: token_type,
          error_code: "token_invalid",
          retry_possible: false
        )
      end
    end

    # Raised during token refresh operations, includes retry information and server responses
    class RefreshError < Error
      def initialize(message, retry_possible: true)
        super(
          message,
          token_type: "refresh",
          error_code: "refresh_failed",
          retry_possible: retry_possible
        )
      end
    end

    # Handles token refresh operations with retry logic
    class Refresh
      include MonitorMixin

      # Maximum number of refresh attempts
      MAX_RETRIES = 3
      # Base delay between retries in seconds
      BASE_DELAY = 1
      # Maximum delay between retries in seconds
      MAX_DELAY = 8

      attr_reader :session, :dpop_client, :auth_server, :client_metadata

      def initialize(session:, dpop_client:, auth_server:, client_metadata:)
        super() # Initialize MonitorMixin
        @session = session
        @dpop_client = dpop_client
        @auth_server = auth_server
        @attempt_count = 0
        @client_metadata = client_metadata
      end

      # Performs token refresh with retry logic
      # @return [TokenSet] New token set
      # @raise [RefreshError] if refresh fails
      def perform!
        synchronize do
          raise RefreshError.new("No refresh token available", retry_possible: false) unless session.renewable?
          raise RefreshError.new("No access token to refresh", retry_possible: false) if session.tokens.nil?

          with_retries do
            request_token_refresh
          end
        end
      end

      private

      def with_retries
        @attempt_count = 0
        last_error = nil

        while @attempt_count < MAX_RETRIES
          begin
            return yield
          rescue StandardError => e
            last_error = e
            @attempt_count += 1

            # Don't retry if error indicates retry not possible
            raise e if e.respond_to?(:retry_possible) && !e.retry_possible

            sleep calculate_delay if @attempt_count < MAX_RETRIES
          end
        end

        # Reached max retries
        raise RefreshError.new(
          "Token refresh failed after #{MAX_RETRIES} attempts: #{last_error.message}",
          retry_possible: false
        )
      end

      def calculate_delay
        # Exponential backoff with jitter
        delay = [BASE_DELAY * (2**(@attempt_count - 1)), MAX_DELAY].min
        delay + (rand * 0.5 * delay) # Add up to 50% jitter
      end

      def request_token_refresh # rubocop:disable Metrics/AbcSize
        # Generate DPoP proof for token request
        proof = dpop_client.generate_proof(
          http_method: "POST",
          http_uri: auth_server.token_endpoint
        )

        # Build refresh request
        body = {
          grant_type: "refresh_token",
          refresh_token: session.tokens.refresh_token,
          scope: session.scope
        }

        # Add client authentication if available
        add_client_authentication!(body) if client_metadata.confidential?

        # Make request
        response = AtprotoAuth.configuration.http_client.post(
          auth_server.token_endpoint,
          body: body,
          headers: {
            "Content-Type" => "application/x-www-form-urlencoded",
            "DPoP" => proof
          }
        )

        handle_refresh_response(response)
      end

      def add_client_authentication!(body) # rubocop:disable Metrics/AbcSize
        return unless session.client_metadata.jwks && !session.client_metadata.jwks["keys"].empty?

        signing_key = JOSE::JWK.from_map(session.client_metadata.jwks["keys"].first)
        client_assertion = PAR::ClientAssertion.new(
          client_id: session.client_metadata.client_id,
          signing_key: signing_key
        )

        body.merge!(
          client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
          client_assertion: client_assertion.generate_jwt(
            audience: auth_server.issuer
          )
        )
      end

      def handle_refresh_response(response)
        case response[:status]
        when 200
          process_successful_response(response)
        when 400
          handle_400_response(response)
        when 401
          raise RefreshError.new("Refresh token is invalid", retry_possible: false)
        when 429
          handle_rate_limit_response(response)
        else
          raise RefreshError, "Unexpected response: #{response[:status]}"
        end
      end

      def process_successful_response(response)
        data = JSON.parse(response[:body])
        validate_refresh_response!(data)

        AtprotoAuth::State::TokenSet.new(
          access_token: data["access_token"],
          token_type: data["token_type"],
          expires_in: data["expires_in"],
          refresh_token: data["refresh_token"],
          scope: data["scope"],
          sub: data["sub"]
        )
      rescue JSON::ParserError => e
        raise RefreshError, "Invalid response format: #{e.message}"
      end

      def handle_400_response(response)
        error_data = JSON.parse(response[:body])
        error_description = error_data["error_description"] || error_data["error"]

        # Handle DPoP nonce requirement
        if error_data["error"] == "use_dpop_nonce"
          dpop_client.process_response(response[:headers], auth_server.issuer)
          raise RefreshError, "Retry with DPoP nonce"
        end

        raise RefreshError.new(
          "Refresh request failed: #{error_description}",
          retry_possible: false
        )
      rescue JSON::ParserError
        raise RefreshError, "Invalid error response format"
      end

      def handle_rate_limit_response(response)
        # Extract retry-after if available
        retry_after = response[:headers]["Retry-After"]&.to_i || calculate_delay
        raise RefreshError, "Rate limited - retry after #{retry_after} seconds"
      end

      def validate_refresh_response!(data) # rubocop:disable Metrics/AbcSize
        # Required fields
        %w[access_token token_type expires_in scope sub].each do |field|
          raise RefreshError.new("Missing #{field} in response", retry_possible: false) unless data[field]
        end

        # Token type must be DPoP
        unless data["token_type"] == "DPoP"
          raise RefreshError.new("Invalid token_type: #{data["token_type"]}", retry_possible: false)
        end

        # Scope must include original scopes
        original_scopes = session.scope.split
        response_scopes = data["scope"].split
        unless (original_scopes - response_scopes).empty?
          raise RefreshError.new("Invalid scope in response", retry_possible: false)
        end

        # Subject must match
        return if data["sub"] == session.tokens.sub

        raise RefreshError.new("Subject mismatch in response", retry_possible: false)
      end
    end
  end
end
