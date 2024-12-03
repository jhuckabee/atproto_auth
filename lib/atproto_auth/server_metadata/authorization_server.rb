# frozen_string_literal: true

module AtprotoAuth
  module ServerMetadata
    # Handles fetching and validation of AT Protocol OAuth Authorization Server metadata.
    # An Authorization Server in atproto can be either a PDS instance or a separate "entryway" server
    # that handles authentication for multiple PDS instances.
    #
    # The Authorization Server metadata is fetched from the well-known endpoint
    # /.well-known/oauth-authorization-server and must conform to RFC 8414 plus additional
    # requirements specific to the AT Protocol OAuth profile.
    #
    # @example Fetching and validating Authorization Server metadata
    #   begin
    #     auth_server = AtprotoAuth::ServerMetadata::AuthorizationServer.from_issuer("https://auth.example.com")
    #     puts "Authorization endpoint: #{auth_server.authorization_endpoint}"
    #     puts "Supported scopes: #{auth_server.scopes_supported}"
    #   rescue AtprotoAuth::InvalidAuthorizationServer => e
    #     puts "Failed to validate authorization server: #{e.message}"
    #   end
    #
    # @see https://atproto.com/specs/oauth#authorization-servers Documentation of Authorization Server requirements
    class AuthorizationServer
      REQUIRED_FIELDS = %w[
        issuer
        authorization_endpoint
        token_endpoint
        response_types_supported
        grant_types_supported
        code_challenge_methods_supported
        token_endpoint_auth_methods_supported
        token_endpoint_auth_signing_alg_values_supported
        scopes_supported
        dpop_signing_alg_values_supported
        pushed_authorization_request_endpoint
      ].freeze

      attr_reader :issuer, :authorization_endpoint, :token_endpoint,
                  :pushed_authorization_request_endpoint, :response_types_supported,
                  :grant_types_supported, :code_challenge_methods_supported,
                  :token_endpoint_auth_methods_supported,
                  :token_endpoint_auth_signing_alg_values_supported,
                  :scopes_supported, :dpop_signing_alg_values_supported

      def initialize(metadata)
        validate_and_set_metadata!(metadata)
      end

      # Fetches and validates Authorization Server metadata from an issuer URL
      # @param issuer [String] Authorization Server issuer URL
      # @return [AuthorizationServer] new instance with fetched metadata
      # @raise [InvalidAuthorizationServer] if metadata is invalid
      def self.from_issuer(issuer)
        response = fetch_metadata(issuer)
        metadata = parse_metadata(response[:body])
        validate_issuer!(metadata["issuer"], issuer)
        new(metadata)
      end

      private

      def validate_and_set_metadata!(metadata) # rubocop:disable Metrics/AbcSize
        REQUIRED_FIELDS.each do |field|
          raise InvalidAuthorizationServer, "#{field} is required" unless metadata[field]
        end

        @issuer = validate_issuer!(metadata["issuer"])
        @authorization_endpoint = validate_https_url!(metadata["authorization_endpoint"])
        @token_endpoint = validate_https_url!(metadata["token_endpoint"])
        @pushed_authorization_request_endpoint = validate_https_url!(metadata["pushed_authorization_request_endpoint"])

        validate_response_types!(metadata["response_types_supported"])
        validate_grant_types!(metadata["grant_types_supported"])
        validate_code_challenge_methods!(metadata["code_challenge_methods_supported"])
        validate_token_endpoint_auth_methods!(metadata["token_endpoint_auth_methods_supported"])
        validate_token_endpoint_auth_signing_algs!(metadata["token_endpoint_auth_signing_alg_values_supported"])
        validate_dpop_signing_algs!(metadata["dpop_signing_alg_values_supported"])
        validate_scopes!(metadata["scopes_supported"])

        # Store validated values
        @response_types_supported = metadata["response_types_supported"]
        @grant_types_supported = metadata["grant_types_supported"]
        @code_challenge_methods_supported = metadata["code_challenge_methods_supported"]
        @token_endpoint_auth_methods_supported = metadata["token_endpoint_auth_methods_supported"]
        @token_endpoint_auth_signing_alg_values_supported = metadata["token_endpoint_auth_signing_alg_values_supported"]
        @scopes_supported = metadata["scopes_supported"]
        @dpop_signing_alg_values_supported = metadata["dpop_signing_alg_values_supported"]

        # Required boolean fields
        validate_boolean_field!(metadata, "authorization_response_iss_parameter_supported", true)
        validate_boolean_field!(metadata, "require_pushed_authorization_requests", true)
        validate_boolean_field!(metadata, "client_id_metadata_document_supported", true)
      end

      def validate_issuer!(issuer)
        is_valid = OriginUrl.new(issuer).valid?
        raise InvalidAuthorizationServer, "invalid issuer URL format" unless is_valid

        issuer
      end

      def validate_https_url!(url)
        uri = URI(url)
        raise InvalidAuthorizationServer, "URL must use HTTPS" unless uri.scheme == "https"

        url
      end

      def validate_response_types!(types)
        raise InvalidAuthorizationServer, "must support 'code' response type" unless types.include?("code")
      end

      def validate_grant_types!(types)
        required = %w[authorization_code refresh_token]
        missing = required - types
        raise InvalidAuthorizationServer, "missing grant types: #{missing.join(", ")}" if missing.any?
      end

      def validate_code_challenge_methods!(methods)
        raise InvalidAuthorizationServer, "must support S256 PKCE" unless methods.include?("S256")
      end

      def validate_token_endpoint_auth_methods!(methods)
        required = %w[private_key_jwt none]
        missing = required - methods
        raise InvalidAuthorizationServer, "missing auth methods: #{missing.join(", ")}" if missing.any?
      end

      def validate_token_endpoint_auth_signing_algs!(algs)
        raise InvalidAuthorizationServer, "must support ES256" unless algs.include?("ES256")
        raise InvalidAuthorizationServer, "must not allow 'none'" if algs.include?("none")
      end

      def validate_dpop_signing_algs!(algs)
        raise InvalidAuthorizationServer, "must support ES256 for DPoP" unless algs.include?("ES256")
      end

      def validate_scopes!(scopes)
        required = %w[atproto]
        missing = required - scopes
        raise InvalidAuthorizationServer, "missing scopes: #{missing.join(", ")}" if missing.any?
      end

      def validate_boolean_field!(metadata, field, required_value)
        actual = metadata[field]
        return if actual == required_value

        raise InvalidAuthorizationServer, "#{field} must be #{required_value}"
      end

      class << self
        private

        def fetch_metadata(issuer)
          metadata_url = URI.join(issuer, "/.well-known/oauth-authorization-server")
          AtprotoAuth.configuration.http_client.get(metadata_url.to_s)
        rescue HttpClient::HttpError => e
          raise InvalidAuthorizationServer, "Failed to fetch authorization server metadata: #{e.message}"
        end

        def parse_metadata(body)
          JSON.parse(body)
        rescue JSON::ParserError => e
          raise InvalidAuthorizationServer, "Invalid JSON in authorization server metadata: #{e.message}"
        end

        def validate_issuer!(metadata_issuer, request_issuer)
          return if metadata_issuer == request_issuer

          raise InvalidAuthorizationServer, "issuer mismatch: #{metadata_issuer} != #{request_issuer}"
        end
      end
    end
  end
end
