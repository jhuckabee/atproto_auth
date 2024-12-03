# frozen_string_literal: true

module AtprotoAuth
  module PAR
    # Generates client authentication JWTs according to RFC 7523 for AT Protocol OAuth.
    # Creates signed assertions using ES256 with required claims including iss/sub (client_id),
    # aud (token endpoint), jti (unique ID), and iat/exp (timing claims).
    class ClientAssertion
      class Error < AtprotoAuth::Error; end

      # @param client_id [String] OAuth client ID
      # @param signing_key [JOSE::JWK] Key to sign assertion with
      def initialize(client_id:, signing_key:)
        @client_id = client_id
        @signing_key = signing_key
      end

      # Generates a new client assertion JWT
      # @param audience [String] Issuer endpoint URL
      # @param lifetime [Integer] How long assertion is valid for in seconds
      # @return [String] Signed JWT assertion
      # 5 minute default lifetime
      def generate_jwt(audience:, lifetime: 300)
        now = Time.now.to_i

        payload = {
          # Required claims
          iss: @client_id, # Issuer is client_id
          sub: @client_id, # Subject is client_id
          aud: audience, # Audience is token endpoint
          jti: SecureRandom.uuid, # Unique identifier
          exp: now + lifetime, # Expiration time
          iat: now # Issued at time
        }

        # Header specifying ES256 algorithm for signing
        header = {
          alg: "ES256",
          typ: "JWT",
          kid: @signing_key.fields["kid"]
        }

        # Sign and return the JWT
        JWT.encode(payload, @signing_key.kty.key, "ES256", header)
      rescue StandardError => e
        raise Error, "Failed to generate client assertion: #{e.message}"
      end
    end
  end
end
