# frozen_string_literal: true

module AtprotoAuth
  module DPoP
    # Manages ES256 keypair generation and storage for DPoP proofs.
    # Provides functionality to generate new keys and store them securely.
    # Uses JOSE for cryptographic operations and key format handling.
    class KeyManager
      # Error raised when key operations fail
      class KeyError < AtprotoAuth::Error; end

      # Default curve for ES256 key generation
      CURVE = "P-256"
      # Default algorithm for key usage
      ALGORITHM = "ES256"

      # @return [JOSE::JWK] The current DPoP keypair
      attr_reader :keypair

      # Creates a new KeyManager instance with an optional existing keypair
      # @param keypair [JOSE::JWK, nil] Optional existing keypair to use
      # @raise [KeyError] if the provided keypair is invalid
      def initialize(keypair = nil)
        @keypair = keypair || generate_keypair
        validate_keypair!
      end

      # Generates a new ES256 keypair for DPoP usage
      # @return [JOSE::JWK] The newly generated keypair
      # @raise [KeyError] if key generation fails
      def generate_keypair
        # Generate base keypair
        base_key = JOSE::JWK.generate_key([:ec, CURVE])
        base_map = base_key.to_map

        # Create new map with all required properties
        key_map = {
          "kty" => base_map["kty"],
          "crv" => base_map["crv"],
          "x" => base_map["x"],
          "y" => base_map["y"],
          "d" => base_map["d"],
          "use" => "sig",
          "kid" => generate_kid(base_map)
        }

        # Create new JWK with all properties
        JOSE::JWK.from_map(key_map)
      rescue StandardError => e
        raise KeyError, "Failed to generate keypair: #{e.message}"
      end

      # Returns the public key in JWK format
      # @return [Hash] JWK representation of the public key
      def public_jwk
        jwk = @keypair.to_public.to_map.to_h
        # If somehow the properties aren't set, add them
        jwk["use"] ||= "sig"
        jwk["kid"] ||= generate_kid(jwk)
        jwk
      rescue StandardError => e
        raise KeyError, "Failed to export public key: #{e.message}"
      end

      # Signs data using the private key
      # @param data [String] Data to sign
      # @return [String] The signature
      # @raise [KeyError] if signing fails
      def sign(data)
        @keypair.sign(data).compact
      rescue StandardError => e
        raise KeyError, "Failed to sign data: #{e.message}"
      end

      def sign_segments(header, payload)
        # Deep transform all keys to strings to avoid symbol comparison issues
        header = deep_stringify_keys(header)
        payload = deep_stringify_keys(payload)

        # Configure JOSE to use ES256 for signing
        signing_config = { "alg" => "ES256" }

        # Merge our header with JOSE's required fields
        full_header = header.merge(signing_config)

        # Convert payload to JSON string before signing
        payload_json = JSON.generate(payload)

        # Create the JWS with our header and payload
        jws = @keypair.sign(payload_json, full_header)

        # Get the compact serialization
        jws.compact
      rescue StandardError => e
        raise KeyError, "Failed to sign segments: #{e.message}"
      end

      def deep_stringify_keys(obj)
        case obj
        when Hash
          obj.each_with_object({}) do |(k, v), hash|
            hash[k.to_s] = deep_stringify_keys(v)
          end
        when Array
          obj.map { |v| deep_stringify_keys(v) }
        else
          obj
        end
      end

      # Verifies a signed JWS
      # @param signed_jws [String] The complete signed JWS to verify
      # @return [Boolean] True if signature is valid
      # @raise [KeyError] if verification fails
      def verify(signed_jws)
        verified, _payload, = @keypair.verify(signed_jws)
        verified
      rescue StandardError => e
        raise KeyError, "Failed to verify signature: #{e.message}"
      end

      # Exports the keypair in JWK format
      # @param include_private [Boolean] Whether to include private key
      # @return [Hash] JWK representation of the keypair
      # @raise [KeyError] if export fails
      def to_jwk(include_private: false)
        key = include_private ? @keypair : @keypair.to_public
        key.to_map
      rescue StandardError => e
        raise KeyError, "Failed to export key: #{e.message}"
      end

      # Creates a KeyManager instance from a JWK
      # @param jwk [Hash] JWK representation of a keypair
      # @return [KeyManager] New KeyManager instance
      # @raise [KeyError] if import fails
      def self.from_jwk(jwk)
        keypair = JOSE::JWK.from_map(jwk)
        new(keypair)
      rescue StandardError => e
        raise KeyError, "Failed to import key: #{e.message}"
      end

      private

      def generate_kid(jwk)
        # Generate a key ID based on the key's components
        components = [
          jwk["kty"],
          jwk["crv"],
          jwk["x"],
          jwk["y"]
        ].join(":")

        # Create a SHA-256 hash and take first 8 bytes
        digest = OpenSSL::Digest::SHA256.digest(components)
        Base64.urlsafe_encode64(digest[0..7], padding: false)
      end

      # Validates that the keypair meets DPoP requirements
      # @raise [KeyError] if validation fails
      def validate_keypair!
        # Check that we have a valid EC key
        raise KeyError, "Invalid key type: #{@keypair.kty}, must be :ec" unless @keypair.kty.is_a?(JOSE::JWK::KTY_EC)

        # Verify the curve
        curve = @keypair.to_map["crv"]
        raise KeyError, "Invalid curve: #{curve}, must be #{CURVE}" unless curve == CURVE

        # Verify we can perform basic operations
        test_data = "test"
        signed = sign(test_data)
        raise KeyError, "Key validation failed: signature verification error" unless verify(signed)
      rescue StandardError => e
        raise KeyError, "Key validation failed: #{e.message}"
      end

      def sign_message(message)
        # Create SHA-256 digest of message
        digest = OpenSSL::Digest::SHA256.digest(message)

        # Get EC key from JOSE JWK
        ec_key = extract_ec_key

        # Sign using ECDSA
        signature = ec_key.sign(OpenSSL::Digest.new("SHA256"), digest)

        # Convert to raw r|s format required for JWTs
        asn1_to_raw(signature)
      end

      def extract_ec_key
        # Extract the raw EC key from JOSE JWK
        key_data = @keypair.to_map
        raise KeyError, "Private key required for signing" unless key_data["d"] # Private key component

        group = OpenSSL::PKey::EC::Group.new("prime256v1")
        key = OpenSSL::PKey::EC.new(group)

        # Convert base64url to hex string for BN
        d = bin_to_hex(Base64.urlsafe_decode64(key_data["d"]))
        x = bin_to_hex(Base64.urlsafe_decode64(key_data["x"]))
        y = bin_to_hex(Base64.urlsafe_decode64(key_data["y"]))

        # Create BNs from hex strings
        key.private_key = OpenSSL::BN.new(d, 16)

        # Set public key point
        point = OpenSSL::PKey::EC::Point.new(group)
        point.set_to_keypair(x, y)
        key.public_key = point

        key
      end

      def bin_to_hex(binary)
        binary.unpack1("H*")
      end

      def asn1_to_raw(signature)
        # Parse ASN.1 signature
        asn1 = OpenSSL::ASN1.decode(signature)
        r = asn1.value[0].value.to_s(2)
        s = asn1.value[1].value.to_s(2)

        # Pad r and s to 32 bytes each
        r = r.rjust(32, "\x00")
        s = s.rjust(32, "\x00")

        # Concatenate r|s
        r + s
      end
    end
  end
end
