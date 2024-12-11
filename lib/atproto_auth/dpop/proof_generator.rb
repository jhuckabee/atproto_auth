# frozen_string_literal: true

require "securerandom"
require "time"

module AtprotoAuth
  module DPoP
    # Creates and manages DPoP proof JWTs according to RFC 9449.
    # DPoP proofs are used to prove possession of a key when making
    # HTTP requests. Each proof is a JWT that includes details about
    # the request and is signed by the DPoP key.
    class ProofGenerator
      # Error raised for proof generation/validation issues
      class ProofError < AtprotoAuth::Error; end

      # @return [KeyManager] The key manager used for signing proofs
      attr_reader :key_manager

      # Creates a new ProofGenerator instance
      # @param key_manager [KeyManager] Key manager to use for signing proofs
      # @raise [ProofError] if key_manager is invalid
      def initialize(key_manager)
        raise ProofError, "key_manager is required" unless key_manager
        raise ProofError, "invalid key_manager type" unless key_manager.is_a?(KeyManager)

        @key_manager = key_manager
      end

      # Generates a new DPoP proof JWT for an HTTP request
      # @param http_method [String] HTTP method (e.g. "POST")
      # @param http_uri [String] Full HTTP URI for the request
      # @param nonce [String, nil] Server-provided nonce (required if available)
      # @param access_token [String, nil] Access token being used (if any)
      # @param ath [Boolean] Whether to include access token hash (default: true if token provided)
      # @return [String] The signed DPoP proof JWT
      # @raise [ProofError] if generation fails or parameters are invalid
      def generate(http_method:, http_uri:, nonce: nil, access_token: nil, ath: nil)
        validate_inputs!(http_method, http_uri)
        ath = !access_token.nil? if ath.nil?

        header = build_header
        payload = build_payload(
          http_method: http_method,
          http_uri: http_uri,
          nonce: nonce,
          access_token: access_token,
          include_ath: ath
        )

        key_manager.sign_segments(header, payload)
      rescue StandardError => e
        raise ProofError, "Failed to generate proof: #{e.message}"
      end

      private

      def validate_inputs!(http_method, http_uri)
        raise ProofError, "http_method is required" if http_method.nil? || http_method.empty?
        raise ProofError, "http_uri is required" if http_uri.nil? || http_uri.empty?

        uri = URI(http_uri)
        raise ProofError, "invalid http_uri" unless uri.is_a?(URI::HTTP)
      rescue URI::InvalidURIError => e
        raise ProofError, "invalid http_uri: #{e.message}"
      end

      def build_header
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: key_manager.public_jwk.to_h
        }
      end

      def build_payload(http_method:, http_uri:, nonce: nil, access_token: nil, include_ath: nil)
        payload = {
          "jti" => SecureRandom.uuid,
          "htm" => http_method.upcase,
          "htu" => normalize_uri(http_uri),
          "iat" => Time.now.to_i
        }

        # Add the nonce if provided
        payload["nonce"] = nonce if nonce

        # Add access token hash if needed
        payload["ath"] = generate_access_token_hash(access_token) if access_token && include_ath

        payload
      end

      def normalize_uri(uri)
        uri = URI(uri)
        # Remove default ports
        uri.port = nil if (uri.scheme == "https" && uri.port == 443) || (uri.scheme == "http" && uri.port == 80)
        uri.fragment = nil
        uri.to_s
      end

      def generate_access_token_hash(access_token)
        digest = OpenSSL::Digest::SHA256.digest(access_token)
        Base64.urlsafe_encode64(digest, padding: false)
      end

      def encode_jwt_segments(header, payload)
        encoded_header = Base64.urlsafe_encode64(JSON.generate(header), padding: false)
        encoded_payload = Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
        "#{encoded_header}.#{encoded_payload}"
      end
    end
  end
end
