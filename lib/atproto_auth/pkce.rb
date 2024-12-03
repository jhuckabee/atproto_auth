# frozen_string_literal: true

require "securerandom"
require "base64"
require "openssl"

module AtprotoAuth
  # Implementation of Proof Key for Code Exchange (PKCE) for OAuth 2.0 / AT Protocol
  # as specified in RFC 7636.
  #
  # This module provides functionality to:
  # - Generate cryptographically secure code verifiers
  # - Create SHA-256 code challenges from verifiers
  # - Verify challenge/verifier pairs
  #
  # Only the S256 challenge method is supported, as required by AT Protocol OAuth.
  module PKCE
    # Error raised for PKCE-related failures
    class Error < AtprotoAuth::Error; end

    # Minimum and maximum lengths for code verifier as per RFC 7636
    MIN_VERIFIER_LENGTH = 43
    MAX_VERIFIER_LENGTH = 128

    # PKCE code verifier charset as per RFC 7636 Section 4.1
    ALLOWED_VERIFIER_CHARS = /^[A-Za-z0-9\-\._~]+$/

    class << self
      # Generates a cryptographically secure random code verifier
      # @param length [Integer] Length of verifier to generate
      # @return [String] The generated code verifier
      # @raise [Error] if length is invalid
      def generate_verifier(length = MAX_VERIFIER_LENGTH)
        validate_verifier_length!(length)

        # Generate random bytes and encode as URL-safe base64
        random_bytes = SecureRandom.random_bytes(length * 3 / 4)
        Base64.urlsafe_encode64(random_bytes, padding: false)[0...length]
      rescue StandardError => e
        raise Error, "Failed to generate verifier: #{e.message}"
      end

      # Creates a code challenge from a verifier using SHA-256
      # @param verifier [String] The code verifier to create challenge from
      # @return [String] Base64URL-encoded SHA-256 hash of the verifier
      # @raise [Error] if verifier is invalid or hashing fails
      def generate_challenge(verifier)
        validate_verifier!(verifier)

        # Hash with SHA-256 and encode as URL-safe base64
        digest = OpenSSL::Digest::SHA256.digest(verifier)
        Base64.urlsafe_encode64(digest, padding: false)
      rescue StandardError => e
        raise Error, "Failed to generate challenge: #{e.message}"
      end

      # Verifies that a challenge matches a verifier
      # @param challenge [String] The code challenge to verify
      # @param verifier [String] The code verifier to check against
      # @return [Boolean] true if challenge matches verifier
      # @raise [Error] if inputs are invalid
      def verify(challenge, verifier)
        # Generate challenge from verifier and compare
        calculated = generate_challenge(verifier)
        secure_compare(calculated, challenge)
      rescue Error
        # Re-raise PKCE errors
        raise
      rescue StandardError => e
        raise Error, "Challenge verification failed: #{e.message}"
      end

      private

      def validate_verifier_length!(length)
        return if length.is_a?(Integer) && length.between?(MIN_VERIFIER_LENGTH, MAX_VERIFIER_LENGTH)

        raise Error, "Verifier length must be between #{MIN_VERIFIER_LENGTH} and #{MAX_VERIFIER_LENGTH}"
      end

      def validate_verifier!(verifier)
        raise Error, "Verifier cannot be nil" if verifier.nil?
        raise Error, "Verifier cannot be empty" if verifier.empty?

        length = verifier.length
        validate_verifier_length!(length)

        return if verifier.match?(ALLOWED_VERIFIER_CHARS)

        raise Error, "Verifier contains invalid characters"
      end

      # Constant-time string comparison to prevent timing attacks
      def secure_compare(str1, str2)
        return false unless str1.bytesize == str2.bytesize

        left = str1.unpack("C*")
        right = str2.unpack("C*")
        result = 0
        left.zip(right) { |x, y| result |= x ^ y }
        result.zero?
      end
    end
  end
end
