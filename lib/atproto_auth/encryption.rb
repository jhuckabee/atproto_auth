# frozen_string_literal: true

# lib/atproto_auth/encryption.rb
module AtprotoAuth
  module Encryption
    class Error < AtprotoAuth::Error; end
    class ConfigurationError < Error; end
    class EncryptionError < Error; end
    class DecryptionError < Error; end

    # HKDF implementation based on RFC 5869
    module HKDF
      def self.derive(secret, salt:, info:, length:)
        # 1. extract
        prk = OpenSSL::HMAC.digest(
          OpenSSL::Digest.new("SHA256"),
          salt.empty? ? "\x00" * 32 : salt,
          secret.to_s
        )

        # 2. expand
        n = (length.to_f / 32).ceil
        t = [""]
        output = ""
        1.upto(n) do |i|
          t[i] = OpenSSL::HMAC.digest(
            OpenSSL::Digest.new("SHA256"),
            prk,
            t[i - 1] + info + [i].pack("C")
          )
          output += t[i]
        end
        output[0, length]
      end
    end

    # Core encryption service - used internally by serializers
    class Service
      CIPHER = "aes-256-gcm"
      VERSION = 1

      def initialize
        @key_provider = KeyProvider.new
      end

      def encrypt(data, context:)
        validate_encryption_inputs!(data, context)

        iv = SecureRandom.random_bytes(12)

        cipher = OpenSSL::Cipher.new(CIPHER)
        cipher.encrypt
        cipher.key = @key_provider.key_for_context(context)
        cipher.iv = iv
        cipher.auth_data = context.to_s

        encrypted = cipher.update(data.to_s) + cipher.final
        auth_tag = cipher.auth_tag

        {
          version: VERSION,
          iv: Base64.strict_encode64(iv),
          data: Base64.strict_encode64(encrypted),
          tag: Base64.strict_encode64(auth_tag)
        }
      rescue StandardError => e
        raise EncryptionError, "Encryption failed: #{e.message}"
      end

      def decrypt(encrypted, context:)
        validate_decryption_inputs!(encrypted, context)
        validate_encrypted_data!(encrypted)

        iv = Base64.strict_decode64(encrypted[:iv])
        data = Base64.strict_decode64(encrypted[:data])
        auth_tag = Base64.strict_decode64(encrypted[:tag])

        cipher = OpenSSL::Cipher.new(CIPHER)
        cipher.decrypt
        cipher.key = @key_provider.key_for_context(context)
        cipher.iv = iv
        cipher.auth_tag = auth_tag
        cipher.auth_data = context.to_s

        cipher.update(data) + cipher.final
      rescue ArgumentError => e
        raise DecryptionError, "Invalid encrypted data format: #{e.message}"
      rescue StandardError => e
        raise DecryptionError, "Decryption failed: #{e.message}"
      end

      private

      def validate_encryption_inputs!(data, context)
        raise EncryptionError, "Data cannot be nil" if data.nil?
        raise EncryptionError, "Context cannot be nil" if context.nil?
        raise EncryptionError, "Context must be a string" unless context.is_a?(String)
        raise EncryptionError, "Context cannot be empty" if context.empty?
      end

      def validate_decryption_inputs!(encrypted, context)
        raise DecryptionError, "Encrypted data cannot be nil" if encrypted.nil?
        raise DecryptionError, "Context cannot be nil" if context.nil?
        raise DecryptionError, "Context must be a string" unless context.is_a?(String)
        raise DecryptionError, "Context cannot be empty" if context.empty?
      end

      def validate_encrypted_data!(encrypted)
        raise DecryptionError, "Invalid encrypted data format" unless encrypted.is_a?(Hash)

        unless encrypted[:version] == VERSION
          raise DecryptionError, "Unsupported encryption version: #{encrypted[:version]}"
        end

        %i[iv data tag].each do |field|
          raise DecryptionError, "Missing required field: #{field}" unless encrypted[field].is_a?(String)
        end
      end
    end

    # Handles key management and derivation
    class KeyProvider
      def initialize
        @master_key = load_master_key
      end

      def key_for_context(context)
        raise ConfigurationError, "Context is required" if context.nil?

        HKDF.derive(
          @master_key,
          salt: salt_for_context(context),
          info: "atproto-#{context}",
          length: 32
        )
      end

      private

      def load_master_key
        # Try environment variable first
        key = ENV.fetch("ATPROTO_MASTER_KEY", nil)
        return Base64.strict_decode64(key) if key

        # Generate and store a random key if not configured
        key = SecureRandom.random_bytes(32)
        warn "WARNING: Using randomly generated encryption key - tokens will not persist across restarts"
        key
      end

      def salt_for_context(context)
        OpenSSL::Digest.digest("SHA256", "atproto-salt-#{context}")
      end
    end
  end
end
