# frozen_string_literal: true

module AtprotoAuth
  module DPoP
    # Manages DPoP nonces provided by servers during the OAuth flow.
    # Tracks separate nonces for each server using persistent storage.
    # Thread-safe to handle concurrent requests.
    class NonceManager
      # Error for nonce-related issues
      class NonceError < AtprotoAuth::Error; end

      # Represents a stored nonce with its server URL
      class StoredNonce
        attr_reader :value, :server_url, :timestamp

        def initialize(value, server_url, timestamp: nil)
          @value = value
          @server_url = server_url
          @timestamp = timestamp || Time.now.to_i
        end
      end

      # Default time in seconds a nonce is considered valid
      DEFAULT_TTL = 300 # 5 minutes

      def initialize(ttl: nil)
        @ttl = ttl || DEFAULT_TTL
        @serializer = Serialization::StoredNonce.new
      end

      # Updates the stored nonce for a server
      # @param nonce [String] The new nonce value
      # @param server_url [String] The server's URL
      # @raise [NonceError] if inputs are invalid
      def update(nonce:, server_url:)
        validate_inputs!(nonce, server_url)
        origin = normalize_server_url(server_url)

        stored_nonce = StoredNonce.new(nonce, origin)
        serialized = @serializer.serialize(stored_nonce)

        key = Storage::KeyBuilder.nonce_key(origin)
        return if AtprotoAuth.storage.set(key, serialized, ttl: @ttl)

        raise NonceError, "Failed to store nonce"
      end

      # Gets the current nonce for a server
      # @param server_url [String] The server's URL
      # @return [String, nil] The current nonce or nil if none exists/expired
      # @raise [NonceError] if server_url is invalid
      def get(server_url)
        validate_server_url!(server_url)
        origin = normalize_server_url(server_url)
        key = Storage::KeyBuilder.nonce_key(origin)

        stored = AtprotoAuth.storage.get(key)
        return nil unless stored

        begin
          stored_nonce = @serializer.deserialize(stored)
          stored_nonce.value
        rescue Serialization::Error => e
          raise NonceError, "Failed to deserialize nonce: #{e.message}"
        end
      end

      # Clears a nonce for a server
      # @param server_url [String] The server's URL
      def clear(server_url)
        validate_server_url!(server_url)
        origin = normalize_server_url(server_url)
        key = Storage::KeyBuilder.nonce_key(origin)
        AtprotoAuth.storage.delete(key)
      end

      # Check if a server has a valid nonce
      # @param server_url [String] The server's URL
      # @return [Boolean] true if server has a valid nonce
      def valid_nonce?(server_url)
        validate_server_url!(server_url)
        origin = normalize_server_url(server_url)
        key = Storage::KeyBuilder.nonce_key(origin)
        AtprotoAuth.storage.exists?(key)
      end

      private

      def normalize_server_url(url)
        uri = URI(url)
        port = uri.port
        port = nil if (uri.scheme == "https" && port == 443) ||
                      (uri.scheme == "http" && port == 80)

        origin = "#{uri.scheme}://#{uri.host}"
        origin = "#{origin}:#{port}" if port
        origin
      end

      def validate_inputs!(nonce, server_url)
        raise NonceError, "nonce is required" if nonce.nil? || nonce.empty?

        validate_server_url!(server_url)
      end

      def validate_server_url!(server_url)
        raise NonceError, "server_url is required" if server_url.nil? || server_url.empty?

        uri = URI(server_url)
        raise NonceError, "server_url must be HTTP(S)" unless uri.is_a?(URI::HTTP)

        # Allow HTTP for localhost only
        if uri.host != "localhost" && uri.scheme != "https"
          raise NonceError, "server_url must be HTTPS (except for localhost)"
        end
      rescue URI::InvalidURIError => e
        raise NonceError, "invalid server_url: #{e.message}"
      end
    end
  end
end
