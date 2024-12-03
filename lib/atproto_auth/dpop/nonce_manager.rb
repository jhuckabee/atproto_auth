# frozen_string_literal: true

require "monitor"

module AtprotoAuth
  module DPoP
    # Manages DPoP nonces provided by servers during the OAuth flow.
    # Tracks separate nonces for Resource Server and Authorization Server.
    # Thread-safe to handle concurrent requests.
    class NonceManager
      # Error for nonce-related issues
      class NonceError < AtprotoAuth::Error; end

      # Represents a stored nonce with its timestamp
      class StoredNonce
        attr_reader :value, :timestamp, :server_url

        def initialize(value, server_url)
          @value = value
          @server_url = server_url
          @timestamp = Time.now.to_i
        end

        def expired?(ttl = nil)
          return false unless ttl

          (Time.now.to_i - @timestamp) > ttl
        end
      end

      # Maximum time in seconds a nonce is considered valid
      DEFAULT_TTL = 300 # 5 minutes

      def initialize(ttl: nil)
        @ttl = ttl || DEFAULT_TTL
        @nonces = {}
        @monitor = Monitor.new
      end

      # Updates the stored nonce for a server
      # @param nonce [String] The new nonce value
      # @param server_url [String] The server's URL
      # @raise [NonceError] if inputs are invalid
      def update(nonce:, server_url:)
        validate_inputs!(nonce, server_url)
        origin = normalize_server_url(server_url)

        @monitor.synchronize do
          @nonces[origin] = StoredNonce.new(nonce, origin)
        end
      end

      # Gets the current nonce for a server
      # @param server_url [String] The server's URL
      # @return [String, nil] The current nonce or nil if none exists/expired
      # @raise [NonceError] if server_url is invalid
      def get(server_url)
        validate_server_url!(server_url)
        origin = normalize_server_url(server_url)

        @monitor.synchronize do
          stored = @nonces[origin]
          return nil if stored.nil? || stored.expired?(@ttl)

          stored.value
        end
      end

      # Clears an expired nonce for a server
      # @param server_url [String] The server's URL
      def clear(server_url)
        @monitor.synchronize do
          @nonces.delete(server_url)
        end
      end

      # Clears all stored nonces
      def clear_all
        @monitor.synchronize do
          @nonces.clear
        end
      end

      # Get all currently stored server URLs
      # @return [Array<String>] Array of server URLs with stored nonces
      def server_urls
        @monitor.synchronize do
          @nonces.keys
        end
      end

      # Check if a server has a valid nonce
      # @param server_url [String] The server's URL
      # @return [Boolean] true if server has a valid nonce
      def valid_nonce?(server_url)
        validate_server_url!(server_url)

        @monitor.synchronize do
          stored = @nonces[server_url]
          !stored.nil? && !stored.expired?(@ttl)
        end
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
