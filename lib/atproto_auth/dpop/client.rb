# frozen_string_literal: true

module AtprotoAuth
  module DPoP
    # High-level client for managing DPoP operations. Integrates key management,
    # proof generation, and nonce tracking to provide a complete DPoP client
    # implementation according to RFC 9449.
    #
    # This client handles:
    # - Key management for signing proofs
    # - Proof generation for HTTP requests
    # - Nonce tracking across servers
    # - Header construction for requests
    # - Response processing for nonce updates
    class Client
      # Error raised for DPoP client operations
      class Error < AtprotoAuth::Error; end

      # @return [KeyManager] DPoP key manager instance
      attr_reader :key_manager
      # @return [ProofGenerator] DPoP proof generator instance
      attr_reader :proof_generator
      # @return [NonceManager] DPoP nonce manager instance
      attr_reader :nonce_manager

      # Creates a new DPoP client
      # @param key_manager [KeyManager, nil] Optional existing key manager
      # @param nonce_ttl [Integer, nil] Optional TTL for nonces in seconds
      def initialize(key_manager: nil, nonce_ttl: nil)
        @key_manager = key_manager || KeyManager.new
        @nonce_manager = NonceManager.new(ttl: nonce_ttl)
        @proof_generator = ProofGenerator.new(@key_manager)
      end

      # Generates a DPoP proof for an HTTP request
      # @param http_method [String] HTTP method (e.g., "POST")
      # @param http_uri [String] Full request URI
      # @param access_token [String, nil] Optional access token to bind to proof
      # @return [String] The DPoP proof JWT
      # @raise [Error] if proof generation fails
      def generate_proof(http_method:, http_uri:, access_token: nil, nonce: nil)
        uri = URI(http_uri)
        server_url = "#{uri.scheme}://#{uri.host}#{":#{uri.port}" if uri.port != uri.default_port}"

        # Use provided nonce or get one from the manager
        nonce ||= @nonce_manager.get(server_url)

        @proof_generator.generate(
          http_method: http_method,
          http_uri: http_uri,
          nonce: nonce,
          access_token: access_token
        )
      rescue StandardError => e
        raise Error, "Failed to generate proof: #{e.message}"
      end

      # Updates stored nonce from server response
      # @param response_headers [Hash] Response headers
      # @param server_url [String] Server's base URL
      # @return [void]
      # @raise [Error] if nonce update fails
      def process_response(response_headers, server_url)
        return unless response_headers

        # Look for DPoP-Nonce header (case insensitive)
        nonce = response_headers.find { |k, _| k.downcase == "dpop-nonce" }&.last
        return unless nonce

        # Store new nonce for future requests
        @nonce_manager.update(nonce: nonce, server_url: server_url)
      rescue StandardError => e
        raise Error, "Failed to process response: #{e.message}"
      end

      # Constructs DPoP header value for a request
      # @param proof [String] The DPoP proof JWT
      # @return [Hash] Headers to add to request
      def request_headers(proof)
        {
          "DPoP" => proof
        }
      end

      # Gets the current public key in JWK format
      # @return [Hash] JWK representation of public key
      def public_key
        @key_manager.public_jwk
      end

      # Exports the current keypair as JWK
      # @param include_private [Boolean] Whether to include private key
      # @return [Hash] JWK representation of keypair
      def export_key(include_private: false)
        @key_manager.to_jwk(include_private: include_private)
      end

      private

      def extract_nonce(headers)
        # Headers can be hash with string or symbol keys, or http headers object
        headers = headers.to_h if headers.respond_to?(:to_h)

        # Try different common header key formats
        nonce = headers["DPoP-Nonce"] ||
                headers["dpop-nonce"] ||
                headers[:dpop_nonce]

        nonce&.strip
      end

      def origin_for_uri(uri)
        port = uri.port
        port = nil if (uri.scheme == "https" && port == 443) || (uri.scheme == "http" && port == 80)

        origin = "#{uri.scheme}://#{uri.host}"
        origin = "#{origin}:#{port}" if port
        origin
      end
    end
  end
end
