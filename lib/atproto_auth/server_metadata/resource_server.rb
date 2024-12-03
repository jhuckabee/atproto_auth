# frozen_string_literal: true

module AtprotoAuth
  module ServerMetadata
    # This class represents a Resource Server (PDS) and is responsible for
    # validating and managing its metadata. It ensures that the authorization
    # server URLs provided are valid and compliant with expected standards.
    # The class also includes functionality to fetch and parse metadata from a
    # remote URL, raising specific errors for invalid or malformed metadata.
    class ResourceServer
      attr_reader :authorization_servers

      def initialize(metadata)
        @authorization_servers = validate_authorization_servers!(metadata["authorization_servers"])
      end

      # Fetches and validates Resource Server metadata from a URL
      # @param url [String] PDS URL to fetch metadata from
      # @return [ResourceServer] new instance with fetched metadata
      # @raise [InvalidAuthorizationServer] if metadata is invalid
      def self.from_url(url)
        response = fetch_metadata(url)
        new(parse_metadata(response[:body]))
      end

      private

      def validate_authorization_servers!(servers)
        ensure_servers_exist(servers)
        ensure_exactly_one_server(servers)
        validate_server_url_format(servers.first)
        servers
      end

      def ensure_servers_exist(servers)
        return if servers.is_a?(Array)

        raise InvalidAuthorizationServer, "authorization_servers missing"
      end

      def ensure_exactly_one_server(servers)
        return if servers.size == 1

        raise InvalidAuthorizationServer, "must have exactly one authorization server"
      end

      def validate_server_url_format(server_url)
        return if OriginUrl.new(server_url).valid?

        raise InvalidAuthorizationServer, "invalid authorization server URL format for #{server_url}"
      end

      class << self
        private

        def fetch_metadata(url)
          metadata_url = URI.join(url, "/.well-known/oauth-protected-resource")
          AtprotoAuth.configuration.http_client.get(metadata_url.to_s)
        rescue HttpClient::HttpError => e
          raise InvalidAuthorizationServer, "Failed to fetch resource server metadata: #{e.message}"
        end

        def parse_metadata(body)
          JSON.parse(body)
        rescue JSON::ParserError => e
          raise InvalidAuthorizationServer, "Invalid JSON in resource server metadata: #{e.message}"
        end
      end
    end
  end
end
