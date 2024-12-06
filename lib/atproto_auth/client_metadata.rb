# frozen_string_literal: true

require "uri"
require "json"

module AtprotoAuth
  module ApplicationType
    ALL = [
      WEB = "web",
      NATIVE = "native"
    ].freeze
  end

  # Handles validation and management of AT Protocol OAuth client metadata according to
  # the specification. This includes required fields like client_id and redirect URIs,
  # optional metadata like client name and logo, and authentication configuration for
  # confidential clients. Validates that all fields conform to the protocol's requirements,
  # including:
  # - Application type (web/native) validation and redirect URI rules
  # - Required scopes and grant types
  # - JWKS configuration for confidential clients
  # - DPoP binding requirements
  # - URI scheme and format validation
  class ClientMetadata
    # Required fields
    attr_reader :application_type, :client_id, :grant_types, :response_types, :redirect_uris, :scope
    # Optional fields
    attr_reader :client_name, :client_uri, :logo_uri, :tos_uri, :policy_uri
    # Authentication and key-related fields
    attr_reader :token_endpoint_auth_method, :jwks, :jwks_uri

    # Initializes a new ClientMetadata instance from metadata hash.
    # @param metadata [Hash] Client metadata.
    # @raise [InvalidClientMetadata] if metadata is invalid.
    def initialize(metadata)
      validate_and_set_metadata!(metadata)
    end

    # Fetches client metadata from a URL and creates a new instance.
    # @param url [String] URL to fetch metadata from.
    # @return [ClientMetadata] new instance with fetched metadata.
    # @raise [InvalidClientMetadata] if metadata is invalid or cannot be fetched.
    def self.from_url(url)
      validate_url!(url)
      response = fetch_metadata(url)
      metadata = parse_metadata(response[:body])
      validate_client_id!(metadata["client_id"], url)
      new(metadata)
    end

    # Determines if the client is confidential (has authentication keys).
    # @return [Boolean] true if client is confidential.
    def confidential?
      token_endpoint_auth_method == "private_key_jwt"
    end

    private

    def validate_and_set_metadata!(metadata)
      # Required fields
      @application_type = validate_application_type(metadata["application_type"])
      @client_id = validate_client_id!(metadata["client_id"])
      @grant_types = validate_grant_types!(metadata["grant_types"])
      @response_types = validate_response_types!(metadata["response_types"])
      @redirect_uris = validate_redirect_uris!(metadata["redirect_uris"])
      @scope = validate_scope!(metadata["scope"])

      validate_dpop!(metadata)

      # Optional fields
      @client_name = metadata["client_name"]
      @client_uri = validate_client_uri(metadata["client_uri"])
      @logo_uri = validate_https_uri(metadata["logo_uri"])
      @tos_uri = validate_https_uri(metadata["tos_uri"])
      @policy_uri = validate_https_uri(metadata["policy_uri"])

      # Authentication methods
      validate_auth_methods!(metadata)
    end

    def validate_client_id!(client_id)
      raise InvalidClientMetadata, "client_id is required" unless client_id

      uri = URI(client_id)
      unless uri.scheme == "https" || (uri.scheme == "http" && uri.host == "localhost")
        raise InvalidClientMetadata, "client_id must be HTTPS or localhost HTTP URL"
      end

      client_id
    end

    def validate_grant_types!(grant_types)
      raise InvalidClientMetadata, "grant_types is required" unless grant_types

      valid_types = %w[authorization_code refresh_token]
      unless grant_types.include?("authorization_code") && (grant_types - valid_types).empty?
        raise InvalidClientMetadata, "grant_types must include authorization_code and optionally refresh_token"
      end

      grant_types
    end

    def validate_response_types!(response_types)
      raise InvalidClientMetadata, "response_types is required" unless response_types
      raise InvalidClientMetadata, "response_types must include 'code'" unless response_types.include?("code")

      response_types
    end

    def validate_redirect_uris!(uris)
      raise InvalidClientMetadata, "redirect_uris is required" if uris.nil? || uris.none?

      uris.each { |uri| validate_redirect_uri!(URI(uri)) }
      uris
    end

    def validate_redirect_uri!(uri)
      case application_type
      when ApplicationType::WEB
        if uri.host != "127.0.0.1" && uri.scheme != "https"
          raise InvalidClientMetadata, "web clients must use HTTPS redirect URIs #{uri}"
        end

        validate_redirect_uri_origin!(uri)
      when ApplicationType::NATIVE
        validate_native_redirect_uri!(uri)
      end
    end

    def validate_redirect_uri_origin!(uri)
      client_origin = URI(@client_id).host
      valid = client_origin == "localhost" ? true : uri.host == client_origin
      raise InvalidClientMetadata, "redirect URI must match client_id origin" unless valid
    end

    def validate_native_redirect_uri!(uri)
      if uri.scheme == "http"
        unless ["127.0.0.1", "[::1]"].include?(uri.host)
          raise InvalidClientMetadata, "HTTP redirect URIs for native clients must use loopback IP"
        end
      else
        validate_custom_scheme!(uri)
      end
    end

    def validate_custom_scheme!(uri)
      reversed_host = URI(@client_id).host.split(".").reverse
      scheme_parts = uri.scheme.split(".")
      unless scheme_parts == reversed_host
        raise InvalidClientMetadata, "custom scheme must match reversed client_id domain"
      end
      raise InvalidClientMetadata, "custom scheme URI must have single path component" unless uri.path == "/"
    end

    def validate_scope!(scope)
      raise InvalidClientMetadata, "scope is required" unless scope

      scope_values = scope.split
      raise InvalidClientMetadata, "atproto scope is required" unless scope_values.include?("atproto")

      # validate_offline_access_scope!(scope_values)
      scope
    end

    def validate_offline_access_scope!(scope_values)
      has_refresh = @grant_types&.include?("refresh_token")
      has_offline = scope_values.include?("offline_access")
      return unless has_refresh != has_offline

      raise InvalidClientMetadata, "offline_access scope must match refresh_token grant type"
    end

    def validate_application_type(type)
      type ||= ApplicationType::WEB # Default to web
      unless ApplicationType::ALL.include?(type)
        raise InvalidClientMetadata,
              "application_type must be 'web' or 'native'"
      end

      type
    end

    def validate_client_uri(uri)
      return unless uri
      raise InvalidClientMetadata, "client_uri must match client_id origin" unless URI(uri).host == URI(@client_id).host

      uri
    end

    def validate_https_uri(uri)
      return unless uri
      raise InvalidClientMetadata, "URI must use HTTPS" unless URI(uri).scheme == "https"

      uri
    end

    def validate_jwks!(jwks)
      raise InvalidClientMetadata, "jwks must have keys array" unless jwks["keys"].is_a?(Array)

      jwks["keys"].each_with_index do |key, index|
        has_key_use_sig = key["use"] == "sig"
        has_key_ops_sign = key["key_ops"]&.include?("sign")
        if !has_key_use_sig && !has_key_ops_sign
          raise InvalidClientMetadata, "jwks.keys.#{index} must have use='sig' or key_ops including 'sign'"
        end

        raise InvalidClientMetadata, "jwks.keys.#{index} must have kid" unless key["kid"]
      end
    end

    def validate_auth_methods!(metadata)
      @token_endpoint_auth_method = metadata["token_endpoint_auth_method"]
      return unless @token_endpoint_auth_method == "private_key_jwt"

      # Validate auth signing algorithm
      @token_endpoint_auth_signing_alg = metadata["token_endpoint_auth_signing_alg"]
      unless @token_endpoint_auth_signing_alg == "ES256"
        raise InvalidClientMetadata, "token_endpoint_auth_signing_alg must be ES256"
      end

      @jwks = metadata["jwks"]
      @jwks_uri = metadata["jwks_uri"]
      raise InvalidClientMetadata, "cannot use both jwks and jwks_uri" if @jwks && @jwks_uri
      raise InvalidClientMetadata, "confidential clients must provide jwks or jwks_uri" unless @jwks || @jwks_uri

      validate_jwks!(@jwks) if @jwks
      validate_https_uri(@jwks_uri) if @jwks_uri
    end

    def validate_dpop!(metadata)
      return if metadata["dpop_bound_access_tokens"] == true

      raise InvalidClientMetadata, "dpop_bound_access_tokens must be true"
    end

    class << self
      private

      def validate_url!(url)
        uri = URI(url)
        return if uri.scheme == "https" || uri.host == "localhost"

        raise InvalidClientMetadata, "client_id must use HTTPS except for localhost"
      end

      def fetch_metadata(url)
        AtprotoAuth.configuration.http_client&.get(url) ||
          raise(InvalidClientMetadata, "HTTP client not configured")
      end

      def parse_metadata(body)
        JSON.parse(body)
      rescue JSON::ParserError => e
        raise InvalidClientMetadata, "Invalid JSON in client metadata: #{e.message}"
      end

      def validate_client_id!(metadata_client_id, url)
        return if metadata_client_id == url

        raise InvalidClientMetadata, "client_id mismatch: #{metadata_client_id} != #{url}"
      end
    end
  end
end
