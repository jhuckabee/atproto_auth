# frozen_string_literal: true

require "resolv"

module AtprotoAuth
  module Identity
    # Resolves and validates AT Protocol identities
    class Resolver
      PLC_DIRECTORY_URL = "https://plc.directory"
      DID_PLC_PREFIX = "did:plc:"
      HANDLE_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/

      # Creates a new Identity resolver
      # @param plc_directory [String] Optional custom PLC directory URL
      def initialize(plc_directory: nil)
        @plc_directory = plc_directory || PLC_DIRECTORY_URL
      end

      # Resolves a handle to a DID Document
      # @param handle [String] The handle to resolve (with or without @ prefix)
      # @return [Hash] Resolution result with :did, :document, and :pds keys
      # @raise [ResolutionError] if resolution fails
      def resolve_handle(handle)
        validate_handle!(handle)
        normalized = normalize_handle(handle)

        # First try DNS-based resolution
        did = resolve_handle_dns(normalized)
        return get_did_info(did) if did

        # Fall back to HTTP resolution via a known PDS
        resolve_handle_http(normalized)
      rescue StandardError => e
        raise ResolutionError, "Failed to resolve handle #{handle}: #{e.message}"
      end

      # Fetches and parses DID Document
      # @param did [String] The DID to resolve
      # @return [Hash] Resolution result with :did, :document, and :pds keys
      # @raise [ResolutionError] if resolution fails
      def get_did_info(did)
        validate_did!(did)

        # Fetch and parse DID document
        doc_data = fetch_did_document(did)
        document = Document.new(doc_data)

        # Validate PDS URL format
        validate_pds_url!(document.pds)

        { did: did, document: document, pds: document.pds }
      rescue DocumentError => e
        raise ResolutionError, "Invalid DID document: #{e.message}"
      rescue StandardError => e
        raise ResolutionError, "Failed to resolve DID #{did}: #{e.message}"
      end

      # Verifies that a PDS hosts a given DID
      # @param did [String] The DID to verify
      # @param pds_url [String] The PDS URL to check
      # @return [Boolean] true if verification succeeds
      # @raise [ValidationError] if verification fails
      def verify_pds_binding(did, pds_url)
        info = get_did_info(did)
        normalize_url(info[:pds]) == normalize_url(pds_url)
      rescue StandardError => e
        raise ValidationError, "Failed to verify PDS binding: #{e.message}"
      end

      # Verifies that an auth server (issuer) is authorized for a DID
      # @param did [String] The DID to verify
      # @param issuer [String] The issuer URL to verify
      # @return [Boolean] true if verification succeeds
      # @raise [ValidationError] if verification fails
      def verify_issuer_binding(did, issuer)
        # Get PDS location from DID
        info = get_did_info(did)
        pds_url = info[:pds]

        # Fetch resource server metadata to find auth server
        resource_server = ServerMetadata::ResourceServer.from_url(pds_url)
        auth_server_url = resource_server.authorization_servers.first

        # Compare normalized URLs
        normalize_url(auth_server_url) == normalize_url(issuer)
      rescue StandardError => e
        raise ValidationError, "Failed to verify issuer binding: #{e.message}"
      end

      # Verifies that a handle belongs to a DID
      # @param handle [String] Handle to verify
      # @param did [String] DID to check against
      # @return [Boolean] true if verification succeeds
      # @raise [ValidationError] if verification fails
      def verify_handle_binding(handle, did)
        info = get_did_info(did)
        info[:document].has_handle?(handle)
      rescue StandardError => e
        raise ValidationError, "Failed to verify handle binding: #{e.message}"
      end

      private

      def validate_handle!(handle)
        normalized = normalize_handle(handle)
        return if normalized.match?(HANDLE_REGEX)

        raise ResolutionError, "Invalid handle format: #{handle}"
      end

      def validate_did!(did)
        return if did.start_with?(DID_PLC_PREFIX)

        raise ResolutionError, "Invalid DID format (must be did:plc:): #{did}"
      end

      def normalize_handle(handle)
        normalized = handle.start_with?("@") ? handle[1..] : handle
        normalized.downcase
      end

      def resolve_handle_dns(handle)
        domain = extract_domain(handle)
        return nil unless domain

        txt_records = fetch_txt_records("_atproto.#{domain}")
        return nil unless txt_records&.any?

        # Look for did= entries in TXT records
        txt_records.each do |record|
          next unless record.start_with?("did=")

          did = record.delete_prefix("did=").strip
          return did if valid_did?(did)
        end

        nil
      rescue Resolv::ResolvError, Resolv::ResolvTimeout => e
        logger.debug("DNS resolution failed for #{handle}: #{e.message}")
        nil # Gracefully fall back to HTTP resolution
      end

      def extract_domain(handle)
        # Remove @ prefix if present
        handle = handle[1..] if handle.start_with?("@")

        # Handle could be user.domain.com or domain.com format
        # We just need the domain portion
        if handle.count(".") == 1
          handle
        else
          handle.split(".", 2)[1]
        end
      end

      def fetch_txt_records(domain)
        resolver = Resolv::DNS.new
        resolver.timeouts = 3 # 3 second timeout

        records = resolver.getresources(
          domain,
          Resolv::DNS::Resource::IN::TXT
        ).map { |r| r.strings.join(" ") }

        resolver.close
        records
      end

      def valid_did?(did)
        did.start_with?(DID_PLC_PREFIX) && did.length > DID_PLC_PREFIX.length
      end

      def resolve_handle_http(handle)
        # Build resolution URL
        uri = URI("https://#{handle}/.well-known/atproto-did")

        # Make HTTP request
        response = AtprotoAuth.configuration.http_client.get(uri.to_s)
        did = response[:body].strip

        validate_did!(did)
        get_did_info(did)
      end

      def fetch_did_document(did)
        # Fetch document from PLC directory
        uri = URI.join(@plc_directory, "/#{did}")
        response = AtprotoAuth.configuration.http_client.get(uri.to_s)
        JSON.parse(response[:body])
      end

      def validate_pds_url!(url)
        uri = URI(url)
        return if uri.is_a?(URI::HTTPS)

        raise ResolutionError, "PDS URL must use HTTPS"
      end

      def normalize_url(url)
        uri = URI(url)

        # Remove default ports
        uri.port = nil if (uri.scheme == "https" && uri.port == 443) ||
                          (uri.scheme == "http" && uri.port == 80)

        # Ensure no trailing slash
        uri.path = uri.path.chomp("/")

        # Remove any query or fragment
        uri.query = nil
        uri.fragment = nil

        uri.to_s
      end

      def logger
        @logger ||= AtprotoAuth.configuration.logger || Logger.new($stdout)
      end
    end
  end
end
