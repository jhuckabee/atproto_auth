# frozen_string_literal: true

require "resolv"

module AtprotoAuth
  module Identity
    # Validates decentralized identifiers (DIDs)
    class DID
      PREFIXES = ["did:plc:", "did:web:"].freeze

      def initialize(did)
        @did = did
      end

      def validate!
        return if PREFIXES.any? { |prefix| @did.start_with?(prefix) }

        raise Error, "Invalid DID format (must be one of #{PREFIXES.join(", ")}): #{@did}"
      end

      def to_s
        @did
      end
    end
  end
end
