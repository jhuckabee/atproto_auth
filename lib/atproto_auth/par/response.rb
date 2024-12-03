# frozen_string_literal: true

module AtprotoAuth
  module PAR
    # Represents a PAR response
    class Response
      attr_reader :request_uri, :expires_in

      def initialize(request_uri:, expires_in:)
        @request_uri = request_uri
        @expires_in = expires_in.to_i
        validate!
      end

      private

      def validate!
        raise Error, "request_uri is required" if request_uri.nil? || request_uri.empty?
        raise Error, "expires_in must be positive" unless expires_in.positive?
      end
    end
  end
end
