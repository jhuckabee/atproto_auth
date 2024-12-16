# frozen_string_literal: true

module AtprotoAuth
  module State
    # Represents a set of OAuth tokens and their associated metadata
    class TokenSet
      attr_reader :access_token, :refresh_token, :token_type,
                  :scope, :expires_at, :sub

      # Creates a new TokenSet from a token response
      # @param access_token [String] The access token
      # @param token_type [String] Token type (must be "DPoP")
      # @param expires_in [Integer] Token lifetime in seconds
      # @param refresh_token [String, nil] Optional refresh token
      # @param scope [String] Space-separated list of granted scopes
      # @param sub [String] DID of the authenticated user
      def initialize( # rubocop:disable Metrics/ParameterLists
        access_token:,
        token_type:,
        expires_in:,
        scope:,
        sub:,
        refresh_token: nil
      )
        validate_token_type!(token_type)
        validate_required!("access_token", access_token)
        validate_required!("scope", scope)
        validate_required!("sub", sub)
        validate_expires_in!(expires_in)

        @access_token = access_token
        @refresh_token = refresh_token
        @token_type = token_type
        @scope = scope
        @sub = sub
        @expires_at = Time.now + expires_in
      end

      # Whether this token set includes a refresh token
      # @return [Boolean]
      def renewable?
        !@refresh_token.nil? && !@refresh_token.empty?
      end

      # Whether the access token has expired
      # @return [Boolean]
      def expired?(buffer = 30)
        Time.now >= (@expires_at - buffer)
      end

      private

      def validate_token_type!(type)
        raise ArgumentError, "token_type must be DPoP" unless type == "DPoP"
      end

      def validate_required!(name, value)
        raise ArgumentError, "#{name} is required" if value.nil? || value.empty?
      end

      def validate_expires_in!(expires_in)
        return if expires_in.is_a?(Integer)

        raise ArgumentError, "expires_in must be an integer"
      end
    end
  end
end
