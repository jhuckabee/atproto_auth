# frozen_string_literal: true

require "securerandom"
require "time"
require "monitor"

module AtprotoAuth
  module State
    # Tracks state for an OAuth authorization flow session
    class Session
      include MonitorMixin

      attr_reader :session_id, :state_token, :client_id, :scope,
                  :pkce_verifier, :pkce_challenge, :auth_server,
                  :did, :tokens

      # Creates a new OAuth session
      # @param client_id [String] OAuth client ID
      # @param scope [String] Requested scope
      # @param auth_server [AuthorizationServer, nil] Optional pre-resolved auth server
      # @param did [String, nil] Optional pre-resolved DID
      def initialize(client_id:, scope:, auth_server: nil, did: nil)
        super() # Initialize MonitorMixin

        @session_id = SecureRandom.uuid
        @state_token = SecureRandom.urlsafe_base64(32)
        @client_id = client_id
        @scope = scope
        @auth_server = auth_server
        @did = did

        # Generate PKCE values
        @pkce_verifier = PKCE.generate_verifier
        @pkce_challenge = PKCE.generate_challenge(@pkce_verifier)

        @tokens = nil
      end

      # Updates the authorization server for this session
      # @param server [AuthorizationServer] The resolved auth server
      # @return [void]
      # @raise [SessionError] if session is already bound to different server
      def authorization_server=(server)
        synchronize do
          if @auth_server && @auth_server.issuer != server.issuer
            raise SessionError, "Session already bound to different authorization server"
          end

          @auth_server = server
        end
      end

      # Updates the user's DID for this session
      # @param did [String] The resolved DID
      # @return [void]
      # @raise [SessionError] if session already has different DID
      def did=(did)
        synchronize do
          raise SessionError, "Session already bound to different DID" if @did && @did != did

          @did = did
        end
      end

      # Updates tokens for this session
      # @param tokens [TokenSet] New token set
      # @return [void]
      # @raise [SessionError] if tokens don't match session DID
      def tokens=(tokens)
        synchronize do
          raise SessionError, "Token subject doesn't match session DID" if @did && tokens.sub != @did

          @tokens = tokens
          @did ||= tokens.sub
        end
      end

      # Whether this session has valid access tokens
      # @return [Boolean]
      def authorized?
        synchronize do
          !@tokens.nil? && !@tokens.expired?
        end
      end

      # Whether this session can refresh its tokens
      # @return [Boolean]
      def renewable?
        synchronize do
          !@tokens.nil? && @tokens.renewable?
        end
      end

      # Validates a state token against this session
      # @param state [String] State token to validate
      # @return [Boolean]
      def validate_state(state)
        return false unless state

        # Use secure comparison to prevent timing attacks
        secure_compare(@state_token, state)
      end

      private

      def secure_compare(str1, str2)
        return false unless str1.bytesize == str2.bytesize

        left = str1.unpack("C*")
        right = str2.unpack("C*")
        result = 0
        left.zip(right) { |x, y| result |= x ^ y }
        result.zero?
      end
    end
  end
end
