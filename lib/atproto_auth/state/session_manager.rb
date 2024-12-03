# frozen_string_literal: true

require "securerandom"
require "time"
require "monitor"

module AtprotoAuth
  module State
    # Manages active OAuth sessions
    class SessionManager
      include MonitorMixin

      def initialize
        super # Initialize MonitorMixin
        @sessions = {}
      end

      # Creates and stores a new session
      # @param client_id [String] OAuth client ID
      # @param scope [String] Requested scope
      # @param auth_server [AuthorizationServer, nil] Optional pre-resolved auth server
      # @param did [String, nil] Optional pre-resolved DID
      # @return [Session] The created session
      def create_session(client_id:, scope:, auth_server: nil, did: nil)
        session = Session.new(
          client_id: client_id,
          scope: scope,
          auth_server: auth_server,
          did: did
        )

        synchronize do
          @sessions[session.session_id] = session
        end

        session
      end

      # Retrieves a session by ID
      # @param session_id [String] Session ID to look up
      # @return [Session, nil] The session if found
      def get_session(session_id)
        synchronize do
          @sessions[session_id]
        end
      end

      # Finds a session by state token
      # @param state [String] State token to look up
      # @return [Session, nil] The session if found
      def get_session_by_state(state)
        synchronize do
          @sessions.values.find { |session| session.validate_state(state) }
        end
      end

      # Removes a session
      # @param session_id [String] Session ID to remove
      # @return [void]
      def remove_session(session_id)
        synchronize do
          @sessions.delete(session_id)
        end
      end

      # Removes all expired sessions
      # @return [void]
      def cleanup_expired
        synchronize do
          @sessions.delete_if { |_, session| !session.renewable? && session.tokens&.expired? }
        end
      end
    end
  end
end
