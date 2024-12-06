# frozen_string_literal: true

module AtprotoAuth
  module State
    # Manages active OAuth sessions with secure persistent storage
    class SessionManager
      def initialize
        @serializer = Serialization::Session.new
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

        # Store both session and state mapping atomically
        session_key = Storage::KeyBuilder.session_key(session.session_id)
        state_key = Storage::KeyBuilder.state_key(session.state_token)

        AtprotoAuth.storage.with_lock(session_key, ttl: 30) do
          serialized = @serializer.serialize(session)
          AtprotoAuth.storage.set(session_key, serialized)
          AtprotoAuth.storage.set(state_key, session.session_id)
        end

        session
      end

      # Updates an existing session
      # @return [Session] The session to update
      # @return [Session] The updated session
      def update_session(session)
        session_key = Storage::KeyBuilder.session_key(session.session_id)

        AtprotoAuth.storage.with_lock(session_key, ttl: 30) do
          serialized = @serializer.serialize(session)
          AtprotoAuth.storage.set(session_key, serialized)

          state_key = Storage::KeyBuilder.state_key(session.state_token)
          AtprotoAuth.storage.set(state_key, session.session_id)
        end

        session
      end

      # Retrieves a session by ID
      # @param session_id [String] Session ID to look up
      # @return [Session, nil] The session if found
      def get_session(session_id)
        session_key = Storage::KeyBuilder.session_key(session_id)

        begin
          serialized = AtprotoAuth.storage.get(session_key)
          return nil unless serialized
        rescue StandardError => e
          AtprotoAuth.configuration.logger.error("Failed to get session: #{e.message}")
          return nil
        end

        begin
          session = @serializer.deserialize(serialized)
          return nil if !session.renewable? && session.tokens&.expired?

          session
        rescue StandardError => e
          AtprotoAuth.configuration.logger.error("Failed to deserialize session: #{e.message}")
          nil
        end
      end

      # Finds a session by state token
      # @param state [String] State token to look up
      # @return [Session, nil] The session if found
      def get_session_by_state(state)
        return nil unless state

        state_key = Storage::KeyBuilder.state_key(state)

        begin
          session_id = AtprotoAuth.storage.get(state_key)
          return nil unless session_id
        rescue StandardError => e
          AtprotoAuth.configuration.logger.error("Failed to get session by state: #{e.message}")
          return nil
        end

        get_session(session_id)
      end

      # Removes a session
      # @param session_id [String] Session ID to remove
      # @return [void]
      def remove_session(session_id)
        session = get_session(session_id)
        return unless session

        session_key = Storage::KeyBuilder.session_key(session_id)
        state_key = Storage::KeyBuilder.state_key(session.state_token)

        AtprotoAuth.storage.with_lock(session_key, ttl: 30) do
          AtprotoAuth.storage.delete(session_key)
          AtprotoAuth.storage.delete(state_key)
        end
      end

      # Removes all expired sessions
      # @return [void]
      def cleanup_expired
        # No-op - expiry handled by storage TTL and retrieval validation
      end
    end
  end
end
