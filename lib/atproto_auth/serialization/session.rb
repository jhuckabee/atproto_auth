# frozen_string_literal: true

module AtprotoAuth
  module Serialization
    # Handles serialization of Session objects
    class Session < Base
      def type_identifier
        "Session"
      end

      private

      def validate_object!(obj)
        return if obj.is_a?(AtprotoAuth::State::Session)

        raise ValidationError,
              "Expected Session object, got #{obj.class}"
      end

      def serialize_data(obj)
        {
          session_id: obj.session_id,
          state_token: obj.state_token,
          client_id: obj.client_id,
          scope: obj.scope,
          pkce_verifier: obj.pkce_verifier,
          pkce_challenge: obj.pkce_challenge,
          did: obj.did,
          tokens: serialize_token_set(obj.tokens),
          auth_server: serialize_auth_server(obj.auth_server)
        }
      end

      def deserialize_data(data)
        AtprotoAuth::State::Session.new(
          client_id: data["client_id"],
          scope: data["scope"],
          did: data["did"],
          auth_server: deserialize_auth_server(data["auth_server"])
        ).tap do |session|
          # Set readonly attributes
          session.instance_variable_set(:@session_id, data["session_id"])
          session.instance_variable_set(:@state_token, data["state_token"])
          session.instance_variable_set(:@pkce_verifier, data["pkce_verifier"])
          session.instance_variable_set(:@pkce_challenge, data["pkce_challenge"])

          # Set tokens if present
          session.tokens = deserialize_token_set(data["tokens"]) if data["tokens"]
        end
      end

      def serialize_token_set(tokens)
        return nil unless tokens

        TokenSet.new.serialize(tokens)
      end

      def deserialize_token_set(data)
        return nil unless data

        TokenSet.new.deserialize(data)
      end

      def serialize_auth_server(server)
        return nil unless server

        server.to_h
      end

      def deserialize_auth_server(data)
        return nil unless data

        AtprotoAuth::ServerMetadata::AuthorizationServer.new(data)
      end
    end
  end
end
