# frozen_string_literal: true

module AtprotoAuth
  module Storage
    # Utility for building storage keys with correct format
    class KeyBuilder
      NAMESPACE_SEPARATOR = ":"
      NAMESPACE_PREFIX = "atproto"

      class << self
        def session_key(id)
          build_key("session", id)
        end

        def state_key(token)
          build_key("state", token)
        end

        def nonce_key(server_url)
          build_key("nonce", server_url)
        end

        def dpop_key(client_id)
          build_key("dpop", client_id)
        end

        def lock_key(namespace, id)
          build_key("lock", namespace, id)
        end

        private

        def build_key(*parts)
          [NAMESPACE_PREFIX, *parts].join(NAMESPACE_SEPARATOR)
        end
      end
    end
  end
end
