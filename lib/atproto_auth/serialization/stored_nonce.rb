# frozen_string_literal: true

module AtprotoAuth
  module Serialization
    # Handles serialization of StoredNonce objects
    class StoredNonce < Base
      def type_identifier
        "StoredNonce"
      end

      private

      def validate_object!(obj)
        return if obj.is_a?(AtprotoAuth::DPoP::NonceManager::StoredNonce)

        raise ValidationError,
              "Expected StoredNonce object, got #{obj.class}"
      end

      def serialize_data(obj)
        {
          value: obj.value,
          server_url: obj.server_url,
          timestamp: obj.timestamp
        }
      end

      def deserialize_data(data)
        AtprotoAuth::DPoP::NonceManager::StoredNonce.new(
          data["value"],
          data["server_url"],
          timestamp: Time.at(data["timestamp"])
        )
      end
    end
  end
end
