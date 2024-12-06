# frozen_string_literal: true

module AtprotoAuth
  module Serialization
    # Handles serialization of DPoP keys
    class DPoPKey < Base
      def type_identifier
        "DPoPKey"
      end

      private

      def validate_object!(obj)
        return if obj.is_a?(AtprotoAuth::DPoP::KeyManager)

        raise ValidationError,
              "Expected KeyManager object, got #{obj.class}"
      end

      def serialize_data(obj)
        obj.to_jwk(include_private: true).to_h
      end

      def deserialize_data(data)
        AtprotoAuth::DPoP::KeyManager.from_jwk(data)
      end
    end
  end
end
