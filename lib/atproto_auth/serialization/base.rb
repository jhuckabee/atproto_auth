# frozen_string_literal: true

module AtprotoAuth
  module Serialization
    class Error < AtprotoAuth::Error; end

    class VersionError < Error; end

    class TypeMismatchError < Error; end

    class ValidationError < Error; end

    # Base serializer that all type-specific serializers inherit from
    class Base
      CURRENT_VERSION = 1
      SENSITIVE_FIELDS = [
        "access_token",
        "refresh_token",
        "private_key",
        "d", # EC private key component
        "pkce_verifier"
      ].freeze

      class << self
        # Serialize object to storage format
        # @param obj [Object] Object to serialize
        # @return [String] JSON serialized data
        def serialize(obj)
          new.serialize(obj)
        end

        # Deserialize from storage format
        # @param data [String] JSON serialized data
        # @return [Object] Deserialized object
        def deserialize(data)
          new.deserialize(data)
        end
      end

      def initialize
        @encryption = Encryption::Service.new
      end

      # Serialize object to storage format
      # @param obj [Object] Object to serialize
      # @return [String] JSON serialized data
      def serialize(obj)
        validate_object!(obj)

        # First serialize the object
        data = {
          version: CURRENT_VERSION,
          type: type_identifier,
          created_at: Time.now.utc.iso8601,
          updated_at: Time.now.utc.iso8601,
          data: serialize_data(obj)
        }

        # Then encrypt sensitive fields
        encrypt_sensitive_fields!(data)

        # Finally convert to JSON
        JSON.generate(data)
      end

      # Deserialize from storage format
      # @param data [String] JSON serialized data
      # @return [Object] Deserialized object
      def deserialize(data)
        parsed = parse_json(data)
        validate_serialized_data!(parsed)

        # Decrypt sensitive fields
        decrypt_sensitive_fields!(parsed)

        # Deserialize according to version
        deserialize_version(parsed)
      end

      private

      def encrypt_sensitive_fields!(data, path: [])
        return unless data.is_a?(Hash)

        data.each do |key, value|
          current_path = path + [key]

          if sensitive_field?(key)
            data[key] = @encryption.encrypt(
              value.to_s,
              context: current_path.join(".")
            )
          elsif value.is_a?(Hash)
            encrypt_sensitive_fields!(value, path: current_path)
          elsif value.is_a?(Array)
            value.each_with_index do |v, i|
              encrypt_sensitive_fields!(v, path: current_path + [i.to_s]) if v.is_a?(Hash)
            end
          end
        end
      end

      def decrypt_sensitive_fields!(data, path: [])
        return unless data.is_a?(Hash)

        data.each do |key, value|
          current_path = path + [key]
          if sensitive_field?(key)
            data[key] = @encryption.decrypt(
              value.transform_keys(&:to_sym),
              context: current_path.join(".")
            )
          elsif value.is_a?(Hash)
            decrypt_sensitive_fields!(value, path: current_path)
          elsif value.is_a?(Array)
            value.each_with_index do |v, i|
              decrypt_sensitive_fields!(v, path: current_path + [i.to_s]) if v.is_a?(Hash)
            end
          end
        end
      end

      def sensitive_field?(field)
        SENSITIVE_FIELDS.any? do |sensitive_field|
          field.to_s == sensitive_field
        end
      end

      # Type identifier for serialized data
      # @return [String]
      def type_identifier
        raise NotImplementedError
      end

      # Serialize object to hash
      # @param obj [Object] Object to serialize
      # @return [Hash] Serialized data
      def serialize_data(_obj)
        raise NotImplementedError
      end

      # Deserialize object from hash
      # @param data [Hash] Serialized data
      # @return [Object] Deserialized object
      def deserialize_data(_data)
        raise NotImplementedError
      end

      # Validate object before serialization
      # @param obj [Object] Object to validate
      # @raise [ValidationError] if object is invalid
      def validate_object!(_obj)
        raise NotImplementedError
      end

      def parse_json(data)
        JSON.parse(data)
      rescue JSON::ParserError => e
        raise Error, "Invalid JSON data: #{e.message}"
      end

      def validate_serialized_data!(data)
        raise Error, "Invalid serialized data format" unless data.is_a?(Hash)

        unless data["type"] == type_identifier
          raise TypeMismatchError,
                "Expected type #{type_identifier}, got #{data["type"]}"
        end

        raise VersionError, "Invalid version format" unless data["version"].is_a?(Integer)

        return unless data["version"] > CURRENT_VERSION

        raise VersionError,
              "Version #{data["version"]} not supported"
      end

      def deserialize_version(data)
        case data["version"]
        when 1
          deserialize_data(data["data"])
        else
          raise VersionError,
                "Unknown version: #{data["version"]}"
        end
      end
    end
  end
end
