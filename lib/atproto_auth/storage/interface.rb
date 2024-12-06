# frozen_string_literal: true

module AtprotoAuth
  module Storage
    # Base storage interface that all implementations must conform to
    class Interface
      # Store a value with optional TTL
      # @param key [String] Storage key
      # @param value [Object] Value to store
      # @param ttl [Integer, nil] Time-to-live in seconds
      # @return [Boolean] Success status
      # @raise [StorageError] if operation fails
      def set(key, value, ttl: nil)
        raise NotImplementedError
      end

      # Retrieve a value
      # @param key [String] Storage key
      # @return [Object, nil] Stored value or nil if not found
      # @raise [StorageError] if operation fails
      def get(key)
        raise NotImplementedError
      end

      # Delete a value
      # @param key [String] Storage key
      # @return [Boolean] Success status
      # @raise [StorageError] if operation fails
      def delete(key)
        raise NotImplementedError
      end

      # Check if key exists
      # @param key [String] Storage key
      # @return [Boolean] True if key exists
      # @raise [StorageError] if operation fails
      def exists?(key)
        raise NotImplementedError
      end

      # Get multiple values
      # @param keys [Array<String>] Storage keys
      # @return [Hash<String, Object>] Key-value pairs
      # @raise [StorageError] if operation fails
      def multi_get(keys)
        raise NotImplementedError
      end

      # Store multiple values
      # @param hash [Hash<String, Object>] Key-value pairs
      # @param ttl [Integer, nil] Time-to-live in seconds
      # @return [Boolean] Success status
      # @raise [StorageError] if operation fails
      def multi_set(hash, ttl: nil)
        raise NotImplementedError
      end

      # Acquire a lock
      # @param key [String] Lock key
      # @param ttl [Integer] Lock timeout in seconds
      # @return [Boolean] True if lock acquired
      # @raise [StorageError] if operation fails
      def acquire_lock(key, ttl:)
        raise NotImplementedError
      end

      # Release a lock
      # @param key [String] Lock key
      # @return [Boolean] Success status
      # @raise [StorageError] if operation fails
      def release_lock(key)
        raise NotImplementedError
      end

      # Execute block with lock
      # @param key [String] Lock key
      # @param ttl [Integer] Lock timeout in seconds
      # @yield Block to execute with lock
      # @return [Object] Block result
      # @raise [StorageError] if operation fails
      def with_lock(key, ttl: 30)
        raise NotImplementedError
      end

      protected

      # Validate key format
      # @param key [String] Key to validate
      # @raise [StorageError] if key is invalid
      def validate_key!(key)
        raise StorageError, "Key cannot be nil" if key.nil?
        raise StorageError, "Key must be a string" unless key.is_a?(String)
        raise StorageError, "Key cannot be empty" if key.empty?
        raise StorageError, "Invalid key format" unless key.start_with?("atproto:")
      end

      # Validate TTL value
      # @param ttl [Integer, nil] TTL to validate
      # @raise [StorageError] if TTL is invalid
      def validate_ttl!(ttl)
        return if ttl.nil?
        raise StorageError, "TTL must be a positive integer" unless ttl.is_a?(Integer) && ttl.positive?
      end
    end

    # Base error class for storage operations
    class StorageError < AtprotoAuth::Error; end

    # Error for lock-related operations
    class LockError < StorageError; end
  end
end
