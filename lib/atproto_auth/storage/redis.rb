# frozen_string_literal: true

require "redis"

module AtprotoAuth
  module Storage
    # Redis storage implementation
    class Redis < Interface
      # Error raised for Redis-specific issues
      class RedisError < StorageError; end

      def initialize(redis_client: nil)
        super()
        @redis_client = redis_client || ::Redis.new
      end

      def set(key, value, ttl: nil)
        validate_key!(key)
        validate_ttl!(ttl) if ttl

        @redis_client.set(key, value, ex: ttl)
        true
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to set value: #{e.message}"
      end

      def get(key)
        validate_key!(key)

        value = @redis_client.get(key)
        value.nil? || value == "" ? nil : value
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to get value: #{e.message}"
      end

      def delete(key)
        validate_key!(key)

        @redis_client.del(key).positive?
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to delete value: #{e.message}"
      end

      def exists?(key)
        validate_key!(key)

        @redis_client.exists?(key)
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to check existence: #{e.message}"
      end

      def multi_get(keys)
        keys.each { |key| validate_key!(key) }

        values = @redis_client.mget(keys)
        result = {}

        # Only include non-nil values in result hash
        keys.zip(values).each do |key, value|
          next if value.nil? || value == ""

          result[key] = value
        end

        result
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to get multiple values: #{e.message}"
      end

      def multi_set(hash, ttl: nil)
        hash.each_key { |key| validate_key!(key) }
        validate_ttl!(ttl) if ttl

        @redis_client.multi do |tx|
          hash.each do |key, value|
            tx.set(key, value, ex: ttl)
          end
        end
        true
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to set multiple values: #{e.message}"
      end

      def acquire_lock(key, ttl:)
        validate_key!(key)
        validate_ttl!(ttl)

        lock_key = "atproto:locks:#{key}"
        @redis_client.set(lock_key, Time.now.to_i, nx: true, ex: ttl)
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to acquire lock: #{e.message}"
      end

      def release_lock(key)
        validate_key!(key)

        lock_key = "atproto:locks:#{key}"
        @redis_client.del(lock_key).positive?
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to release lock: #{e.message}"
      end

      def with_lock(key, ttl: 30)
        raise ArgumentError, "Block required" unless block_given?

        acquired = acquire_lock(key, ttl: ttl)
        raise LockError, "Failed to acquire lock" unless acquired

        begin
          yield
        ensure
          release_lock(key)
        end
      rescue ::Redis::BaseError => e
        raise RedisError, "Lock operation failed: #{e.message}"
      end
    end
  end
end
