# frozen_string_literal: true

require "monitor"

module AtprotoAuth
  module Storage
    # Thread-safe in-memory storage implementation
    class Memory < Interface
      def initialize
        super
        @data = {}
        @locks = {}
        @expirations = {}
        @monitor = Monitor.new
        @cleanup_interval = 60 # 1 minute
        start_cleanup_thread
      end

      def set(key, value, ttl: nil)
        validate_key!(key)
        validate_ttl!(ttl)

        @monitor.synchronize do
          @data[key] = value
          set_expiration(key, ttl) if ttl
          true
        end
      end

      def get(key)
        validate_key!(key)

        @monitor.synchronize do
          return nil if expired?(key)

          @data[key]
        end
      end

      def delete(key)
        validate_key!(key)

        @monitor.synchronize do
          @data.delete(key)
          @expirations.delete(key)
          true
        end
      end

      def exists?(key)
        validate_key!(key)

        @monitor.synchronize do
          return false unless @data.key?(key)
          return false if expired?(key)

          true
        end
      end

      def multi_get(keys)
        keys.each { |key| validate_key!(key) }

        @monitor.synchronize do
          result = {}
          keys.each do |key|
            result[key] = @data[key] if @data.key?(key) && !expired?(key)
          end
          result
        end
      end

      def multi_set(hash, ttl: nil)
        hash.each_key { |key| validate_key!(key) }
        validate_ttl!(ttl)

        @monitor.synchronize do
          hash.each do |key, value|
            @data[key] = value
            set_expiration(key, ttl) if ttl
          end
          true
        end
      end

      def acquire_lock(key, ttl:)
        validate_key!(key)
        validate_ttl!(ttl)
        lock_key = "lock:#{key}"

        @monitor.synchronize do
          return false if @locks[lock_key] && !lock_expired?(lock_key)

          @locks[lock_key] = Time.now.to_i + ttl
          true
        end
      end

      def release_lock(key)
        validate_key!(key)
        lock_key = "lock:#{key}"

        @monitor.synchronize do
          @locks.delete(lock_key)
          true
        end
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
      end

      def clear
        @monitor.synchronize do
          @data.clear
          @expirations.clear
          @locks.clear
        end
      end

      private

      def expired?(key)
        return false unless @expirations.key?(key)

        expiry = @expirations[key]
        if Time.now.to_i >= expiry
          @data.delete(key)
          @expirations.delete(key)
          true
        else
          false
        end
      end

      def lock_expired?(lock_key)
        expiry = @locks[lock_key]
        return false unless expiry

        if Time.now.to_i >= expiry
          @locks.delete(lock_key)
          true
        else
          false
        end
      end

      def set_expiration(key, ttl)
        @expirations[key] = Time.now.to_i + ttl
      end

      def cleanup_expired
        @monitor.synchronize do
          now = Time.now.to_i

          # Cleanup expired data
          @expirations.each do |key, expiry|
            if now >= expiry
              @data.delete(key)
              @expirations.delete(key)
            end
          end

          # Cleanup expired locks
          @locks.delete_if { |_, expiry| now >= expiry }
        end
      end

      def start_cleanup_thread
        Thread.new do
          loop do
            sleep @cleanup_interval
            cleanup_expired
          rescue StandardError => e
            # Log error but keep thread running
            AtprotoAuth.configuration.logger.error "Storage cleanup error: #{e.message}"
          end
        end
      end
    end
  end
end
