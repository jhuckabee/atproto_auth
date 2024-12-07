# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "storage_examples"

describe AtprotoAuth::Storage::Redis do
  let(:redis) { Redis.new(url: ENV.fetch("REDIS_URL", "redis://localhost:6379")) }
  let(:storage) { AtprotoAuth::Storage::Redis.new(redis_client: redis) }

  # Include shared storage implementation tests
  include AtprotoAuth::Test::StorageExamples

  before do
    # Clear test keys before each test
    keys = redis.keys("atproto:*")
    redis.del(*keys) if keys.any?
  end

  describe "#initialize" do
    it "accepts a custom redis client" do
      custom_redis = Redis.new
      storage = AtprotoAuth::Storage::Redis.new(redis_client: custom_redis)
      _(storage.instance_variable_get(:@redis_client)).must_equal custom_redis
    end

    it "creates default redis client if none provided" do
      storage = AtprotoAuth::Storage::Redis.new
      _(storage.instance_variable_get(:@redis_client)).must_be_instance_of Redis
    end
  end

  describe "error handling" do
    it "wraps Redis connection errors" do
      redis.stub(:set, proc { raise Redis::ConnectionError }) do
        assert_raises(AtprotoAuth::Storage::Redis::RedisError) do
          storage.set("atproto:test:key", "value")
        end
      end
    end

    it "wraps Redis command errors" do
      redis.stub(:get, proc { raise Redis::CommandError }) do
        assert_raises(AtprotoAuth::Storage::Redis::RedisError) do
          storage.get("atproto:test:key")
        end
      end
    end
  end

  describe "TTL handling" do
    it "sets TTL on values" do
      storage.set("atproto:test:ttl", "value", ttl: 2)
      ttl = redis.ttl("atproto:test:ttl")
      assert_operator ttl, :>=, 1
      assert_operator ttl, :<=, 2
    end

    it "handles TTL in multi_set" do
      storage.multi_set({
                          "atproto:test:ttl1" => "value1",
                          "atproto:test:ttl2" => "value2"
                        }, ttl: 2)

      ["atproto:test:ttl1", "atproto:test:ttl2"].each do |key|
        ttl = redis.ttl(key)
        assert_operator ttl, :>=, 1
        assert_operator ttl, :<=, 2
      end
    end
  end

  describe "locking" do
    after do
      # Clean up any leftover locks
      redis.del("atproto:locks:atproto:test:lock")
    end

    it "creates lock with correct key prefix" do
      storage.acquire_lock("atproto:test:lock", ttl: 30)
      assert redis.exists?("atproto:locks:atproto:test:lock")
    end

    it "prevents duplicate lock acquisition" do
      storage.acquire_lock("atproto:test:lock", ttl: 30)
      refute storage.acquire_lock("atproto:test:lock", ttl: 30)
    end

    it "releases lock properly" do
      storage.acquire_lock("atproto:test:lock", ttl: 30)
      assert storage.release_lock("atproto:test:lock")
      refute redis.exists?("atproto:locks:atproto:test:lock")
    end

    it "ensures lock is released after block execution" do
      executed = false
      storage.with_lock("atproto:test:lock", ttl: 30) do
        executed = true
      end

      assert executed, "Block should have executed"
      refute redis.exists?("atproto:locks:atproto:test:lock")
    end

    it "ensures lock is released even if block raises error" do
      assert_raises(RuntimeError) do
        storage.with_lock("atproto:test:lock", ttl: 30) do
          raise "test error"
        end
      end

      refute redis.exists?("atproto:locks:atproto:test:lock")
    end

    it "releases lock if Redis connection fails during block execution" do
      redis.stub(:del, proc { raise Redis::ConnectionError }) do
        assert_raises(AtprotoAuth::Storage::Redis::RedisError) do
          storage.with_lock("atproto:test:lock", ttl: 30) { true }
        end
      end
    end
  end

  describe "atomic operations" do
    it "performs multi_set atomically" do
      storage.multi_set({
                          "atproto:test:1" => "value1",
                          "atproto:test:2" => "value2"
                        })

      # Both values should be set
      assert_equal "value1", storage.get("atproto:test:1")
      assert_equal "value2", storage.get("atproto:test:2")
    end

    it "rolls back multi_set if any operation fails" do
      # Simulate failure on second operation
      def storage.validate_key!(key)
        raise AtprotoAuth::Storage::StorageError if key == "atproto:test:2"

        super
      end

      assert_raises(AtprotoAuth::Storage::StorageError) do
        storage.multi_set({
                            "atproto:test:1" => "value1",
                            "atproto:test:2" => "value2"
                          })
      end

      # Value should not be set due to rollback
      assert_nil storage.get("atproto:test:1")
    end
  end
end
