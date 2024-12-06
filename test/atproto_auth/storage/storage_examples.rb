# frozen_string_literal: true

module AtprotoAuth
  module Test
    # Shared examples for testing storage implementations
    # Include this module in storage implementation tests
    module StorageExamples
      def self.included(base)
        base.class_eval do
          describe "basic operations" do
            it "stores and retrieves values" do
              storage.set("atproto:test:key", "value")
              assert_equal "value", storage.get("atproto:test:key")
            end

            it "handles nil values" do
              storage.set("atproto:test:nil", nil)
              assert_nil storage.get("atproto:test:nil")
            end

            it "returns nil for missing keys" do
              assert_nil storage.get("atproto:test:missing")
            end

            it "deletes values" do
              storage.set("atproto:test:delete", "value")
              assert storage.delete("atproto:test:delete")
              assert_nil storage.get("atproto:test:delete")
            end

            it "checks existence" do
              storage.set("atproto:test:exists", "value")
              assert storage.exists?("atproto:test:exists")
              refute storage.exists?("atproto:test:missing")
            end
          end

          describe "key validation" do
            it "requires atproto: prefix" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("invalid:key", "value")
              end
            end

            it "rejects nil keys" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set(nil, "value")
              end
            end

            it "rejects empty keys" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("", "value")
              end
            end

            it "rejects non-string keys" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set(123, "value")
              end
            end
          end

          describe "TTL handling" do
            it "expires values after TTL" do
              storage.set("atproto:test:ttl", "value", ttl: 1)
              assert_equal "value", storage.get("atproto:test:ttl")
              sleep 1.1 # Wait for expiration
              assert_nil storage.get("atproto:test:ttl")
            end

            it "validates TTL values" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("atproto:test:ttl", "value", ttl: -1)
              end

              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("atproto:test:ttl", "value", ttl: "invalid")
              end
            end

            it "handles nil TTL" do
              storage.set("atproto:test:ttl", "value", ttl: nil)
              assert_equal "value", storage.get("atproto:test:ttl")
            end
          end

          describe "batch operations" do
            it "handles multi-get" do
              storage.set("atproto:test:1", "value1")
              storage.set("atproto:test:2", "value2")

              result = storage.multi_get(["atproto:test:1", "atproto:test:2", "atproto:test:missing"])

              assert_equal(
                {
                  "atproto:test:1" => "value1",
                  "atproto:test:2" => "value2"
                },
                result
              )
            end

            it "handles multi-set" do
              values = {
                "atproto:test:1" => "value1",
                "atproto:test:2" => "value2"
              }

              assert storage.multi_set(values)
              assert_equal "value1", storage.get("atproto:test:1")
              assert_equal "value2", storage.get("atproto:test:2")
            end

            it "handles multi-set with TTL" do
              values = {
                "atproto:test:1" => "value1",
                "atproto:test:2" => "value2"
              }

              assert storage.multi_set(values, ttl: 1)
              assert_equal "value1", storage.get("atproto:test:1")
              assert_equal "value2", storage.get("atproto:test:2")

              sleep 1.1 # Wait for expiration
              assert_nil storage.get("atproto:test:1")
              assert_nil storage.get("atproto:test:2")
            end
          end

          describe "locking" do
            it "acquires and releases locks" do
              assert storage.acquire_lock("atproto:test:lock", ttl: 30)
              refute storage.acquire_lock("atproto:test:lock", ttl: 30)
              assert storage.release_lock("atproto:test:lock")
              assert storage.acquire_lock("atproto:test:lock", ttl: 30)
            end

            it "expires locks after TTL" do
              assert storage.acquire_lock("atproto:test:lock", ttl: 1)
              refute storage.acquire_lock("atproto:test:lock", ttl: 30)

              sleep 1.1 # Wait for expiration
              assert storage.acquire_lock("atproto:test:lock", ttl: 30)
            end

            it "executes blocks with locks" do
              result = storage.with_lock("atproto:test:lock", ttl: 30) do
                # Verify lock is held
                refute storage.acquire_lock("atproto:test:lock", ttl: 30)
                "success"
              end

              assert_equal "success", result
              # Verify lock is released
              assert storage.acquire_lock("atproto:test:lock", ttl: 30)
            end

            it "releases locks after block even if error raised" do
              assert_raises(RuntimeError) do
                storage.with_lock("atproto:test:lock", ttl: 30) do
                  raise "test error"
                end
              end

              # Verify lock is released
              assert storage.acquire_lock("atproto:test:lock", ttl: 30)
            end

            it "requires block for with_lock" do
              assert_raises(ArgumentError) do
                storage.with_lock("atproto:test:lock", ttl: 30)
              end
            end
          end

          describe "concurrency" do
            it "handles concurrent access to same key" do
              threads = 10.times.map do
                Thread.new do
                  storage.set("atproto:test:concurrent", "value")
                  storage.get("atproto:test:concurrent")
                  storage.delete("atproto:test:concurrent")
                end
              end

              threads.each(&:join)
              assert_nil storage.get("atproto:test:concurrent")
            end

            it "handles concurrent lock acquisition" do
              success_count = 0
              threads = 10.times.map do
                Thread.new do
                  if storage.acquire_lock("atproto:test:lock", ttl: 1)
                    success_count += 1
                    sleep 0.1
                    storage.release_lock("atproto:test:lock")
                  end
                end
              end

              threads.each(&:join)
              assert_equal 1, success_count
            end
          end
        end
      end
    end
  end
end
