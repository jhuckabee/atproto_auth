# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "storage_examples"

describe AtprotoAuth::Storage::Memory do
  let(:storage) { AtprotoAuth::Storage::Memory.new }

  include AtprotoAuth::Test::StorageExamples

  describe "memory-specific behavior" do
    it "cleans up expired keys automatically" do
      storage.set("atproto:test:short", "value", ttl: 1)
      storage.set("atproto:test:long", "value", ttl: 3600)

      assert_equal "value", storage.get("atproto:test:short")
      sleep 1.1 # Wait for expiration
      assert_nil storage.get("atproto:test:short")
      assert_equal "value", storage.get("atproto:test:long")
    end

    it "handles clear operation" do
      storage.set("atproto:test:1", "value1")
      storage.set("atproto:test:2", "value2")

      storage.clear

      assert_nil storage.get("atproto:test:1")
      assert_nil storage.get("atproto:test:2")
    end
  end
end
