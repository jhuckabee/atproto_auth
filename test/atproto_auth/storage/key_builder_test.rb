# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Storage::KeyBuilder do
  describe ".session_key" do
    it "builds valid session key" do
      assert_equal "atproto:session:123", AtprotoAuth::Storage::KeyBuilder.session_key("123")
    end
  end

  describe ".state_key" do
    it "builds valid state key" do
      assert_equal "atproto:state:xyz789", AtprotoAuth::Storage::KeyBuilder.state_key("xyz789")
    end
  end

  describe ".nonce_key" do
    it "builds valid nonce key" do
      assert_equal "atproto:nonce:example.com", AtprotoAuth::Storage::KeyBuilder.nonce_key("example.com")
    end
  end

  describe ".dpop_key" do
    it "builds valid dpop key" do
      assert_equal "atproto:dpop:client123", AtprotoAuth::Storage::KeyBuilder.dpop_key("client123")
    end
  end

  describe ".lock_key" do
    it "builds valid lock key" do
      assert_equal "atproto:lock:session:123",
                   AtprotoAuth::Storage::KeyBuilder.lock_key("session", "123")
    end
  end
end
