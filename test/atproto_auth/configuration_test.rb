# frozen_string_literal: true

require_relative "../test_helper"

describe AtprotoAuth::Configuration do
  let(:configuration) { AtprotoAuth::Configuration.new }

  describe "#initialize" do
    it "sets default values" do
      _(configuration.default_token_lifetime).must_equal 300
      _(configuration.dpop_nonce_lifetime).must_equal 300
      _(configuration.logger).must_be_instance_of Logger
      _(configuration.storage).must_be_instance_of AtprotoAuth::Storage::Memory
    end
  end

  describe "#validate!" do
    it "validates valid configuration" do
      _(configuration.validate!).must_equal true
    end

    it "validates custom storage implementation" do
      custom_storage = Class.new(AtprotoAuth::Storage::Interface) do
        def set(key, value, ttl: nil); end
        def get(key); end
        def delete(key); end
        def exists?(key); end
        def multi_get(keys); end
        def multi_set(hash, ttl: nil); end
        def acquire_lock(key, ttl:); end
        def release_lock(key); end
        def with_lock(key, ttl: 30); end
      end.new

      configuration.storage = custom_storage
      _(configuration.validate!).must_equal true
    end

    it "raises error for invalid storage implementation" do
      configuration.storage = Object.new
      assert_raises(AtprotoAuth::ConfigurationError) do
        configuration.validate!
      end
    end

    it "raises error for nil storage" do
      configuration.storage = nil
      assert_raises(AtprotoAuth::ConfigurationError) do
        configuration.validate!
      end
    end

    it "validates http client interface" do
      valid_client = Object.new
      def valid_client.get(url, headers = {}); end
      def valid_client.post(url, body: nil, headers: {}); end

      configuration.http_client = valid_client
      _(configuration.validate!).must_equal true
    end

    it "raises error for invalid http client" do
      configuration.http_client = Object.new
      assert_raises(AtprotoAuth::ConfigurationError) do
        configuration.validate!
      end
    end
  end
end
