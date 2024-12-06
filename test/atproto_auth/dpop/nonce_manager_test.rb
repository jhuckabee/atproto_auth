# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::DPoP::NonceManager do
  let(:server_url) { "https://example.com" }
  let(:invalid_server_url) { "http://example.com" }
  let(:nonce) { "valid_nonce" }
  let(:expired_nonce) { "expired_nonce" }
  let(:ttl) { 2 } # Custom TTL for testing expiration
  let(:nonce_manager) { AtprotoAuth::DPoP::NonceManager.new(ttl: ttl) }

  after do
    nonce_manager.clear(server_url)
  end

  describe "#initialize" do
    it "initializes with a default TTL" do
      manager = AtprotoAuth::DPoP::NonceManager.new
      _(manager.instance_variable_get(:@ttl)).must_equal AtprotoAuth::DPoP::NonceManager::DEFAULT_TTL
    end

    it "initializes with a custom TTL" do
      _(nonce_manager.instance_variable_get(:@ttl)).must_equal ttl
    end
  end

  describe "#update" do
    it "stores a nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      stored = nonce_manager.get(server_url)
      _(stored).must_equal nonce
    end

    it "updates an existing nonce" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      nonce_manager.update(nonce: "new_nonce", server_url: server_url)
      _(nonce_manager.get(server_url)).must_equal "new_nonce"
    end

    it "stores nonce for non-HTTPS localhost server" do
      nonce_manager.update(nonce: nonce, server_url: "http://localhost:3000")
      stored = nonce_manager.get("http://localhost:3000")
      _(stored).must_equal nonce
    end

    it "raises an error if nonce is invalid" do
      assert_raises(AtprotoAuth::DPoP::NonceManager::NonceError) do
        nonce_manager.update(nonce: "", server_url: server_url)
      end
    end

    it "raises an error if server_url is invalid" do
      assert_raises(AtprotoAuth::DPoP::NonceManager::NonceError) do
        nonce_manager.update(nonce: nonce, server_url: invalid_server_url)
      end
    end
  end

  describe "#get" do
    it "returns the current nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      _(nonce_manager.get(server_url)).must_equal nonce
    end

    it "returns nil if no nonce exists for the server" do
      _(nonce_manager.get(server_url)).must_equal nil
    end

    it "returns nil if the nonce has expired" do
      nonce_manager.update(nonce: expired_nonce, server_url: server_url)
      sleep(ttl + 0.1) # Wait for expiration
      _(nonce_manager.get(server_url)).must_be_nil
    end

    it "raises an error if server_url is invalid" do
      assert_raises(AtprotoAuth::DPoP::NonceManager::NonceError) do
        nonce_manager.get("")
      end
    end
  end

  describe "#clear" do
    it "removes a nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      nonce_manager.clear(server_url)
      _(nonce_manager.get(server_url)).must_be_nil
    end
  end

  describe "#valid_nonce?" do
    it "returns true if the server has a valid nonce" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      _(nonce_manager.valid_nonce?(server_url)).must_equal true
    end

    it "returns false if no nonce exists for the server" do
      _(nonce_manager.valid_nonce?(server_url)).must_equal false
    end

    it "returns false if the nonce has expired" do
      nonce_manager.update(nonce: expired_nonce, server_url: server_url)
      sleep(ttl + 0.1) # Wait for expiration
      _(nonce_manager.valid_nonce?(server_url)).must_equal false
    end

    it "raises an error if server_url is invalid" do
      assert_raises(AtprotoAuth::DPoP::NonceManager::NonceError) do
        nonce_manager.valid_nonce?("")
      end
    end
  end

  describe "thread safety" do
    it "handles concurrent nonce updates" do
      threads = 10.times.map do |i|
        Thread.new do
          nonce_manager.update(nonce: "nonce_#{i}", server_url: server_url)
          sleep(0.1)
          nonce_manager.get(server_url)
        end
      end

      threads.each(&:join)
      # The nonce should exist and be one of the values we set
      stored = nonce_manager.get(server_url)
      assert stored =~ /^nonce_\d$/
    end
  end
end
