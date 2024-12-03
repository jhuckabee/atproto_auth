# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::DPoP::NonceManager do
  let(:server_url) { "https://example.com" }
  let(:invalid_server_url) { "http://example.com" }
  let(:nonce) { "valid_nonce" }
  let(:expired_nonce) { "expired_nonce" }
  let(:ttl) { 2 } # Custom TTL for testing expiration
  let(:nonce_manager) { AtprotoAuth::DPoP::NonceManager.new(ttl: ttl) }

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
    it "updates the nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      stored_nonce = nonce_manager.instance_variable_get(:@nonces)[server_url]
      _(stored_nonce.value).must_equal nonce
    end

    it "updates the nonce for non-HTTPS localhost server" do
      nonce_manager.update(nonce: nonce, server_url: "http://localhost:3000")
      stored_nonce = nonce_manager.instance_variable_get(:@nonces)["http://localhost:3000"]
      _(stored_nonce.value).must_equal nonce
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

    it "returns nil if the nonce has expired" do
      nonce_manager.update(nonce: expired_nonce, server_url: server_url)
      sleep(ttl + 1) # Ensure the nonce expires
      _(nonce_manager.get(server_url)).must_be_nil
    end

    it "returns nil if no nonce exists for the server" do
      _(nonce_manager.get(server_url)).must_be_nil
    end

    it "raises an error if server_url is invalid" do
      assert_raises(AtprotoAuth::DPoP::NonceManager::NonceError) do
        nonce_manager.get("")
      end
    end
  end

  describe "#clear" do
    it "clears the nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      nonce_manager.clear(server_url)
      _(nonce_manager.get(server_url)).must_be_nil
    end
  end

  describe "#clear_all" do
    it "clears all stored nonces" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      nonce_manager.clear_all
      _(nonce_manager.server_urls).must_be_empty
    end
  end

  describe "#server_urls" do
    it "returns all server URLs with stored nonces" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      _(nonce_manager.server_urls).must_equal [server_url]
    end
  end

  describe "#valid_nonce?" do
    it "returns true if the server has a valid nonce" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      _(nonce_manager.valid_nonce?(server_url)).must_equal true
    end

    it "returns false if the nonce has expired" do
      nonce_manager.update(nonce: expired_nonce, server_url: server_url)
      sleep(ttl + 1) # Ensure the nonce expires
      _(nonce_manager.valid_nonce?(server_url)).must_equal false
    end

    it "returns false if no nonce exists for the server" do
      _(nonce_manager.valid_nonce?(server_url)).must_equal false
    end

    it "raises an error if server_url is invalid" do
      assert_raises(AtprotoAuth::DPoP::NonceManager::NonceError) do
        nonce_manager.valid_nonce?("")
      end
    end
  end
end
