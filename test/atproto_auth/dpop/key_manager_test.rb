# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::DPoP::KeyManager do
  let(:valid_keypair) { JOSE::JWK.generate_key([:ec, "P-256"]) }
  let(:invalid_keypair) { JOSE::JWK.generate_key([:rsa, 2048]) }

  describe "#initialize" do
    it "creates a KeyManager with a valid EC keypair" do
      manager = AtprotoAuth::DPoP::KeyManager.new(valid_keypair)
      assert_equal valid_keypair, manager.keypair
    end

    it "raises an error when initialized with an invalid keypair" do
      assert_raises(AtprotoAuth::DPoP::KeyManager::KeyError) do
        AtprotoAuth::DPoP::KeyManager.new(invalid_keypair)
      end
    end

    it "generates a new keypair if none is provided" do
      manager = AtprotoAuth::DPoP::KeyManager.new
      keypair = manager.keypair
      assert_equal "EC", keypair.to_map["kty"]
      assert_equal "P-256", keypair.to_map["crv"]
    end
  end

  describe "#generate_keypair" do
    it "generates a valid ES256 keypair" do
      manager = AtprotoAuth::DPoP::KeyManager.new
      keypair = manager.generate_keypair
      assert_equal "EC", keypair.to_map["kty"]
      assert_equal "P-256", keypair.to_map["crv"]
    end
  end

  describe "#public_jwk" do
    it "returns the public key in JWK format" do
      manager = AtprotoAuth::DPoP::KeyManager.new(valid_keypair)
      public_jwk = manager.public_jwk
      assert_equal "EC", public_jwk["kty"]
      assert_equal "P-256", public_jwk["crv"]
    end
  end

  describe "#sign" do
    it "signs data using the private key" do
      manager = AtprotoAuth::DPoP::KeyManager.new(valid_keypair)
      data = "test_data"
      signature = manager.sign(data)
      assert_instance_of JOSE::SignedBinary, signature
    end
  end

  describe "#verify" do
    it "verifies a signed JWS" do
      manager = AtprotoAuth::DPoP::KeyManager.new(valid_keypair)
      data = "test_data"
      signature = manager.sign(data)
      assert manager.verify(signature)
    end

    it "raises an error if verification fails" do
      manager = AtprotoAuth::DPoP::KeyManager.new(valid_keypair)
      invalid_signature = "invalid_signature"
      assert_raises(AtprotoAuth::DPoP::KeyManager::KeyError) do
        manager.verify(invalid_signature)
      end
    end
  end

  describe "#to_jwk" do
    it "exports the keypair in JWK format including private key" do
      manager = AtprotoAuth::DPoP::KeyManager.new(valid_keypair)
      jwk = manager.to_jwk(include_private: true)
      assert_equal "EC", jwk["kty"]
      assert_equal "P-256", jwk["crv"]
      assert jwk.key?("d")
    end

    it "exports the public key only when include_private is false" do
      manager = AtprotoAuth::DPoP::KeyManager.new(valid_keypair)
      jwk = manager.to_jwk(include_private: false)
      assert_equal "EC", jwk["kty"]
      assert_equal "P-256", jwk["crv"]
      refute jwk.key?("d")
    end
  end

  describe ".from_jwk" do
    it "creates a KeyManager instance from a JWK" do
      manager = AtprotoAuth::DPoP::KeyManager.from_jwk(valid_keypair.to_map)
      assert_instance_of AtprotoAuth::DPoP::KeyManager, manager
    end

    it "raises an error if importing the JWK fails" do
      invalid_jwk = { "kty" => "RSA", "n" => "mocked_n", "e" => "mocked_e" }
      assert_raises(AtprotoAuth::DPoP::KeyManager::KeyError) do
        AtprotoAuth::DPoP::KeyManager.from_jwk(invalid_jwk)
      end
    end
  end
end
