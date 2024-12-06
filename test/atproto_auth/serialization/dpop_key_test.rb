# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Serialization::DPoPKey do
  let(:key_manager) { AtprotoAuth::DPoP::KeyManager.new }
  let(:serializer) { AtprotoAuth::Serialization::DPoPKey.new }

  it "roundtrips a DPoP key manager object" do
    serialized = serializer.serialize(key_manager)
    deserialized = serializer.deserialize(serialized)

    # Compare public key components
    original_jwk = key_manager.public_jwk
    deserialized_jwk = deserialized.public_jwk

    assert_equal original_jwk["kty"], deserialized_jwk["kty"]
    assert_equal original_jwk["crv"], deserialized_jwk["crv"]
    assert_equal original_jwk["x"], deserialized_jwk["x"]
    assert_equal original_jwk["y"], deserialized_jwk["y"]
  end

  it "encrypts private key material" do
    serialized = JSON.parse(serializer.serialize(key_manager))
    jwk = serialized["data"]

    assert_encrypted jwk["d"] if jwk["d"] # Private key component
  end

  it "validates object type" do
    assert_raises(AtprotoAuth::Serialization::ValidationError) do
      serializer.serialize(Object.new)
    end
  end
end
