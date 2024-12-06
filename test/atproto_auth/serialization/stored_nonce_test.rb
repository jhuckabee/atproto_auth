# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Serialization::StoredNonce do
  let(:stored_nonce) do
    AtprotoAuth::DPoP::NonceManager::StoredNonce.new(
      "test_nonce",
      "https://example.com"
    )
  end
  let(:serializer) { AtprotoAuth::Serialization::StoredNonce.new }

  it "roundtrips a stored nonce object" do
    serialized = serializer.serialize(stored_nonce)
    deserialized = serializer.deserialize(serialized)

    assert_equal stored_nonce.value, deserialized.value
    assert_equal stored_nonce.server_url, deserialized.server_url
    assert_equal stored_nonce.timestamp.to_i, deserialized.timestamp.to_i
  end

  it "validates object type" do
    assert_raises(AtprotoAuth::Serialization::ValidationError) do
      serializer.serialize(Object.new)
    end
  end
end
