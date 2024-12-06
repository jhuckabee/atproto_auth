# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Serialization::TokenSet do
  let(:token_set) do
    AtprotoAuth::State::TokenSet.new(
      access_token: "test_access_token",
      refresh_token: "test_refresh_token",
      token_type: "DPoP",
      expires_in: 3600,
      scope: "test_scope",
      sub: "test_sub"
    )
  end
  let(:serializer) { AtprotoAuth::Serialization::TokenSet.new }

  it "roundtrips a token set object" do
    serialized = serializer.serialize(token_set)
    deserialized = serializer.deserialize(serialized)

    assert_equal token_set.access_token, deserialized.access_token
    assert_equal token_set.refresh_token, deserialized.refresh_token
    assert_equal token_set.token_type, deserialized.token_type
    assert_equal token_set.scope, deserialized.scope
    assert_equal token_set.sub, deserialized.sub
  end

  it "encrypts sensitive token data" do
    serialized = JSON.parse(serializer.serialize(token_set))

    assert_encrypted serialized.dig("data", "access_token")
    assert_encrypted serialized.dig("data", "refresh_token")
  end

  it "validates object type" do
    assert_raises(AtprotoAuth::Serialization::ValidationError) do
      serializer.serialize(Object.new)
    end
  end
end
