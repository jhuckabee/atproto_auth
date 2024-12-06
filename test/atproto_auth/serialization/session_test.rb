# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Serialization::Session do
  let(:client_id) { "test_client" }
  let(:scope) { "test_scope" }
  let(:session) do
    AtprotoAuth::State::Session.new(
      client_id: client_id,
      scope: scope
    )
  end
  let(:serializer) { AtprotoAuth::Serialization::Session.new }

  it "roundtrips a session object" do
    serialized = serializer.serialize(session)
    deserialized = serializer.deserialize(serialized)

    assert_equal session.session_id, deserialized.session_id
    assert_equal session.state_token, deserialized.state_token
    assert_equal session.client_id, deserialized.client_id
    assert_equal session.scope, deserialized.scope
    assert_equal session.pkce_verifier, deserialized.pkce_verifier
    assert_equal session.pkce_challenge, deserialized.pkce_challenge
  end

  it "encrypts sensitive session data" do
    serialized = JSON.parse(serializer.serialize(session))

    assert_encrypted serialized.dig("data", "pkce_verifier")
    assert_encrypted serialized.dig("data", "tokens", "access_token") if session.tokens
  end

  it "validates object type" do
    assert_raises(AtprotoAuth::Serialization::ValidationError) do
      serializer.serialize(Object.new)
    end
  end
end
