# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::State::Session do
  let(:client_id) { "test_client_id" }
  let(:scope) { "read write" }
  let(:auth_server) { nil }
  let(:did) { "did:example:1234" }
  let(:tokens) do
    AtprotoAuth::State::TokenSet.new(
      access_token: "valid_access_token",
      token_type: "DPoP",
      expires_in: 3600,
      refresh_token: "valid_refresh_token",
      scope: scope,
      sub: did
    )
  end
  let(:session) do
    AtprotoAuth::State::Session.new(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
  end

  describe "#initialize" do
    let(:auth_server) { mock("AuthorizationServer") }

    it "initializes with valid parameters" do
      _(session.session_id).wont_be_nil
      _(session.state_token).wont_be_nil
      _(session.client_id).must_equal client_id
      _(session.scope).must_equal scope
      _(session.auth_server).must_equal auth_server
      _(session.did).must_equal did
      _(session.pkce_verifier).wont_be_nil
      _(session.pkce_challenge).wont_be_nil
      _(session.tokens).must_be_nil
    end

    it "generates unique session_id and state_token" do
      another_session = AtprotoAuth::State::Session.new(client_id: client_id, scope: scope)
      _(session.session_id).wont_equal another_session.session_id
      _(session.state_token).wont_equal another_session.state_token
    end
  end

  describe "#authorization_server=" do
    it "sets the authorization server if not already set" do
      new_server = mock("AuthorizationServer")
      session.authorization_server = new_server
      _(session.auth_server).must_equal new_server
    end

    describe "when an existing authorization server is set" do
      let(:auth_server) { mock("AuthorizationServer", issuer: "https://auth.example.com") }

      it "raises an error if setting a different authorization server" do
        new_server = mock("AuthorizationServer", issuer: "https://auth2.example.com")
        assert_raises(AtprotoAuth::State::SessionError) do
          session.authorization_server = new_server
        end
      end
    end
  end

  describe "#did=" do
    describe "when the DID is not already has a DID" do
      let(:did) { nil }

      it "sets the DID" do
        new_did = "did:example:5678"
        session.did = new_did
        _(session.did).must_equal new_did
      end
    end

    it "raises an error if setting a different DID" do
      new_did = "did:example:5678"
      assert_raises(AtprotoAuth::State::SessionError) do
        session.did = new_did
      end
    end
  end

  describe "#tokens=" do
    it "sets the tokens if they match the session DID" do
      session.tokens = tokens
      _(session.tokens).must_equal tokens
    end

    it "sets the DID if it was not previously set" do
      session_without_did = AtprotoAuth::State::Session.new(client_id: client_id, scope: scope)
      session_without_did.tokens = tokens
      _(session_without_did.did).must_equal tokens.sub
    end

    it "raises an error if the tokens' subject does not match the session DID" do
      mismatched_tokens = AtprotoAuth::State::TokenSet.new(
        access_token: "valid_access_token",
        token_type: "DPoP",
        expires_in: 3600,
        scope: scope,
        sub: "did:example:5678"
      )
      assert_raises(AtprotoAuth::State::SessionError) do
        session.tokens = mismatched_tokens
      end
    end
  end

  describe "#authorized?" do
    it "returns true if tokens are set and not expired" do
      session.tokens = tokens
      _(session.authorized?).must_equal true
    end

    it "returns false if tokens are nil" do
      _(session.authorized?).must_equal false
    end

    it "returns false if tokens are expired" do
      expired_tokens = AtprotoAuth::State::TokenSet.new(
        access_token: "expired_access_token",
        token_type: "DPoP",
        expires_in: 1,
        scope: scope,
        sub: did
      )
      expired_tokens.instance_variable_set(:@expires_at, Time.now - 10)
      session.tokens = expired_tokens
      _(session.authorized?).must_equal false
    end
  end

  describe "#renewable?" do
    it "returns true if tokens are set and renewable" do
      session.tokens = tokens
      _(session.renewable?).must_equal true
    end

    it "returns false if tokens are nil" do
      _(session.renewable?).must_equal false
    end

    it "returns false if tokens are not renewable" do
      non_renewable_tokens = AtprotoAuth::State::TokenSet.new(
        access_token: "valid_access_token",
        token_type: "DPoP",
        expires_in: 3600,
        scope: scope,
        sub: did
      )
      session.tokens = non_renewable_tokens
      _(session.renewable?).must_equal false
    end
  end

  describe "#validate_state" do
    it "returns true for a matching state token" do
      _(session.validate_state(session.state_token)).must_equal true
    end

    it "returns false for a non-matching state token" do
      _(session.validate_state("invalid_state")).must_equal false
    end

    it "returns false for a nil state token" do
      _(session.validate_state(nil)).must_equal false
    end
  end
end
