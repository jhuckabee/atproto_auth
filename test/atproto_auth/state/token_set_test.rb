# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::State::TokenSet do
  let(:access_token) { "valid_access_token" }
  let(:refresh_token) { "valid_refresh_token" }
  let(:token_type) { "DPoP" }
  let(:expires_in) { 3600 }
  let(:scope) { "read write" }
  let(:sub) { "did:example:1234" }
  let(:token_set) do
    AtprotoAuth::State::TokenSet.new(
      access_token: access_token,
      token_type: token_type,
      expires_in: expires_in,
      refresh_token: refresh_token,
      scope: scope,
      sub: sub
    )
  end

  describe "#initialize" do
    it "initializes with valid parameters" do
      _(token_set.access_token).must_equal access_token
      _(token_set.refresh_token).must_equal refresh_token
      _(token_set.token_type).must_equal token_type
      _(token_set.scope).must_equal scope
      _(token_set.sub).must_equal sub
      _(token_set.expires_at).must_be_instance_of Time
      _(token_set.expires_at).must_be :>, Time.now
    end

    it "raises an error if token_type is not 'DPoP'" do
      assert_raises(ArgumentError, "token_type must be DPoP") do
        AtprotoAuth::State::TokenSet.new(
          access_token: access_token,
          token_type: "Bearer",
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: scope,
          sub: sub
        )
      end
    end

    it "raises an error if required parameters are missing" do
      assert_raises(ArgumentError, "access_token is required") do
        AtprotoAuth::State::TokenSet.new(
          access_token: nil,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: scope,
          sub: sub
        )
      end

      assert_raises(ArgumentError, "scope is required") do
        AtprotoAuth::State::TokenSet.new(
          access_token: access_token,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: nil,
          sub: sub
        )
      end

      assert_raises(ArgumentError, "sub is required") do
        AtprotoAuth::State::TokenSet.new(
          access_token: access_token,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: scope,
          sub: nil
        )
      end
    end

    it "raises an error if expires_in is not a positive integer" do
      assert_raises(ArgumentError, "expires_in must be positive integer") do
        AtprotoAuth::State::TokenSet.new(
          access_token: access_token,
          token_type: token_type,
          expires_in: -1,
          refresh_token: refresh_token,
          scope: scope,
          sub: sub
        )
      end
    end
  end

  describe "#renewable?" do
    it "returns true if refresh_token is present" do
      _(token_set.renewable?).must_equal true
    end

    it "returns false if refresh_token is nil" do
      token_set_without_refresh = AtprotoAuth::State::TokenSet.new(
        access_token: access_token,
        token_type: token_type,
        expires_in: expires_in,
        scope: scope,
        sub: sub
      )
      _(token_set_without_refresh.renewable?).must_equal false
    end
  end

  describe "#expired?" do
    it "returns false if token has not expired" do
      _(token_set.expired?).must_equal false
    end

    it "returns true if token has expired" do
      expired_token_set = AtprotoAuth::State::TokenSet.new(
        access_token: access_token,
        token_type: token_type,
        expires_in: 1,
        refresh_token: refresh_token,
        scope: scope,
        sub: sub
      )
      # Force the token to appear expired
      expired_token_set.instance_variable_set(:@expires_at, Time.now - 10)
      _(expired_token_set.expired?).must_equal true
    end

    it "respects the buffer parameter for expiration check" do
      token_set_with_buffer = AtprotoAuth::State::TokenSet.new(
        access_token: access_token,
        token_type: token_type,
        expires_in: 10,
        refresh_token: refresh_token,
        scope: scope,
        sub: sub
      )
      _(token_set_with_buffer.expired?(15)).must_equal true
    end
  end
end
