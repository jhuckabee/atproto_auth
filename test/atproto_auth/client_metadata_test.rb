# frozen_string_literal: true

require_relative "../test_helper"

describe AtprotoAuth::ClientMetadata do
  before do
    @valid_metadata = {
      "client_id" => "https://example.com/metadata.json",
      "grant_types" => %w[authorization_code refresh_token],
      "response_types" => ["code"],
      "redirect_uris" => ["https://example.com/callback"],
      "scope" => "atproto offline_access",
      "dpop_bound_access_tokens" => true,
      "client_name" => "Example Client",
      "application_type" => "web"
    }
  end

  describe "initialization" do
    it "initializes with valid metadata" do
      client_metadata = AtprotoAuth::ClientMetadata.new(@valid_metadata)
      _(client_metadata.client_id).must_equal "https://example.com/metadata.json"
      _(client_metadata.grant_types).must_equal %w[authorization_code refresh_token]
      _(client_metadata.response_types).must_equal ["code"]
      _(client_metadata.redirect_uris).must_equal ["https://example.com/callback"]
      _(client_metadata.scope).must_equal "atproto offline_access"
      _(client_metadata.client_name).must_equal "Example Client"
      _(client_metadata.application_type).must_equal "web"
    end

    it "initializes with localhost client_id" do
      @valid_metadata["client_id"] = "http://localhost"
      @valid_metadata["redirect_uris"] = ["http://127.0.0.1:9292/callback"]
      client_metadata = AtprotoAuth::ClientMetadata.new(@valid_metadata)
      _(client_metadata.client_id).must_equal "http://localhost"
    end

    it "raises an error when client_id is missing" do
      @valid_metadata.delete("client_id")
      _(-> { AtprotoAuth::ClientMetadata.new(@valid_metadata) }).must_raise AtprotoAuth::InvalidClientMetadata
    end

    it "raises an error for invalid client_id scheme" do
      @valid_metadata["client_id"] = "http://example.com"
      _(-> { AtprotoAuth::ClientMetadata.new(@valid_metadata) }).must_raise AtprotoAuth::InvalidClientMetadata
    end

    it "raises an error for invalid grant types" do
      @valid_metadata["grant_types"] = ["invalid_grant"]
      _(-> { AtprotoAuth::ClientMetadata.new(@valid_metadata) }).must_raise AtprotoAuth::InvalidClientMetadata
    end

    it "raises an error when redirect URIs are missing" do
      @valid_metadata.delete("redirect_uris")
      _(-> { AtprotoAuth::ClientMetadata.new(@valid_metadata) }).must_raise AtprotoAuth::InvalidClientMetadata
    end

    it "raises an error for invalid redirect URI scheme" do
      @valid_metadata["redirect_uris"] = ["http://example.com/callback"]
      _(-> { AtprotoAuth::ClientMetadata.new(@valid_metadata) }).must_raise AtprotoAuth::InvalidClientMetadata
    end

    it "raises an error for invalid scope" do
      @valid_metadata["scope"] = "invalid_scope"
      _(-> { AtprotoAuth::ClientMetadata.new(@valid_metadata) }).must_raise AtprotoAuth::InvalidClientMetadata
    end

    it "raises an error for missing dpop_bound_access_tokens" do
      @valid_metadata.delete("dpop_bound_access_tokens")
      _(-> { AtprotoAuth::ClientMetadata.new(@valid_metadata) }).must_raise AtprotoAuth::InvalidClientMetadata
    end
  end

  describe ".from_url" do
    it "creates an instance from valid URL metadata" do
      AtprotoAuth::ClientMetadata.stubs(:fetch_metadata).returns({ body: @valid_metadata.to_json })
      client_metadata = AtprotoAuth::ClientMetadata.from_url("https://example.com/metadata.json")
      _(client_metadata).must_be_instance_of AtprotoAuth::ClientMetadata
      _(client_metadata.client_id).must_equal "https://example.com/metadata.json"
    end

    it "raises an error for invalid URL scheme" do
      _(lambda {
        AtprotoAuth::ClientMetadata.from_url("http://example.com/metadata")
      }).must_raise AtprotoAuth::InvalidClientMetadata
    end

    it "raises an error for client_id mismatch in metadata" do
      AtprotoAuth::ClientMetadata.stubs(:fetch_metadata).returns({ body: @valid_metadata.to_json })
      @valid_metadata["client_id"] = "https://otherexample.com"
      _(lambda {
        AtprotoAuth::ClientMetadata.from_url("https://example.com/metadata")
      }).must_raise AtprotoAuth::InvalidClientMetadata
    end
  end

  describe "#confidential?" do
    it "returns true for confidential clients using private_key_jwt" do
      @valid_metadata["token_endpoint_auth_method"] = "private_key_jwt"
      @valid_metadata["token_endpoint_auth_signing_alg"] = "ES256"
      @valid_metadata["jwks"] = { "keys" => [] }
      client_metadata = AtprotoAuth::ClientMetadata.new(@valid_metadata)
      _(client_metadata.confidential?).must_equal true
    end

    it "returns false for non-confidential clients" do
      client_metadata = AtprotoAuth::ClientMetadata.new(@valid_metadata)
      _(client_metadata.confidential?).must_equal false
    end
  end
end
