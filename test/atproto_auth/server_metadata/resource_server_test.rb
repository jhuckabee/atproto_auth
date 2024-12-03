# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::ServerMetadata::ResourceServer do
  let(:valid_metadata) { { "authorization_servers" => ["https://auth.example.com"] } }
  let(:invalid_metadata_missing_servers) { {} }
  let(:invalid_metadata_multiple_servers) { { "authorization_servers" => ["https://auth1.example.com", "https://auth2.example.com"] } }
  let(:invalid_metadata_bad_url) { { "authorization_servers" => ["http://auth.example.com"] } }
  let(:valid_url) { "https://example.com" }
  let(:mock_response) { { body: valid_metadata.to_json } }

  describe "#initialize" do
    it "initializes successfully with valid metadata" do
      server = AtprotoAuth::ServerMetadata::ResourceServer.new(valid_metadata)
      _(server.authorization_servers).must_equal valid_metadata["authorization_servers"]
    end

    it "raises an error if authorization_servers is missing" do
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::ResourceServer.new(invalid_metadata_missing_servers)
      end
    end

    it "raises an error if there are multiple authorization_servers" do
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::ResourceServer.new(invalid_metadata_multiple_servers)
      end
    end

    it "raises an error for invalid authorization server URL format" do
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::ResourceServer.new(invalid_metadata_bad_url)
      end
    end
  end

  describe ".from_url" do
    before do
      AtprotoAuth.configuration.stubs(:http_client).returns(mock_http_client = mock)
      mock_http_client.stubs(:get).with("#{valid_url}/.well-known/oauth-protected-resource").returns(mock_response)
    end

    it "fetches and parses metadata successfully" do
      server = AtprotoAuth::ServerMetadata::ResourceServer.from_url(valid_url)
      _(server.authorization_servers).must_equal valid_metadata["authorization_servers"]
    end

    it "raises an error if fetching metadata fails" do
      AtprotoAuth.configuration.http_client.stubs(:get).raises(AtprotoAuth::HttpClient::HttpError.new("Network error",
                                                                                                      {}))
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::ResourceServer.from_url(valid_url)
      end
    end

    it "raises an error if the metadata JSON is invalid" do
      AtprotoAuth.configuration.http_client.stubs(:get).returns(body: "not-json")
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::ResourceServer.from_url(valid_url)
      end
    end
  end
end
