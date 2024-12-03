# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::ServerMetadata::AuthorizationServer do
  let(:valid_metadata) do
    {
      "issuer" => "https://auth.example.com",
      "authorization_endpoint" => "https://auth.example.com/authorize",
      "token_endpoint" => "https://auth.example.com/token",
      "response_types_supported" => ["code"],
      "grant_types_supported" => %w[authorization_code refresh_token],
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => %w[private_key_jwt none],
      "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
      "scopes_supported" => %w[atproto email profile],
      "dpop_signing_alg_values_supported" => ["ES256"],
      "pushed_authorization_request_endpoint" => "https://auth.example.com/par",
      "authorization_response_iss_parameter_supported" => true,
      "require_pushed_authorization_requests" => true,
      "client_id_metadata_document_supported" => true
    }
  end

  let(:invalid_metadata_missing_field) { valid_metadata.except("issuer") }
  let(:invalid_metadata_bad_url) { valid_metadata.merge("issuer" => "http://auth.example.com") }
  let(:issuer_url) { "https://auth.example.com" }
  let(:mock_response) { { body: valid_metadata.to_json } }

  describe "#initialize" do
    it "initializes successfully with valid metadata" do
      server = AtprotoAuth::ServerMetadata::AuthorizationServer.new(valid_metadata)
      _(server.issuer).must_equal valid_metadata["issuer"]
      _(server.authorization_endpoint).must_equal valid_metadata["authorization_endpoint"]
    end

    it "raises an error if a required field is missing" do
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.new(invalid_metadata_missing_field)
      end
    end

    it "raises an error for an invalid HTTPS URL" do
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.new(invalid_metadata_bad_url)
      end
    end
  end

  describe ".from_issuer" do
    before do
      AtprotoAuth.configuration.stubs(:http_client).returns(mock_http_client = mock)
      mock_http_client.stubs(:get).with("#{issuer_url}/.well-known/oauth-authorization-server").returns(mock_response)
    end

    it "fetches and parses metadata successfully" do
      server = AtprotoAuth::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      _(server.issuer).must_equal valid_metadata["issuer"]
    end

    it "raises an error if fetching metadata fails" do
      AtprotoAuth.configuration.http_client.stubs(:get).raises(AtprotoAuth::HttpClient::HttpError.new("Network error",
                                                                                                      {}))
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      end
    end

    it "raises an error if the metadata JSON is invalid" do
      AtprotoAuth.configuration.http_client.stubs(:get).returns(body: "not-json")
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      end
    end

    it "raises an error if the issuer in metadata does not match the request issuer" do
      invalid_metadata = valid_metadata.merge("issuer" => "https://other.example.com")
      AtprotoAuth.configuration.http_client.stubs(:get).returns(body: invalid_metadata.to_json)

      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      end
    end
  end

  describe "validation methods" do
    it "validates required fields" do
      server = AtprotoAuth::ServerMetadata::AuthorizationServer.new(valid_metadata)
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        server.send(:validate_boolean_field!, valid_metadata, "nonexistent_field", true)
      end
    end

    it "validates response types" do
      invalid_response_types = valid_metadata.merge("response_types_supported" => [])
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.new(invalid_response_types)
      end
    end

    it "validates grant types" do
      invalid_grant_types = valid_metadata.merge("grant_types_supported" => ["authorization_code"])
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.new(invalid_grant_types)
      end
    end

    it "validates token endpoint auth methods" do
      invalid_auth_methods = valid_metadata.merge("token_endpoint_auth_methods_supported" => ["none"])
      assert_raises(AtprotoAuth::InvalidAuthorizationServer) do
        AtprotoAuth::ServerMetadata::AuthorizationServer.new(invalid_auth_methods)
      end
    end
  end
end
