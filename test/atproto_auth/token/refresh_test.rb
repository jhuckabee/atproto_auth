# frozen_string_literal: true

require "test_helper"

describe AtprotoAuth::Token::Refresh do
  before do
    AtprotoAuth.configure do |configuration|
      configuration.http_client = AtprotoAuth::HttpClient.new
    end

    client_metadata = AtprotoAuth::ClientMetadata.new(
      "client_id" => "https://example.com/metadata.json",
      "grant_types" => %w[authorization_code refresh_token],
      "response_types" => ["code"],
      "redirect_uris" => ["https://example.com/callback"],
      "scope" => "atproto offline_access",
      "dpop_bound_access_tokens" => true,
      "client_name" => "Example Client",
      "application_type" => "web"
    )

    # Set up a real session
    session = AtprotoAuth::State::Session.new(
      client_id: "mock_client",
      scope: "atproto",
      auth_server: AtprotoAuth::ServerMetadata::AuthorizationServer.new(
        "issuer" => "https://example.com",
        "token_endpoint" => "https://example.com/token",
        "authorization_endpoint" => "https://example.com/auth",
        "response_types_supported" => "code",
        "grant_types_supported" => %w[authorization_code refresh_token],
        "code_challenge_methods_supported" => "S256",
        "token_endpoint_auth_methods_supported" => %w[private_key_jwt none],
        "token_endpoint_auth_signing_alg_values_supported" => %w[ES256],
        "scopes_supported" => %w[atproto],
        "dpop_signing_alg_values_supported" => %w[ES256],
        "pushed_authorization_request_endpoint" => "https://example.com/pushed_auth",
        "authorization_response_iss_parameter_supported" => true,
        "require_pushed_authorization_requests" => true,
        "client_id_metadata_document_supported" => true
      )
    )
    token_set = AtprotoAuth::State::TokenSet.new(
      access_token: "existing_access_token",
      refresh_token: "mock_refresh_token",
      token_type: "DPoP",
      expires_in: 3600,
      scope: "atproto",
      sub: "subject_id"
    )
    session.tokens = token_set

    # Real DPoP client
    @dpop_client = AtprotoAuth::DPoP::Client.new

    # Stub HTTP request
    stub_request(:post, "https://example.com/token").to_return(
      status: 200,
      body: {
        access_token: "new_token",
        token_type: "DPoP",
        expires_in: 3600,
        scope: "atproto",
        sub: "subject_id"
      }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    # Token refresher
    @refresher = AtprotoAuth::Token::Refresh.new(
      client_metadata: client_metadata,
      session: session,
      dpop_client: @dpop_client,
      auth_server: session.auth_server
    )
  end

  it "refreshes the token and returns a new TokenSet" do
    token_set = @refresher.perform!

    assert_instance_of AtprotoAuth::State::TokenSet, token_set
    assert_equal "new_token", token_set.access_token
    assert_equal "atproto", token_set.scope
  end

  it "raises a Token::RefreshError after max retries are reached" do
    # Stub HTTP request to always fail
    stub_request(:post, "https://example.com/token").to_return(
      status: 500, # Internal Server Error
      body: { error: "server_error", error_description: "Something went wrong" }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    error = assert_raises(AtprotoAuth::Token::RefreshError) do
      @refresher.perform!
    end

    assert_match "Token refresh failed after 3 attempts", error.message
  end
end
