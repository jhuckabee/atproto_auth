# frozen_string_literal: true

require "securerandom"
require "base64"
require "openssl"

module AtprotoAuth
  # Handles creation and processing of Pushed Authorization Requests (PAR)
  # according to RFC 9126 and AT Protocol OAuth requirements.
  #
  # PAR is mandatory in AT Protocol OAuth. Before redirecting a user to the
  # authorization endpoint, clients must first submit all authorization parameters
  # via HTTP POST to the PAR endpoint. Only the returned request_uri and client_id
  # are then included in the authorization redirect.
  #
  # @example Basic PAR request
  #   par = AtprotoAuth::PAR::Client.new(endpoint: "https://auth.example.com/par")
  #
  #   request = par.create_request(
  #     client_id: "https://app.example.com/client-metadata.json",
  #     redirect_uri: "https://app.example.com/callback",
  #     code_challenge: "abc123...",
  #     code_challenge_method: "S256",
  #     state: "xyz789...",
  #     scope: "atproto"
  #   )
  #
  #   response = par.submit(request)
  #   auth_url = par.authorization_url(
  #     authorize_endpoint: "https://auth.example.com/authorize",
  #     request_uri: response.request_uri,
  #     client_id: request.client_id
  #   )
  module PAR
    # Error raised for PAR-related issues
    class Error < AtprotoAuth::Error; end

    CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  end
end
