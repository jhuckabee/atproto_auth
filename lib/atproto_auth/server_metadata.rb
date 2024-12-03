# frozen_string_literal: true

module AtprotoAuth
  # Provides functionality for fetching and validating AT Protocol OAuth server metadata
  # from both Resource Servers (PDS instances) and Authorization Servers (PDS/entryway).
  #
  # The flow for resolving an account's authorization server is:
  # 1. Start with PDS URL
  # 2. Fetch Resource Server metadata from /.well-known/oauth-protected-resource
  # 3. Get Authorization Server URL from authorization_servers array
  # 4. Fetch Authorization Server metadata from /.well-known/oauth-authorization-server
  #
  # @example Resolving authorization server from PDS URL
  #   resource_server = AtprotoAuth::ServerMetadata::ResourceServer.from_url("https://pds.example.com")
  #   auth_server_url = resource_server.authorization_servers.first
  #   auth_server = AtprotoAuth::ServerMetadata::AuthorizationServer.from_issuer(auth_server_url)
  #
  # The module includes three main classes:
  # - {ResourceServer} - Handles PDS metadata validation and authorization server discovery
  # - {AuthorizationServer} - Handles authorization server metadata validation
  # - {OriginUrl} - Validates URLs conform to AT Protocol's "simple origin URL" requirements
  module ServerMetadata
  end
end
