# frozen_string_literal: true

require "jose"
require "jwt"

require "atproto_auth/version"

require "atproto_auth/configuration"
require "atproto_auth/errors"
require "atproto_auth/client_metadata"
require "atproto_auth/http_client"
require "atproto_auth/pkce"

require "atproto_auth/server_metadata"
require "atproto_auth/server_metadata/origin_url"
require "atproto_auth/server_metadata/authorization_server"
require "atproto_auth/server_metadata/resource_server"

require "atproto_auth/dpop/key_manager"
require "atproto_auth/dpop/proof_generator"
require "atproto_auth/dpop/nonce_manager"
require "atproto_auth/dpop/client"

require "atproto_auth/state"
require "atproto_auth/state/token_set"
require "atproto_auth/state/session"
require "atproto_auth/state/session_manager"

require "atproto_auth/identity"
require "atproto_auth/identity/document"
require "atproto_auth/identity/resolver"

require "atproto_auth/par"
require "atproto_auth/par/client_assertion"
require "atproto_auth/par/request"
require "atproto_auth/par/response"
require "atproto_auth/par/client"

require "atproto_auth/token/refresh"

require "atproto_auth/client"

# AtprotoAuth is a Ruby library implementing the AT Protocol OAuth specification.
# It provides functionality for both client and server-side implementations of
# the AT Protocol OAuth flow, including support for DPoP, PAR, and dynamic client registration.
module AtprotoAuth
  class << self
    attr_writer :configuration

    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
    end
  end
end
