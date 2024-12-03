# AtprotoAuth

[![Gem Version](https://badge.fury.io/rb/atproto_auth.svg)](https://badge.fury.io/rb/atproto_auth)
[![Ruby Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://github.com/testdouble/standard)
[![Documentation](https://img.shields.io/badge/docs-rdoc-blue.svg)](https://www.rubydoc.info/gems/atproto_auth)

A Ruby implementation of the [AT Protocol OAuth specification](https://docs.bsky.app/docs/advanced-guides/oauth-client). This library provides comprehensive support for both client and server-side implementations, with built-in security features including DPoP (Demonstrating Proof of Possession), PAR (Pushed Authorization Requests), and dynamic client registration.

## Features

- Complete AT Protocol OAuth 2.0 implementation
- Secure by default with mandatory DPoP and PKCE
- Support for confidential (backend) and public clients
- Thread-safe session and token management
- Comprehensive identity resolution and verification
- Automatic token refresh and session management
- Robust error handling and recovery mechanisms

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'atproto_auth'
```

And then execute:

```sh
bundle install
```

Or install it yourself as:

```sh
gem install atproto_auth
```

## Requirements

- Ruby 3.0 or higher
- OpenSSL support
- For confidential clients: HTTPS-capable domain for client metadata hosting

## Basic Usage

### Configuration

```ruby
require 'atproto_auth'

AtprotoAuth.configure do |config|
  # Configure HTTP client settings
  config.http_client = AtprotoAuth::HttpClient.new(
    timeout: 10,
    verify_ssl: true
  )

  # Set token lifetimes
  config.default_token_lifetime = 300 # 5 minutes
  config.dpop_nonce_lifetime = 300  # 5 minutes
end
```

### Confidential Client Example

Here's a basic example of using the library in a confidential client application:

```ruby
# Initialize client with metadata
client = AtprotoAuth::Client.new(
  client_id: "https://app.example.com/client-metadata.json",
  redirect_uri: "https://app.example.com/callback",
  metadata: {
    # Your client metadata...
  }
)

# Start authorization flow
auth = client.authorize(
  handle: "user.bsky.social",
  scope: "atproto"
)

# Use auth[:url] to redirect user

# Handle callback
tokens = client.handle_callback(
  code: params[:code],
  state: params[:state],
  iss: params[:iss]
)

# Make authenticated requests
headers = client.auth_headers(
  session_id: tokens[:session_id],
  method: "GET",
  url: "https://api.example.com/resource"
)
```

For a complete working example of a confidential client implementation, check out the example application in `examples/confidential_client/`. This Sinatra-based web application demonstrates:
- Complete OAuth flow implementation
- Session management
- DPoP token binding
- Making authenticated API requests
- Proper error handling
- Key generation and management

See `examples/confidential_client/README.md` for setup instructions and implementation details.

### Public Client Example

```ruby
client = AtprotoAuth::Client.new(
  client_id: "https://app.example.com/client-metadata.json",
  redirect_uri: "https://app.example.com/callback"
)

# Browser will open authorization URL
auth = client.authorize(
  handle: "user.bsky.social",
  scope: "atproto"
)

# After callback, exchange code for tokens
tokens = client.handle_callback(
  code: params[:code],
  state: params[:state],
  iss: params[:iss]
)
```

## Features In Detail

### Identity Resolution

The library handles the complete AT Protocol identity resolution flow:

- Handle to DID resolution (DNS-based or HTTP fallback)
- DID document fetching and validation
- PDS (Personal Data Server) location verification
- Bidirectional handle verification
- Authorization server binding verification

### Token & Session Management

Comprehensive token lifecycle management:

- Secure token storage with encryption
- Automatic token refresh
- DPoP proof generation and binding
- Session state tracking
- Cleanup of expired sessions

### Security Features

Built-in security best practices:

- Mandatory PKCE for all flows
- DPoP token binding
- Constant-time token comparisons
- Thread-safe state management
- Protection against SSRF attacks
- Secure token storage

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jhuckabee/atproto_auth.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
