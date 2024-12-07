# AT Protocol OAuth Confidential Client Example

This is an example implementation of a confidential OAuth client for the AT Protocol using the AtprotoAuth gem. It demonstrates how to implement the OAuth flow for a web application, including DPoP token binding and secure session management.

<img src="https://github.com/jhuckabee/atproto_auth/blob/main/examples/confidential_client/screenshots/screenshot-1-sign-in.png?raw=true" alt="Sign In Form Screenshot" title="Sign In Form" width="500">

<img src="https://github.com/jhuckabee/atproto_auth/blob/main/examples/confidential_client/screenshots/screenshot-2-success.png?raw=true" alt="Sign In Success Screenshot" title="Sign In Success" width="500">

## Overview

The example implements a simple web application using Sinatra that:
- Allows users to sign in with their AT Protocol handle (@handle)
- Implements the complete OAuth authorization flow
- Uses DPoP-bound tokens for API requests
- Demonstrates secure session management with encryption
- Shows how to make authenticated API calls to Bluesky
- Provides examples of both development and production storage configurations

## Requirements

- Ruby 3.0+
- Bundler
- A domain name for your application that matches your client metadata
- SSL certificate for your domain (required for production)
- Redis (optional, recommended for production)

## Setup

1. Clone the repository and navigate to the example directory:
```bash
cd examples/confidential_client
```

2. Install dependencies:
```bash
bundle install
```

3. Generate EC keys for client authentication:
```bash
bundle exec ruby scripts/generate_keys.rb > config/keys.json
```

4. Configure your client metadata:
   - Copy the example metadata file over:
     ```
     cp config/client-metadata.example.json config/client-metadata.json
     ```
   - Set the correct `client_id` URL where your metadata will be hosted
   - Configure valid `redirect_uris` for your application
   - Add your generated keys from step 3 to the `jwks` field

5. Set up environment variables:
```bash
# Required for session encryption
export SESSION_SECRET=your-secure-session-secret 

# Your application's domain name
export PERMITTED_DOMAIN=your.domain.com 

# Optional: Redis URL for production storage
export REDIS_URL=redis://localhost:6379
```

## Configuration

### Storage Configuration

The example app supports both in-memory and Redis storage backends:

#### Development (In-Memory Storage)
```ruby
# config/development.rb
AtprotoAuth.configure do |config|
  config.storage = AtprotoAuth::Storage::Memory.new
  config.logger = Logger.new($stdout)
end
```

#### Production (Redis Storage)
```ruby
# config/production.rb
require 'redis'

AtprotoAuth.configure do |config|
  redis_client = Redis.new(
    url: ENV.fetch('REDIS_URL'),
    ssl_params: { verify_mode: OpenSSL::SSL::VERIFY_PEER }
  )
  
  config.storage = AtprotoAuth::Storage::Redis.new(
    redis_client: redis_client
  )
  
  config.logger = Logger.new($stdout)
end
```

### Host Authorization

This application requires specific domain configuration to function properly:

1. **Domain-Client Matching**: The domain where you run the application must exactly match the `client_id` domain in your client metadata. For example, if your `client_id` is `https://myapp.example.com/client-metadata.json`, the application must be accessible at `myapp.example.com`.

2. **Internet Accessibility**: The application must be accessible from the internet for AT Protocol OAuth to work. The Authorization Server needs to be able to reach your application's redirect URI during the OAuth flow.

3. **Quick Setup with Tailscale Funnel**: One easy way to expose your local development server to the internet is using Tailscale Funnel:

   1. Set up [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)
   2. Ensure you have HTTPS certificates configured
   5. Start your Funnel:
      ```bash
      tailscale funnel 9292
      ```
   4. Ensure your client_id and redirect_uris match your funnel path
   5. Set the `PERMITTED_DOMAIN` environment variable to your Tailscale domain
      ```bash
      export PERMITTED_DOMAIN=machinename.xyz.ts.net
      ```
   6. Run the application (see below)

Your application will now be accessible via your Tailscale domain with HTTPS enabled.

### Session Security

The application uses encrypted sessions to store authorization data. Configure the session secret with:

```bash
export SESSION_SECRET=your-secure-random-string
```

If not set, a random secret will be generated on startup (not recommended for production).

## Running the Application

### Development
```bash
RACK_ENV=development bundle exec rackup
```

### Production
```bash
RACK_ENV=production bundle exec rackup -E production
```

This will start the server on `http://localhost:9292`.

## Troubleshooting

### Common Issues

1. "Invalid redirect URI":
   - Ensure your redirect URI matches exactly what's in your client metadata
   - Check that your domain matches the client_id domain

2. "Invalid client metadata":
   - Verify your client metadata is accessible at the URL specified in client_id
   - Check that your JSON is valid and contains all required fields

3. "Authorization failed":
   - Verify your JWKS configuration
   - Check that your DPoP proofs are being generated correctly
   - Ensure your client authentication is working

4. "Storage errors":
   - For Redis storage, verify Redis connection settings
   - Check Redis SSL configuration if using encrypted connections
   - Ensure proper Redis authentication credentials if required

5. "Session state lost":
   - Verify storage configuration is correct
   - Check Redis connection stability if using Redis storage
   - Ensure session TTLs are appropriately configured

## Understanding the Code

The example demonstrates several important concepts:

1. **Secure Storage**: The app shows proper configuration of both development (in-memory) and production (Redis) storage backends.

2. **Token Management**: All tokens are stored securely with encryption in the configured storage backend.

3. **Session Handling**: The app demonstrates proper session state management with atomic operations and locking.

4. **Error Recovery**: Includes examples of handling storage failures and token refresh scenarios.

The code is thoroughly commented to explain these concepts and their implementation details.
