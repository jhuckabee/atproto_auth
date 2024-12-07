# frozen_string_literal: true

require "sinatra/base"
require "sinatra/reloader"
require "atproto_auth"
require "faraday"
require "json"
require "dotenv/load"

# Main app entry point
class ExampleApp < Sinatra::Base
  def check_stored_session(session_id)
    return false unless session_id

    settings.oauth_client.authorized?(session_id)
  rescue AtprotoAuth::SessionError
    false
  end

  configure :development do
    register Sinatra::Reloader
  end

  # Initialize the AT Protocol OAuth client
  configure do
    # Configure AtprotoAuth settings
    AtprotoAuth.configure do |config|
      config.http_client = AtprotoAuth::HttpClient.new(
        timeout: 10,
        verify_ssl: true
      )
      config.default_token_lifetime = 300
      config.dpop_nonce_lifetime = 300

      # Optionally, use Redis storage instead of in-memory
      # config.storage = AtprotoAuth::Storage::Redis.new
    end

    # Load client metadata
    metadata_path = File.join(__dir__, "config", "client-metadata.json")
    metadata = JSON.parse(File.read(metadata_path))

    # Create OAuth client
    set :oauth_client, AtprotoAuth::Client.new(
      client_id: metadata["client_id"],
      redirect_uri: metadata["redirect_uris"][0],
      metadata: metadata,
      dpop_key: metadata["jwks"]["keys"][0]
    )
  end

  set :host_authorization, {
    permitted_hosts: ["localhost", ENV.fetch("PERMITTED_DOMAIN", nil)].compact
  }

  use Rack::Session::Cookie,
      key: "atproto.session",
      expire_after: 86_400, # 1 day in seconds
      secret: ENV.fetch("SESSION_SECRET") { SecureRandom.hex(32) },
      secure: true,       # Only send over HTTPS
      httponly: true,     # Not accessible via JavaScript
      same_site: :lax     # CSRF protection

  helpers do
    def recover_session
      session_id = session[:oauth_session_id]
      return nil unless session_id

      begin
        # Check if session is still valid
        return nil unless settings.oauth_client.authorized?(session_id)

        session_id
      rescue AtprotoAuth::Client::SessionError
        # Clear invalid session
        session.delete(:oauth_session_id)
        nil
      end
    end
  end

  get "/" do
    # Check for existing session
    redirect "/authorized" if recover_session

    erb :index
  end

  get "/client-metadata.json" do
    content_type :json

    # Read metadata from config file
    metadata_path = File.join(__dir__, "config", "client-metadata.json")
    metadata = JSON.parse(File.read(metadata_path))

    # Strip private key 'd' component from each key in the JWKS
    if metadata["jwks"] && metadata["jwks"]["keys"]
      metadata["jwks"]["keys"] = metadata["jwks"]["keys"].map do |key|
        key.except("d")
      end
    end

    # Return sanitized metadata
    JSON.generate(metadata)
  end

  # Start OAuth flow
  post "/auth" do
    handle = params[:handle]

    begin
      # Start authorization flow
      auth = settings.oauth_client.authorize(
        handle: handle,
        scope: "atproto"
      )

      # Store session ID in user's browser session
      session[:oauth_session_id] = auth[:session_id]

      # Redirect to authorization URL
      redirect auth[:url]
    rescue StandardError => e
      session[:error] = "Authorization failed: #{e.message}"
      redirect "/"
    end
  end

  # OAuth callback handler
  get "/callback" do
    # Handle the callback
    result = settings.oauth_client.handle_callback(
      code: params[:code],
      state: params[:state],
      iss: params[:iss]
    )

    # Store tokens
    session[:oauth_session_id] = result[:session_id]

    redirect "/authorized"
  rescue StandardError => e
    session[:error] = "Callback failed: #{e.message}"
    redirect "/"
  end

  # Show authorized state and test API call
  get "/authorized" do
    session_id = session[:oauth_session_id]
    return redirect "/" unless check_stored_session(session_id)

    begin
      # Get current session tokens
      oauth_session = settings.oauth_client.get_tokens(session_id)

      # Check if token needs refresh
      if oauth_session[:expires_in] < 30
        # Refresh token
        oauth_session = settings.oauth_client.refresh_token(session_id)
      end

      # Make test API call to com.atproto.identity.resolveHandle
      conn = Faraday.new(url: "https://api.bsky.app") do |f|
        f.request :json
        f.response :json
      end

      # Get auth headers for request
      headers = settings.oauth_client.auth_headers(
        session_id: session_id,
        method: "GET",
        url: "https://api.bsky.app/xrpc/com.atproto.identity.resolveHandle"
      )

      # Make authenticated request
      response = conn.get("/xrpc/com.atproto.identity.resolveHandle") do |req|
        headers.each { |k, v| req.headers[k] = v }
        req.params[:handle] = "bsky.app"
      end

      @api_result = response.body
      @session = oauth_session
      erb :authorized
    rescue StandardError => e
      session[:error] = "API call failed: #{e.message}"
      redirect "/"
    end
  end

  get "/signout" do
    if session[:oauth_session_id]
      # Clean up stored session
      settings.oauth_client.remove_session(session[:oauth_session_id])
    end

    session.clear
    session[:notice] = "Successfully signed out"
    redirect "/"
  end

  # Helper method to check if user is authenticated
  def authenticated?
    return false unless session[:tokens]

    settings.oauth_client.authorized?(session[:tokens][:session_id])
  end
end
