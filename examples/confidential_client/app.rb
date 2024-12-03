# frozen_string_literal: true

require "sinatra/base"
require "sinatra/reloader"
require "atproto_auth"
require "faraday"
require "json"
require "dotenv/load"

# Main app entry point
class ExampleApp < Sinatra::Base
  configure :development do
    register Sinatra::Reloader
  end

  set :host_authorization, {
    permitted_hosts: ["localhost", ENV.fetch("PERMITTED_DOMAIN", nil)].compact
  }

  enable :sessions
  set :session_secret, ENV.fetch("SESSION_SECRET") { SecureRandom.hex(32) }

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

  get "/" do
    erb :index
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

      # Store session ID for callback
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

    # Store tokens in session
    session[:tokens] = result

    redirect "/authorized"
  rescue StandardError => e
    session[:error] = "Callback failed: #{e.message}"
    redirect "/"
  end

  # Show authorized state and test API call
  get "/authorized" do
    return redirect "/" unless session[:tokens]

    begin
      # Make test API call to com.atproto.identity.resolveHandle
      conn = Faraday.new(url: "https://api.bsky.app") do |f|
        f.request :json
        f.response :json
      end

      # Get auth headers for request
      headers = settings.oauth_client.auth_headers(
        session_id: session[:tokens][:session_id],
        method: "GET",
        url: "https://api.bsky.app/xrpc/com.atproto.identity.resolveHandle"
      )

      # Make authenticated request
      response = conn.get("/xrpc/com.atproto.identity.resolveHandle") do |req|
        headers.each { |k, v| req.headers[k] = v }
        req.params[:handle] = "bsky.app"
      end

      @api_result = response.body
      erb :authorized
    rescue StandardError => e
      session[:error] = "API call failed: #{e.message}"
      redirect "/"
    end
  end

  get "/signout" do
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
