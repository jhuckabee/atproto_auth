# frozen_string_literal: true

module AtprotoAuth
  # Manages OAuth state for AT Protocol authorization flows. This module provides thread-safe
  # storage and management of authorization session data, including tokens, PKCE values,
  # and identity information.
  #
  # The module consists of three main components:
  #
  # 1. {TokenSet} - Represents OAuth tokens (access and refresh) with their metadata,
  #    including expiration times, scope, and the authenticated user's DID.
  #
  # 2. {Session} - Tracks the complete state of an authorization flow, including:
  #    - PKCE verifier/challenge pairs
  #    - State tokens for request verification
  #    - Authorization server information
  #    - Current tokens and user identity (DID)
  #
  # 3. {SessionManager} - Provides thread-safe storage and retrieval of active sessions,
  #    with support for lookup by session ID or state token.
  #
  # @example Creating and managing a session
  #   manager = AtprotoAuth::State::SessionManager.new
  #
  #   # Create a new session
  #   session = manager.create_session(
  #     client_id: "https://myapp.com/client-metadata.json",
  #     scope: "atproto"
  #   )
  #
  #   # Update session with tokens
  #   tokens = TokenSet.new(
  #     access_token: "...",
  #     token_type: "DPoP",
  #     expires_in: 3600,
  #     scope: "atproto",
  #     sub: "did:plc:abcdef123"
  #   )
  #   session.tokens = tokens
  #
  #   # Lookup session later
  #   session = manager.get_session(session_id)
  #   if session.authorized?
  #     puts "Access token: #{session.tokens.access_token}"
  #   end
  #
  # All classes in this module are thread-safe and can be used in concurrent environments.
  # The module handles secure generation and validation of state tokens, and ensures
  # consistency of session data through synchronized access.
  module State
    # Error raised for session-related issues
    class SessionError < AtprotoAuth::Error; end
  end
end
