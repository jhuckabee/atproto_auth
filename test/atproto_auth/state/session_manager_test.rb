# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::State::SessionManager do
  let(:client_id) { "test_client_id" }
  let(:scope) { "read write" }
  let(:auth_server) do
    AtprotoAuth::ServerMetadata::AuthorizationServer.new(
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
  end
  let(:did) { "did:example:1234" }
  let(:session_manager) { AtprotoAuth::State::SessionManager.new }
  let(:storage) { AtprotoAuth::Storage::Memory.new }

  before do
    AtprotoAuth.stubs(:storage).returns(storage)
    auth_server.stubs(:as_json).returns({ some: value })
  end

  describe "#create_session" do
    it "creates and stores a new session" do
      session = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)

      # Verify session was stored
      session_key = AtprotoAuth::Storage::KeyBuilder.session_key(session.session_id)
      stored = storage.get(session_key)
      assert stored, "Session was not stored"

      # Verify state mapping was stored
      state_key = AtprotoAuth::Storage::KeyBuilder.state_key(session.state_token)
      state_mapping = storage.get(state_key)
      assert_equal session.session_id, state_mapping
    end
  end

  describe "#update_session" do
    let(:client_id) { "test_client_id" }
    let(:scope) { "read write" }
    let(:session) do
      session_manager.create_session(client_id: client_id, scope: scope)
    end

    it "updates an existing session" do
      # Update session with new data
      session.did = "did:test:123"
      updated = session_manager.update_session(session)

      # Verify session was stored correctly
      retrieved = session_manager.get_session(session.session_id)
      _(retrieved.did).must_equal "did:test:123"
      _(retrieved.session_id).must_equal session.session_id
      _(updated).must_equal session
    end

    it "maintains state token mapping after update" do
      updated = session_manager.update_session(session)
      retrieved = session_manager.get_session_by_state(updated.state_token)

      _(retrieved).wont_be_nil
      _(retrieved.session_id).must_equal session.session_id
    end

    it "handles storage errors gracefully" do
      failing_storage = Class.new(AtprotoAuth::Storage::Interface) do
        def set(*)
          raise AtprotoAuth::Storage::StorageError, "Storage failure"
        end

        def with_lock(*)
          yield if block_given?
        end
      end.new

      AtprotoAuth.stubs(:storage).returns(failing_storage)

      assert_raises(AtprotoAuth::Storage::StorageError) do
        session_manager.update_session(session)
      end
    end

    it "updates both session and state mapping atomically" do
      original_state = session.state_token

      # Verify both session and state mapping are updated
      updates = []
      storage.define_singleton_method(:set) do |key, value|
        updates << key
        super(key, value)
      end

      session_manager.update_session(session)

      session_key = AtprotoAuth::Storage::KeyBuilder.session_key(session.session_id)
      state_key = AtprotoAuth::Storage::KeyBuilder.state_key(original_state)

      _(updates).must_include session_key
      _(updates).must_include state_key
    end
  end

  describe "#get_session" do
    it "retrieves an existing session by ID" do
      original = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      retrieved = session_manager.get_session(original.session_id)

      assert_equal original.session_id, retrieved.session_id
      assert_equal original.client_id, retrieved.client_id
      assert_equal original.scope, retrieved.scope
    end

    it "returns nil for a non-existent session ID" do
      assert_nil session_manager.get_session("non_existent_session_id")
    end

    it "returns nil if deserialization fails" do
      session = session_manager.create_session(client_id: client_id, scope: scope)
      session_key = AtprotoAuth::Storage::KeyBuilder.session_key(session.session_id)

      # Corrupt the stored data
      storage.set(session_key, "invalid json")

      assert_nil session_manager.get_session(session.session_id)
    end

    it "returns nil for expired non-renewable sessions" do
      session = session_manager.create_session(client_id: client_id, scope: scope)

      # Add expired tokens
      tokens = AtprotoAuth::State::TokenSet.new(
        access_token: "expired_token",
        token_type: "DPoP",
        expires_in: 1,
        scope: scope,
        sub: did
      )

      tokens.instance_variable_set(:@expires_at, Time.now - 10)
      session.tokens = tokens

      # Re-store the session with expired tokens
      session_key = AtprotoAuth::Storage::KeyBuilder.session_key(session.session_id)
      serializer = AtprotoAuth::Serialization::Session.new
      storage.set(session_key, serializer.serialize(session))

      # If this still fails, let's inspect what we get back
      result = session_manager.get_session(session.session_id)
      if result
        flunk "Expected nil but got session with: expired=#{result.tokens&.expired?}, " \
              "renewable=#{result.renewable?}, refresh_token=#{result.tokens&.refresh_token}"
      end

      assert_nil session_manager.get_session(session.session_id)
    end
  end

  describe "#get_session_by_state" do
    it "retrieves a session by a valid state token" do
      original = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      retrieved = session_manager.get_session_by_state(original.state_token)
      assert_equal original.session_id, retrieved.session_id
    end

    it "returns nil for an invalid state token" do
      session_manager.create_session(client_id: client_id, scope: scope)
      assert_nil session_manager.get_session_by_state("invalid_state_token")
    end

    it "returns nil for nil state" do
      assert_nil session_manager.get_session_by_state(nil)
    end
  end

  describe "#remove_session" do
    it "removes a session and its state mapping" do
      session = session_manager.create_session(client_id: client_id, scope: scope)
      session_key = AtprotoAuth::Storage::KeyBuilder.session_key(session.session_id)
      state_key = AtprotoAuth::Storage::KeyBuilder.state_key(session.state_token)

      session_manager.remove_session(session.session_id)

      refute storage.exists?(session_key), "Session was not removed"
      refute storage.exists?(state_key), "State mapping was not removed"
    end

    it "handles removal of non-existent session" do
      assert_nil session_manager.remove_session("non_existent_session_id")
    end
  end

  describe "storage integration" do
    it "handles storage errors gracefully" do
      # Create a failing storage implementation
      failing_storage = Class.new(AtprotoAuth::Storage::Interface) do
        def set(*)
          raise AtprotoAuth::Storage::StorageError, "Storage failure"
        end

        def get(*)
          raise AtprotoAuth::Storage::StorageError, "Storage failure"
        end

        def delete(*)
          raise AtprotoAuth::Storage::StorageError, "Storage failure"
        end

        def exists?(*)
          raise AtprotoAuth::Storage::StorageError, "Storage failure"
        end

        def multi_get(*)
          raise AtprotoAuth::Storage::StorageError, "Storage failure"
        end

        def multi_set(*)
          raise AtprotoAuth::Storage::StorageError, "Storage failure"
        end

        def acquire_lock(*)
          false
        end

        def release_lock(*)
          true
        end

        def with_lock(*)
          yield if block_given?
        end
      end.new

      AtprotoAuth.stubs(:storage).returns(failing_storage)

      # Test error handling
      assert_raises(AtprotoAuth::Storage::StorageError) do
        session_manager.create_session(client_id: client_id, scope: scope)
      end

      assert_nil session_manager.get_session("any_id")
      assert_nil session_manager.get_session_by_state("any_state")
    end
  end
end
