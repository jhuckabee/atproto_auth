# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::State::SessionManager do
  let(:client_id) { "test_client_id" }
  let(:scope) { "read write" }
  let(:state_token) { "test_state_token" }
  let(:session_id) { SecureRandom.uuid }
  let(:auth_server) { mock("AuthorizationServer") }
  let(:did) { "did:example:1234" }
  let(:session_manager) { AtprotoAuth::State::SessionManager.new }

  describe "#initialize" do
    it "initializes with an empty session store" do
      _(session_manager.instance_variable_get(:@sessions)).must_equal({})
    end
  end

  describe "#create_session" do
    it "creates and stores a new session" do
      session = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      _(session).must_be_instance_of AtprotoAuth::State::Session
      _(session_manager.get_session(session.session_id)).must_equal session
    end
  end

  describe "#get_session" do
    it "retrieves an existing session by ID" do
      session = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      _(session_manager.get_session(session.session_id)).must_equal session
    end

    it "returns nil for a non-existent session ID" do
      _(session_manager.get_session("non_existent_session_id")).must_be_nil
    end
  end

  describe "#get_session_by_state" do
    it "retrieves a session by a valid state token" do
      session = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      _(session_manager.get_session_by_state(session.state_token)).must_equal session
    end

    it "returns nil for an invalid state token" do
      session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      _(session_manager.get_session_by_state("invalid_state_token")).must_be_nil
    end
  end

  describe "#remove_session" do
    it "removes a session by ID" do
      session = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      session_manager.remove_session(session.session_id)
      _(session_manager.get_session(session.session_id)).must_be_nil
    end
  end

  describe "#cleanup_expired" do
    it "removes sessions that are expired and not renewable" do
      expired_session = Minitest::Mock.new
      expired_session.expect(:renewable?, false)
      expired_session.expect(:tokens, Minitest::Mock.new.expect(:expired?, true))
      renewable_session = Minitest::Mock.new
      renewable_session.expect(:renewable?, true)
      session_manager.instance_variable_set(:@sessions, {
                                              "expired_session" => expired_session,
                                              "renewable_session" => renewable_session
                                            })

      session_manager.cleanup_expired

      _(session_manager.instance_variable_get(:@sessions).keys).must_equal ["renewable_session"]
      expired_session.verify
      renewable_session.verify
    end

    it "does not remove sessions that are renewable or have valid tokens" do
      session = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)

      session_manager.cleanup_expired

      _(session_manager.get_session(session.session_id)).must_equal session
    end
  end
end
