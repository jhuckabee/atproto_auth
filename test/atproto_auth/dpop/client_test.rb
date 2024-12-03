# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::DPoP::Client do
  let(:mock_key_manager) do
    Class.new(AtprotoAuth::DPoP::KeyManager) do
      def initialize; end # rubocop:disable Lint/MissingSuper - prevent calling actual KeyManager initialization logic
      def public_jwk = { kty: "EC", crv: "P-256", x: "test", y: "test" }
      def sign(_jwt_payload) = "signed_jwt"
    end.new
  end

  let(:client) do
    AtprotoAuth::DPoP::Client.new(
      key_manager: mock_key_manager,
      nonce_ttl: 400
    )
  end
  let(:http_method) { "POST" }
  let(:http_uri) { "https://example.com/resource" }
  let(:nonce) { "valid_nonce" }
  let(:access_token) { "test_access_token" }
  let(:server_url) { "https://example.com" }
  let(:proof) { "dpop_proof_jwt" }
  let(:response_headers) { { "DPoP-Nonce" => nonce } }

  describe "#initialize" do
    it "initializes with a custom key_manager and nonce_ttl" do
      _(client.key_manager).must_equal mock_key_manager
      _(client.nonce_manager.instance_variable_get(:@ttl)).must_equal 400
    end
  end

  describe "#generate_proof" do
    it "generates a DPoP proof using proof_generator" do
      client.nonce_manager.expects(:get).with("https://example.com").returns(nonce)
      client.proof_generator.expects(:generate).with(
        http_method: http_method,
        http_uri: http_uri,
        nonce: nonce,
        access_token: access_token
      ).returns(proof)

      generated_proof = client.generate_proof(http_method: http_method, http_uri: http_uri, access_token: access_token)
      _(generated_proof).must_equal proof
    end

    it "raises an error if proof generation fails" do
      client.nonce_manager.expects(:get).with("https://example.com").returns(nil)
      client.proof_generator.expects(:generate).raises(StandardError, "Generation failed")

      assert_raises(AtprotoAuth::DPoP::Client::Error) do
        client.generate_proof(http_method: http_method, http_uri: http_uri)
      end
    end
  end

  describe "#process_response" do
    it "updates the nonce manager with a valid nonce" do
      client.nonce_manager.expects(:update).with(nonce: nonce, server_url: server_url)

      client.process_response(response_headers, server_url)
    end

    it "does nothing if the response headers do not include a nonce" do
      headers = {}
      client.nonce_manager.expects(:update).never

      client.process_response(headers, server_url)
    end

    it "raises an error if nonce update fails" do
      client.nonce_manager.expects(:update).raises(StandardError, "Update failed")

      assert_raises(AtprotoAuth::DPoP::Client::Error) do
        client.process_response(response_headers, server_url)
      end
    end
  end

  describe "#request_headers" do
    it "constructs the DPoP headers with the proof" do
      headers = client.request_headers(proof)
      _(headers).must_equal({ "DPoP" => proof })
    end
  end

  describe "#public_key" do
    it "returns the public JWK from key_manager" do
      mock_key_manager.expects(:public_jwk).returns({ "kty" => "EC", "crv" => "P-256" })

      _(client.public_key).must_equal({ "kty" => "EC", "crv" => "P-256" })
    end
  end

  describe "#export_key" do
    it "exports the keypair with the private key" do
      mock_key_manager.expects(:to_jwk).with(include_private: true).returns({ "kty" => "EC", "d" => "private" })

      _(client.export_key(include_private: true)).must_equal({ "kty" => "EC", "d" => "private" })
    end

    it "exports the keypair without the private key" do
      mock_key_manager.expects(:to_jwk).with(include_private: false).returns({ "kty" => "EC" })

      _(client.export_key(include_private: false)).must_equal({ "kty" => "EC" })
    end
  end
end
