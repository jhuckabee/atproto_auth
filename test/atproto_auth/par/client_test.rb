# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::PAR::Client do
  before do
    @endpoint = "https://auth.example.com/par"
    @dpop_client = mock("dpop_client")
    @nonce_manager = mock("nonce_manager")
    @dpop_client.stubs(:nonce_manager).returns(@nonce_manager)
    @client = AtprotoAuth::PAR::Client.new(endpoint: @endpoint, dpop_client: @dpop_client)
  end

  describe "#initialize" do
    it "raises an error if endpoint is not HTTPS" do
      assert_raises(AtprotoAuth::PAR::Error) do
        AtprotoAuth::PAR::Client.new(endpoint: "http://auth.example.com/par", dpop_client: @dpop_client)
      end
    end

    it "initializes correctly with a valid HTTPS endpoint" do
      assert_equal @endpoint, @client.endpoint
      assert_equal @dpop_client, @client.dpop_client
    end
  end

  describe "#submit" do
    before do
      @request = mock("request")
      @proof = "mocked_dpop_proof"
      @response = { status: 201, body: '{"request_uri":"mocked_uri","expires_in":3600}' }
      @server_origin = "https://auth.example.com"

      @request.stubs(:to_form).returns("client_id=mock_client_id&scope=mock_scope")
      @dpop_client.stubs(:generate_proof).returns(@proof)
      @nonce_manager.stubs(:get).returns("mocked_nonce")
      @http_client = mock("http_client")
      @http_client.stubs(:get)
      @http_client.stubs(:post).returns(@response)
      AtprotoAuth.configure do |configuration|
        configuration.http_client = @http_client
      end
    end

    it "submits the PAR request and returns a Response object on success" do
      response = @client.submit(@request)
      assert_instance_of AtprotoAuth::PAR::Response, response
      assert_equal "mocked_uri", response.request_uri
      assert_equal 3600, response.expires_in
    end

    it "retries the request with a nonce if the response indicates 'use_dpop_nonce'" do
      error_response = { status: 400, body: '{"error":"use_dpop_nonce"}', headers: { "DPoP-Nonce" => "new_nonce" } }
      @nonce_manager.expects(:update).with(nonce: "new_nonce", server_url: @server_origin)
      AtprotoAuth.configuration.http_client.stubs(:post).returns(error_response).then.returns(@response)

      response = @client.submit(@request)
      assert_instance_of AtprotoAuth::PAR::Response, response
    end

    it "raises an error if the response is invalid" do
      AtprotoAuth.configuration.http_client.stubs(:post).returns({ status: 400, body: '{"error":"invalid_request"}' })
      assert_raises(AtprotoAuth::PAR::Error) { @client.submit(@request) }
    end
  end

  describe "#authorization_url" do
    it "constructs a valid authorization URL" do
      authorize_endpoint = "https://auth.example.com/authorize"
      request_uri = "mocked_request_uri"
      client_id = "mocked_client_id"

      url = @client.authorization_url(authorize_endpoint: authorize_endpoint,
                                      request_uri: request_uri,
                                      client_id: client_id)
      expected_url = "https://auth.example.com/authorize?request_uri=mocked_request_uri&client_id=mocked_client_id"
      assert_equal expected_url, url
    end
  end
end
