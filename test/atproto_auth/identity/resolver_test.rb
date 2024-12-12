# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Identity::Resolver do
  let(:resolver) { AtprotoAuth::Identity::Resolver.new }
  let(:handle) { "user.test.com" }
  let(:did) { "did:plc:test123" }
  let(:pds_url) { "https://pds.test.com" }

  before do
    AtprotoAuth.configure do |configuration|
      configuration.http_client = AtprotoAuth::HttpClient.new
    end
  end

  describe "#resolve_handle" do
    it "resolves handle via DNS" do
      # Create mock resolver
      mock_dns = Minitest::Mock.new

      def mock_dns.timeouts=(val); end

      def mock_dns.close; end

      def mock_dns.getresources(name, type)
        if name == "_atproto.user.test.com" && type == Resolv::DNS::Resource::IN::TXT
          txt_record = Minitest::Mock.new

          def txt_record.strings
            ["did=did:plc:test123"]
          end

          [txt_record]
        else
          []
        end
      end

      def mock_dns.getaddresses(_name)
        []
      end

      # Stub DNS resolution and PLC document
      Resolv::DNS.stub :new, mock_dns do
        stub_plc_document(did, pds_url)

        result = resolver.resolve_handle(handle)
        assert_equal did, result[:did]
        assert_equal pds_url, result[:pds]
      end
    end

    it "falls back to HTTP resolution when DNS fails" do
      stub_dns_empty do
        stub_request(:get, "https://#{handle}/.well-known/atproto-did")
          .to_return(
            status: 200,
            body: did,
            headers: { "Content-Type": "text/plain" }
          )

        stub_plc_document(did, pds_url)

        result = resolver.resolve_handle(handle)
        assert_equal did, result[:did]
        assert_equal pds_url, result[:pds]
      end
    end

    it "handles @ prefix in handle" do
      result = resolver.send(:normalize_handle, "@user.test.com")
      assert_equal "user.test.com", result
    end

    it "validates handle format" do
      assert_raises(AtprotoAuth::Identity::ResolutionError) do
        resolver.resolve_handle("invalid handle")
      end
    end
  end

  describe "#get_did_info" do
    it "fetches and validates DID document" do
      stub_plc_document(did, pds_url)

      result = resolver.get_did_info(did)
      assert_equal did, result[:did]
      assert_equal pds_url, result[:pds]
      assert_kind_of AtprotoAuth::Identity::Document, result[:document]
    end

    it "requires HTTPS for PDS URL" do
      stub_plc_document(did, "http://insecure.com")

      assert_raises(AtprotoAuth::Identity::ResolutionError) do
        resolver.get_did_info(did)
      end
    end

    it "validates DID format" do
      assert_raises(AtprotoAuth::Identity::ResolutionError) do
        resolver.get_did_info("invalid:did")
      end
    end

    it "fetches and validates web DID document" do
      web_did = "did:web:example.com"
      stub_request(:get, "https://example.com/.well-known/did.json")
        .to_return(
          status: 200,
          body: {
            id: web_did,
            pds: "https://pds.example.com"
          }.to_json,
          headers: { "Content-Type": "application/json" }
        )

      result = resolver.get_did_info(web_did)
      assert_equal web_did, result[:did]
      assert_equal "https://pds.example.com", result[:pds]
    end

    it "handles web DID with path component" do
      web_did = "did:web:example.com:user:alice"
      stub_request(:get, "https://example.com/user/alice/did.json")
        .to_return(
          status: 200,
          body: {
            id: web_did,
            pds: "https://pds.example.com"
          }.to_json,
          headers: { "Content-Type": "application/json" }
        )

      result = resolver.get_did_info(web_did)
      assert_equal web_did, result[:did]
    end
  end

  describe "#verify_pds_binding" do
    it "verifies PDS hosts DID" do
      stub_plc_document(did, pds_url)

      assert resolver.verify_pds_binding(did, pds_url)
    end

    it "normalizes URLs for comparison" do
      stub_plc_document(did, pds_url)

      assert resolver.verify_pds_binding(did, "#{pds_url}/")
    end

    it "raises error for non-matching PDS" do
      stub_plc_document(did, pds_url)
      different_pds = "https://different-pds.com"

      error = assert_raises(AtprotoAuth::Identity::ValidationError) do
        resolver.verify_pds_binding(did, different_pds)
      end

      assert_match(/PDS .* is not authorized for DID .*/, error.message)
    end
  end

  describe "#verify_issuer_binding" do
    let(:issuer) { "https://auth.test.com" }

    it "verifies issuer is authorized for DID" do
      stub_plc_document(did, pds_url)
      stub_resource_server_metadata(pds_url, issuer)

      assert resolver.verify_issuer_binding(did, issuer)
    end

    it "normalizes URLs for comparison" do
      stub_plc_document(did, pds_url)
      stub_resource_server_metadata(pds_url, issuer)

      assert resolver.verify_issuer_binding(did, "#{issuer}/")
    end

    it "fails for non-matching issuer" do
      stub_plc_document(did, pds_url)
      stub_resource_server_metadata(pds_url, issuer)

      error = assert_raises(AtprotoAuth::Identity::ValidationError) do
        resolver.verify_issuer_binding(did, "https://wrong-issuer.com")
      end

      assert_match(/Issuer .* is not authorized for DID .*/, error.message)
    end
  end

  describe "#verify_handle_binding" do
    it "verifies handle belongs to DID" do
      doc = {
        "id" => did,
        "alsoKnownAs" => ["at://#{handle}"],
        "pds" => pds_url
      }
      stub_request(:get, "#{resolver.instance_variable_get(:@plc_directory)}/#{did}")
        .to_return(
          status: 200,
          body: doc.to_json,
          headers: { "Content-Type": "application/json" }
        )

      assert resolver.verify_handle_binding(handle, did)
    end

    it "fails for non-matching handle" do
      doc = {
        "id" => did,
        "alsoKnownAs" => ["at://other.handle.com"],
        "pds" => pds_url
      }
      stub_request(:get, "#{resolver.instance_variable_get(:@plc_directory)}/#{did}")
        .to_return(
          status: 200,
          body: doc.to_json,
          headers: { "Content-Type": "application/json" }
        )

      error = assert_raises(AtprotoAuth::Identity::ValidationError) do
        resolver.verify_handle_binding(handle, did)
      end

      assert_match(/Handle .* does not belong to DID .*/, error.message)
    end
  end

  private

  def stub_dns_empty(&block)
    mock_dns = Minitest::Mock.new

    def mock_dns.timeouts=(val); end

    def mock_dns.close; end

    def mock_dns.getresources(*)
      []
    end

    def mock_dns.getaddresses(*)
      []
    end

    Resolv::DNS.stub :new, mock_dns do
      block&.call
    end
  end

  def stub_plc_document(did, pds_url)
    stub_request(:get, "#{resolver.instance_variable_get(:@plc_directory)}/#{did}")
      .to_return(
        status: 200,
        body: {
          "id" => did,
          "pds" => pds_url
        }.to_json,
        headers: { "Content-Type": "application/json" }
      )
  end

  def stub_resource_server_metadata(pds_url, auth_server)
    stub_request(:get, "#{pds_url}/.well-known/oauth-protected-resource")
      .to_return(
        status: 200,
        body: {
          authorization_servers: [auth_server]
        }.to_json,
        headers: { "Content-Type": "application/json" }
      )
  end
end
