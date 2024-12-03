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
      stub_dns_records(["did=#{did}"])
      stub_plc_document(did, pds_url)

      result = resolver.resolve_handle(handle)
      assert_equal did, result[:did]
      assert_equal pds_url, result[:pds]
    end

    it "falls back to HTTP resolution" do
      stub_dns_empty
      stub_request(:get, "https://#{handle}/.well-known/atproto-did")
        .to_return(body: did)
      stub_plc_document(did, pds_url)

      result = resolver.resolve_handle(handle)
      assert_equal did, result[:did]
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
  end

  describe "#verify_issuer_binding" do
    let(:issuer) { "https://auth.test.com" }

    it "verifies issuer is authorized for DID" do
      stub_plc_document(did, pds_url)
      stub_resource_server_metadata(pds_url, issuer)

      assert resolver.verify_issuer_binding(did, issuer)
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
        .to_return(body: doc.to_json)

      assert resolver.verify_handle_binding(handle, did)
    end
  end

  private

  def stub_dns_records(records)
    Resolv::DNS.stubs(:new).returns(mock_resolver(records))
  end

  def stub_dns_empty
    Resolv::DNS.stubs(:new).returns(mock_resolver([]))
  end

  def mock_resolver(records)
    resolver = Minitest::Mock.new
    def resolver.timeouts=(val); end
    def resolver.close; end

    txt_resources = records.map do |record|
      resource = Minitest::Mock.new
      resource.expect :strings, [record]
      resource
    end

    resolver.expect :getresources, txt_resources, [String, Resolv::DNS::Resource::IN::TXT]
    resolver
  end

  def stub_plc_document(did, pds_url)
    doc = {
      "id" => did,
      "pds" => pds_url
    }
    stub_request(:get, "#{resolver.instance_variable_get(:@plc_directory)}/#{did}")
      .to_return(body: doc.to_json)
  end

  def stub_resource_server_metadata(pds_url, auth_server)
    stub_request(:get, "#{pds_url}/.well-known/oauth-protected-resource")
      .to_return(body: { authorization_servers: [auth_server] }.to_json)
  end
end
