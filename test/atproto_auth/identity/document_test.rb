# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Identity::Document do
  let(:valid_data) do
    {
      "id" => "did:plc:abc123",
      "verificationMethod" => [{ "publicKeyMultibase" => "z123" }],
      "alsoKnownAs" => ["at://alice.example.com"],
      "pds" => "https://pds.example.com"
    }
  end

  let(:legacy_data) do
    {
      "id" => "did:plc:abc123",
      "service" => [
        {
          "id" => "#atproto_pds",
          "type" => "AtprotoPersonalDataServer",
          "serviceEndpoint" => "https://pds.example.com"
        }
      ]
    }
  end

  let(:invalid_data_no_id) { { "verificationMethod" => [] } }
  let(:invalid_did) { { "id" => "invalid:plc:123" } }
  let(:invalid_service_format) do
    {
      "id" => "did:plc:abc123",
      "service" => [{ "id" => "#svc", "type" => "ServiceType" }]
    }
  end

  describe "#initialize" do
    it "initializes with valid data" do
      doc = AtprotoAuth::Identity::Document.new(valid_data)
      _(doc.did).must_equal "did:plc:abc123"
      _(doc.rotation_keys).must_equal ["z123"]
      _(doc.also_known_as).must_equal ["at://alice.example.com"]
      _(doc.pds).must_equal "https://pds.example.com"
    end

    it "initializes with legacy data format" do
      doc = AtprotoAuth::Identity::Document.new(legacy_data)
      _(doc.did).must_equal "did:plc:abc123"
      _(doc.rotation_keys).must_equal []
      _(doc.also_known_as).must_equal []
      _(doc.pds).must_equal "https://pds.example.com"
    end

    it "raises an error if data is missing id" do
      assert_raises(AtprotoAuth::Identity::DocumentError, "Document must have id") do
        AtprotoAuth::Identity::Document.new(invalid_data_no_id)
      end
    end

    it "raises an error if DID format is invalid" do
      assert_raises(AtprotoAuth::Identity::Error, "Invalid DID format (must be did:plc:)") do
        AtprotoAuth::Identity::Document.new(invalid_did)
      end
    end

    it "raises an error if service entry format is invalid" do
      assert_raises(AtprotoAuth::Identity::DocumentError, "Invalid service entry format") do
        AtprotoAuth::Identity::Document.new(invalid_service_format)
      end
    end
  end

  describe "#has_handle?" do
    let(:doc) { AtprotoAuth::Identity::Document.new(valid_data) }

    it "returns true if handle is present in alsoKnownAs" do
      _(doc.has_handle?("alice.example.com")).must_equal true
    end

    it "returns true if handle with @ prefix is present in alsoKnownAs" do
      _(doc.has_handle?("@alice.example.com")).must_equal true
    end

    it "returns false if handle is not present in alsoKnownAs" do
      _(doc.has_handle?("bob.example.com")).must_equal false
    end
  end
end
