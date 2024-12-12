# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::Identity::DID do
  describe "#initialize" do
    it "initializes with a DID" do
      did = AtprotoAuth::Identity::DID.new("did:plc:abc123")
      _(did.to_s).must_equal "did:plc:abc123"
    end
  end

  describe "#validate!" do
    it "validates a PLC DID" do
      did = AtprotoAuth::Identity::DID.new("did:plc:abc123")
      did.validate!
    end

    it "validates a Web DID" do
      did = AtprotoAuth::Identity::DID.new("did:web:abc123")
      did.validate!
    end

    it "raises an error for an invalid DID" do
      did = AtprotoAuth::Identity::DID.new("invalid:plc:123")
      assert_raises(AtprotoAuth::Identity::Error,
                    "Invalid DID format (must be one of did:plc:, did:web:): invalid:plc:123") do
        did.validate!
      end
    end
  end
end
