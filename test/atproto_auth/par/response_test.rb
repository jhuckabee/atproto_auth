# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::PAR::Response do
  describe "#initialize" do
    it "initializes with valid parameters" do
      response = AtprotoAuth::PAR::Response.new(request_uri: "https://example.com/request", expires_in: 3600)
      _(response.request_uri).must_equal "https://example.com/request"
      _(response.expires_in).must_equal 3600
    end

    it "raises an error if request_uri is missing" do
      assert_raises(AtprotoAuth::PAR::Error, "request_uri is required") do
        AtprotoAuth::PAR::Response.new(request_uri: nil, expires_in: 3600)
      end
    end

    it "raises an error if request_uri is empty" do
      assert_raises(AtprotoAuth::PAR::Error, "request_uri is required") do
        AtprotoAuth::PAR::Response.new(request_uri: "", expires_in: 3600)
      end
    end

    it "raises an error if expires_in is not positive" do
      assert_raises(AtprotoAuth::PAR::Error, "expires_in must be positive") do
        AtprotoAuth::PAR::Response.new(request_uri: "https://example.com/request", expires_in: 0)
      end
    end
  end
end
