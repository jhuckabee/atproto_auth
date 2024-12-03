# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::PAR::Request do
  let(:config) do
    AtprotoAuth::PAR::Request::Configuration.new.tap do |c|
      c.client_id = "client123"
      c.redirect_uri = "https://example.com/callback"
      c.code_challenge = "abc123"
      c.code_challenge_method = "S256"
      c.state = "xyz456"
      c.scope = "atproto read"
    end
  end

  describe ".build" do
    it "creates a new request instance" do
      request = AtprotoAuth::PAR::Request.build do |c|
        c.client_id = "client123"
        c.redirect_uri = "https://example.com/callback"
        c.code_challenge = "abc123"
        c.code_challenge_method = "S256"
        c.state = "xyz456"
        c.scope = "atproto read"
      end

      _(request).must_be_instance_of AtprotoAuth::PAR::Request
      _(request.client_id).must_equal "client123"
      _(request.redirect_uri).must_equal "https://example.com/callback"
    end
  end

  describe "#initialize" do
    it "initializes with valid configuration" do
      request = AtprotoAuth::PAR::Request.new(config)
      _(request.client_id).must_equal "client123"
      _(request.redirect_uri).must_equal "https://example.com/callback"
      _(request.code_challenge).must_equal "abc123"
      _(request.code_challenge_method).must_equal "S256"
      _(request.state).must_equal "xyz456"
      _(request.scope).must_equal "atproto read"
    end

    it "raises an error if a required parameter is missing" do
      config.client_id = nil
      assert_raises(AtprotoAuth::PAR::Error, "client_id is required") do
        AtprotoAuth::PAR::Request.new(config)
      end
    end

    it "raises an error if response_type is invalid" do
      request = AtprotoAuth::PAR::Request.new(config)
      request.instance_variable_set(:@response_type, "invalid")
      assert_raises(AtprotoAuth::PAR::Error, "response_type must be 'code'") do
        request.send(:validate_response_type!)
      end
    end

    it "raises an error if code_challenge_method is invalid" do
      config.code_challenge_method = "invalid"
      assert_raises(AtprotoAuth::PAR::Error, "code_challenge_method must be 'S256'") do
        AtprotoAuth::PAR::Request.new(config)
      end
    end

    it "raises an error if atproto scope is missing" do
      config.scope = "read"
      assert_raises(AtprotoAuth::PAR::Error, "atproto scope is required") do
        AtprotoAuth::PAR::Request.new(config)
      end
    end
  end

  describe "#to_form" do
    it "returns form-encoded parameters" do
      request = AtprotoAuth::PAR::Request.new(config)
      form = request.to_form
      _(form).must_include "client_id=client123"
      _(form).must_include "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"
      _(form).must_include "code_challenge=abc123"
      _(form).must_include "code_challenge_method=S256"
      _(form).must_include "state=xyz456"
      _(form).must_include "scope=atproto+read"
    end
  end
end
