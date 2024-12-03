# frozen_string_literal: true

require_relative "../../test_helper"

describe AtprotoAuth::ServerMetadata::OriginUrl do
  let(:valid_url) { "https://example.com" }
  let(:valid_url_with_port) { "https://example.com:8443" }
  let(:url_with_http) { "http://example.com" }
  let(:url_with_path) { "https://example.com/path" }
  let(:url_with_query) { "https://example.com?query=1" }
  let(:url_with_fragment) { "https://example.com#fragment" }
  let(:url_with_userinfo) { "https://user:pass@example.com" }
  let(:url_with_default_port) { "https://example.com:443" }
  let(:malformed_url) { "not a url" }

  describe "#valid?" do
    it "returns true for a valid origin URL" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(valid_url)
      _(origin_url.valid?).must_equal true
    end

    it "returns true for a valid origin URL with a non-default port" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(valid_url_with_port)
      _(origin_url.valid?).must_equal true
    end

    it "returns false for a URL using HTTP scheme" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(url_with_http)
      _(origin_url.valid?).must_equal false
    end

    it "returns false for a URL with a non-root path" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(url_with_path)
      _(origin_url.valid?).must_equal false
    end

    it "returns false for a URL with a query string" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(url_with_query)
      _(origin_url.valid?).must_equal false
    end

    it "returns false for a URL with a fragment" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(url_with_fragment)
      _(origin_url.valid?).must_equal false
    end

    it "returns false for a URL with userinfo (credentials)" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(url_with_userinfo)
      _(origin_url.valid?).must_equal false
    end

    it "returns false for a URL with the default HTTPS port (443)" do
      origin_url = AtprotoAuth::ServerMetadata::OriginUrl.new(url_with_default_port)
      _(origin_url.valid?).must_equal false
    end

    it "raises an error for a malformed URL" do
      assert_raises(URI::InvalidURIError) do
        AtprotoAuth::ServerMetadata::OriginUrl.new(malformed_url).valid?
      end
    end
  end
end
