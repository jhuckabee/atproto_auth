# frozen_string_literal: true

require_relative "../../test_helper"

UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

describe AtprotoAuth::DPoP::ProofGenerator do
  let(:key_manager) { AtprotoAuth::DPoP::KeyManager.new }
  let(:generator) { AtprotoAuth::DPoP::ProofGenerator.new(key_manager) }
  let(:http_method) { "POST" }
  let(:http_uri) { "https://example.com/path" }

  describe "initialization" do
    it "requires a key manager" do
      assert_raises(AtprotoAuth::DPoP::ProofGenerator::ProofError) do
        AtprotoAuth::DPoP::ProofGenerator.new(nil)
      end
    end

    it "validates key manager type" do
      assert_raises(AtprotoAuth::DPoP::ProofGenerator::ProofError) do
        AtprotoAuth::DPoP::ProofGenerator.new("invalid")
      end
    end
  end

  describe "#generate" do
    it "generates valid proof JWT" do
      proof = generator.generate(http_method: http_method, http_uri: http_uri)
      segments = proof.split(".")
      assert_equal 3, segments.length # header.payload.signature

      header = JSON.parse(Base64.urlsafe_decode64(segments[0]))
      payload = JSON.parse(Base64.urlsafe_decode64(segments[1]))

      assert_equal "dpop+jwt", header["typ"]
      assert_equal "ES256", header["alg"]
      assert_kind_of Hash, header["jwk"]

      assert_match UUID_REGEX, payload["jti"]
      assert_equal http_method, payload["htm"]
      assert_equal http_uri, payload["htu"]
      assert_kind_of Integer, payload["iat"]
    end

    it "includes nonce when provided" do
      nonce = SecureRandom.hex
      proof = generator.generate(
        http_method: http_method,
        http_uri: http_uri,
        nonce: nonce
      )
      payload = extract_payload(proof)
      assert_equal nonce, payload["nonce"]
    end

    it "optionally includes access token hash" do
      token = "test_token"
      proof = generator.generate(
        http_method: http_method,
        http_uri: http_uri,
        access_token: token,
        ath: true
      )
      payload = extract_payload(proof)

      digest = OpenSSL::Digest::SHA256.digest(token)
      expected_hash = Base64.urlsafe_encode64(digest, padding: false)
      assert_equal expected_hash, payload["ath"]
    end

    it "normalizes URIs" do
      uri = "https://example.com:443/path?query#fragment"
      proof = generator.generate(http_method: http_method, http_uri: uri)
      payload = extract_payload(proof)
      assert_equal "https://example.com/path?query", payload["htu"]
    end

    it "validates http method" do
      assert_raises(AtprotoAuth::DPoP::ProofGenerator::ProofError) do
        generator.generate(http_method: "", http_uri: http_uri)
      end
    end

    it "validates http uri" do
      assert_raises(AtprotoAuth::DPoP::ProofGenerator::ProofError) do
        generator.generate(http_method: http_method, http_uri: "invalid")
      end
    end

    it "requires https or http uri" do
      assert_raises(AtprotoAuth::DPoP::ProofGenerator::ProofError) do
        generator.generate(http_method: http_method, http_uri: "ftp://example.com")
      end
    end
  end

  private

  def extract_payload(proof)
    payload = proof.split(".")[1]
    JSON.parse(Base64.urlsafe_decode64(payload))
  end
end
