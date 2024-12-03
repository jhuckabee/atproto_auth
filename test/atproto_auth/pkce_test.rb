# frozen_string_literal: true

require_relative "../test_helper"

describe AtprotoAuth::PKCE do
  let(:valid_verifier) { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" }
  let(:short_verifier) { "short" }
  let(:long_verifier) { "a" * 129 }
  let(:invalid_verifier) { "invalid_verifier!" }
  let(:challenge) { AtprotoAuth::PKCE.generate_challenge(valid_verifier) }

  describe ".generate_verifier" do
    it "generates a valid code verifier of default length" do
      verifier = AtprotoAuth::PKCE.generate_verifier
      _(verifier.length).must_equal AtprotoAuth::PKCE::MAX_VERIFIER_LENGTH
      _(verifier).must_match AtprotoAuth::PKCE::ALLOWED_VERIFIER_CHARS
    end

    it "generates a valid code verifier of specified length" do
      length = 50
      verifier = AtprotoAuth::PKCE.generate_verifier(length)
      _(verifier.length).must_equal length
      _(verifier).must_match AtprotoAuth::PKCE::ALLOWED_VERIFIER_CHARS
    end

    it "raises an error for a length below the minimum" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.generate_verifier(AtprotoAuth::PKCE::MIN_VERIFIER_LENGTH - 1)
      end
    end

    it "raises an error for a length above the maximum" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.generate_verifier(AtprotoAuth::PKCE::MAX_VERIFIER_LENGTH + 1)
      end
    end
  end

  describe ".generate_challenge" do
    it "generates a valid challenge for a given verifier" do
      challenge = AtprotoAuth::PKCE.generate_challenge(valid_verifier)
      _(challenge).must_match(/^[A-Za-z0-9\-_]+$/)
    end

    it "raises an error for a nil verifier" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.generate_challenge(nil)
      end
    end

    it "raises an error for an empty verifier" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.generate_challenge("")
      end
    end

    it "raises an error for a verifier below the minimum length" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.generate_challenge(short_verifier)
      end
    end

    it "raises an error for a verifier above the maximum length" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.generate_challenge(long_verifier)
      end
    end

    it "raises an error for a verifier with invalid characters" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.generate_challenge(invalid_verifier)
      end
    end
  end

  describe ".verify" do
    it "returns true for a valid verifier and matching challenge" do
      result = AtprotoAuth::PKCE.verify(challenge, valid_verifier)
      _(result).must_equal true
    end

    it "returns false for a valid verifier and non-matching challenge" do
      non_matching_challenge = AtprotoAuth::PKCE.generate_challenge("different_verifier_different_verifier_12345")
      result = AtprotoAuth::PKCE.verify(non_matching_challenge, valid_verifier)
      _(result).must_equal false
    end

    it "raises an error for a nil challenge" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.verify(nil, valid_verifier)
      end
    end

    it "raises an error for a nil verifier" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.verify(challenge, nil)
      end
    end

    it "raises an error for a verifier with invalid characters" do
      assert_raises(AtprotoAuth::PKCE::Error) do
        AtprotoAuth::PKCE.verify(challenge, invalid_verifier)
      end
    end
  end
end
