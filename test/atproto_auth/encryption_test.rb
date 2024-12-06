# frozen_string_literal: true

require_relative "../test_helper"

describe AtprotoAuth::Encryption do
  describe AtprotoAuth::Encryption::Service do
    let(:encryption_service) { AtprotoAuth::Encryption::Service.new }
    let(:sample_data) { "sensitive data" }
    let(:context) { "access_token" }

    describe "#encrypt" do
      it "encrypts data with a context" do
        result = encryption_service.encrypt(sample_data, context: context)

        assert_equal AtprotoAuth::Encryption::Service::VERSION, result[:version]
        assert_kind_of String, result[:iv]
        assert_kind_of String, result[:data]
        assert_kind_of String, result[:tag]

        # Base64 validation
        assert Base64.strict_decode64(result[:iv])
        assert Base64.strict_decode64(result[:data])
        assert Base64.strict_decode64(result[:tag])
      end

      it "produces different ciphertexts for same data with different contexts" do
        result1 = encryption_service.encrypt(sample_data, context: "context1")
        result2 = encryption_service.encrypt(sample_data, context: "context2")

        refute_equal result1[:data], result2[:data]
      end

      it "produces different ciphertexts for same data and context due to IV" do
        result1 = encryption_service.encrypt(sample_data, context: context)
        result2 = encryption_service.encrypt(sample_data, context: context)

        refute_equal result1[:data], result2[:data]
        refute_equal result1[:iv], result2[:iv]
      end

      it "raises EncryptionError for nil data" do
        assert_raises(AtprotoAuth::Encryption::EncryptionError, "Data cannot be nil") do
          encryption_service.encrypt(nil, context: context)
        end
      end

      it "raises EncryptionError for nil context" do
        assert_raises(AtprotoAuth::Encryption::EncryptionError, "Context cannot be nil") do
          encryption_service.encrypt(sample_data, context: nil)
        end
      end

      it "raises EncryptionError for empty context" do
        assert_raises(AtprotoAuth::Encryption::EncryptionError, "Context cannot be empty") do
          encryption_service.encrypt(sample_data, context: "")
        end
      end

      it "converts non-string data to string" do
        result = encryption_service.encrypt(123, context: context)
        decrypted = encryption_service.decrypt(result, context: context)
        assert_equal "123", decrypted
      end
    end

    describe "#decrypt" do
      it "correctly decrypts encrypted data" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        decrypted = encryption_service.decrypt(encrypted, context: context)

        assert_equal sample_data, decrypted
      end

      it "raises DecryptionError for wrong context" do
        encrypted = encryption_service.encrypt(sample_data, context: context)

        assert_raises(AtprotoAuth::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: "wrong_context")
        end
      end

      it "raises DecryptionError for tampered data" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:data] = Base64.strict_encode64("tampered")

        assert_raises(AtprotoAuth::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: context)
        end
      end

      it "raises DecryptionError for tampered auth tag" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:tag] = Base64.strict_encode64("tampered")

        assert_raises(AtprotoAuth::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: context)
        end
      end

      it "raises DecryptionError for nil encrypted data" do
        assert_raises(AtprotoAuth::Encryption::DecryptionError, "Encrypted data cannot be nil") do
          encryption_service.decrypt(nil, context: context)
        end
      end

      it "raises DecryptionError for nil context" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        assert_raises(AtprotoAuth::Encryption::DecryptionError, "Context cannot be nil") do
          encryption_service.decrypt(encrypted, context: nil)
        end
      end

      it "raises DecryptionError for invalid format" do
        assert_raises(AtprotoAuth::Encryption::DecryptionError) do
          encryption_service.decrypt({ invalid: "format" }, context: context)
        end
      end

      it "raises DecryptionError for wrong version" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:version] = 999

        assert_raises(AtprotoAuth::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: context)
        end
      end
    end
  end

  describe AtprotoAuth::Encryption::KeyProvider do
    let(:key_provider) { AtprotoAuth::Encryption::KeyProvider.new }

    describe "#key_for_context" do
      it "derives different keys for different contexts" do
        key1 = key_provider.key_for_context("context1")
        key2 = key_provider.key_for_context("context2")

        refute_equal key1, key2
      end

      it "derives consistent keys for same context" do
        key1 = key_provider.key_for_context("context")
        key2 = key_provider.key_for_context("context")

        assert_equal key1, key2
      end

      it "returns keys of correct length for AES-256" do
        key = key_provider.key_for_context("context")
        assert_equal 32, key.bytesize
      end

      it "raises ConfigurationError for nil context" do
        assert_raises(AtprotoAuth::Encryption::ConfigurationError) do
          key_provider.key_for_context(nil)
        end
      end
    end
  end
end
