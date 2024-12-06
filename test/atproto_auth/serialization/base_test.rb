# frozen_string_literal: true

require_relative "../../test_helper"

class TestSerializer < AtprotoAuth::Serialization::Base
  def type_identifier
    "Test"
  end

  private

  def serialize_data(obj)
    { "value" => obj }
  end

  def deserialize_data(data)
    data["value"]
  end

  def validate_object!(obj)
    raise AtprotoAuth::Serialization::ValidationError unless obj.is_a?(String)
  end
end

describe AtprotoAuth::Serialization::Base do
  let(:serializer) { TestSerializer.new }
  let(:sample_data) { "test data" }

  describe "#serialize" do
    it "creates valid serialized format" do
      result = JSON.parse(serializer.serialize(sample_data))

      assert_equal AtprotoAuth::Serialization::Base::CURRENT_VERSION, result["version"]
      assert_equal "Test", result["type"]
      assert result["created_at"]
      assert result["updated_at"]
      assert result["data"]
    end

    it "encrypts sensitive fields" do
      sensitive_data = { "access_token" => "secret" }
      serializer.stubs(:serialize_data).returns(sensitive_data)

      result = JSON.parse(serializer.serialize("test"))
      encrypted = result["data"]["access_token"]

      assert encrypted.key?("version")
      assert encrypted.key?("iv")
      assert encrypted.key?("data")
      assert encrypted.key?("tag")
    end

    it "raises ValidationError for invalid objects" do
      assert_raises(AtprotoAuth::Serialization::ValidationError) do
        serializer.serialize(123)
      end
    end
  end

  describe "#deserialize" do
    it "correctly deserializes and decrypts data" do
      serialized = serializer.serialize(sample_data) # { "value" => obj }
      deserialized = serializer.deserialize(serialized) # data["value"]

      assert_equal sample_data, deserialized
    end

    it "raises Error for invalid JSON" do
      assert_raises(AtprotoAuth::Serialization::Error) do
        serializer.deserialize("invalid json")
      end
    end

    it "raises TypeMismatchError for wrong type" do
      serialized = TestSerializer.new.serialize(sample_data)
      data = JSON.parse(serialized)
      data["type"] = "Wrong"

      assert_raises(AtprotoAuth::Serialization::TypeMismatchError) do
        serializer.deserialize(JSON.generate(data))
      end
    end

    it "raises VersionError for unsupported version" do
      serialized = TestSerializer.new.serialize(sample_data)
      data = JSON.parse(serialized)
      data["version"] = 999

      assert_raises(AtprotoAuth::Serialization::VersionError) do
        serializer.deserialize(JSON.generate(data))
      end
    end
  end
end
