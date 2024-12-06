# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "atproto_auth"

require "minitest/autorun"
require "minitest/mock"
require "minitest/reporters"
require "mocha/minitest"
require "webmock/minitest"

# Set a consistent encryption key to use across all tests
ENV["ATPROTO_MASTER_KEY"] = Base64.strict_encode64("0" * 32)

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new unless ENV["RM_INFO"]

module Minitest
  module Assertions
    # Helper to check if a value is encrypted
    def assert_encrypted(value, msg = nil)
      assert value.is_a?(Hash), msg || "Expected encrypted hash format"
      assert_equal AtprotoAuth::Encryption::Service::VERSION, value["version"]
      assert value["iv"], "Missing IV"
      assert value["data"], "Missing encrypted data"
      assert value["tag"], "Missing auth tag"
    end
  end
end
