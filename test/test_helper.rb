# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "atproto_auth"

require "minitest/autorun"
require "minitest/mock"
require "mocha/minitest"
require "webmock/minitest"
