# frozen_string_literal: true

require "logger"

module AtprotoAuth
  # Configuration class for global AtprotoAuth settings
  class Configuration
    attr_accessor :default_token_lifetime, :dpop_nonce_lifetime, :http_client, :logger

    def initialize
      @default_token_lifetime = 300 # 5 minutes in seconds
      @dpop_nonce_lifetime = 300 # 5 minutes in seconds
      @http_client = nil
      @logger = Logger.new($stdout)
    end
  end
end
