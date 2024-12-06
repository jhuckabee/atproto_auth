# frozen_string_literal: true

require "logger"

module AtprotoAuth
  class ConfigurationError < Error; end

  # Configuration class for global AtprotoAuth settings
  class Configuration
    attr_accessor :default_token_lifetime,
                  :dpop_nonce_lifetime,
                  :encryption,
                  :http_client,
                  :logger,
                  :storage

    def initialize
      @default_token_lifetime = 300 # 5 minutes in seconds
      @dpop_nonce_lifetime = 300 # 5 minutes in seconds
      @encryption = nil
      @http_client = nil
      @logger = Logger.new($stdout)
      @storage = AtprotoAuth::Storage::Memory.new
    end

    # Validates the current configuration
    # @raise [ConfigurationError] if configuration is invalid
    def validate!
      validate_storage!
      validate_http_client!
      true
    end

    private

    def validate_storage!
      raise ConfigurationError, "Storage must be configured" if @storage.nil?
      return if @storage.is_a?(AtprotoAuth::Storage::Interface)

      raise ConfigurationError, "Storage must implement Storage::Interface"
    end

    def validate_http_client!
      return if @http_client.nil? # Allow nil for testing

      return if @http_client.respond_to?(:get) && @http_client.respond_to?(:post)

      raise ConfigurationError, "HTTP client must implement get and post methods"
    end
  end
end
