# frozen_string_literal: true

require "net/http"
require "uri"
require "ipaddr"

module AtprotoAuth
  # A secure HTTP client for making OAuth-related requests.
  # Implements protections against SSRF attacks and enforces security headers.
  class HttpClient
    FORBIDDEN_IP_RANGES = [
      IPAddr.new("0.0.0.0/8"),      # Current network
      IPAddr.new("10.0.0.0/8"),     # Private network
      IPAddr.new("127.0.0.0/8"),    # Loopback
      IPAddr.new("169.254.0.0/16"), # Link-local
      IPAddr.new("172.16.0.0/12"),  # Private network
      IPAddr.new("192.168.0.0/16"), # Private network
      IPAddr.new("fc00::/7"),       # Unique local address
      IPAddr.new("fe80::/10")       # Link-local address
    ].freeze

    ALLOWED_SCHEMES = ["https"].freeze
    DEFAULT_TIMEOUT = 10 # seconds
    MAX_REDIRECTS = 5
    MAX_RESPONSE_SIZE = 10 * 1024 * 1024 # 10MB

    # Error raised when a request is blocked due to SSRF protection
    class SSRFError < Error; end

    # Error raised when an HTTP request fails
    class HttpError < Error
      attr_reader :response

      def initialize(message, response)
        @response = response
        super(message)
      end
    end

    RedirectHandlerOptions = Data.define(:original_uri, :method, :response, :headers, :redirect_count, :body)

    # @param timeout [Integer] Request timeout in seconds
    # @param verify_ssl [Boolean] Whether to verify SSL certificates
    def initialize(timeout: DEFAULT_TIMEOUT, verify_ssl: true)
      @timeout = timeout
      @verify_ssl = verify_ssl
    end

    # Makes a secure HTTP GET request
    # @param url [String] URL to request
    # @param headers [Hash] Additional headers to send
    # @return [Hash] Response with :status, :headers, and :body
    # @raise [SSRFError] If the request would be unsafe
    # @raise [HttpError] If the request fails
    def get(url, headers = {})
      uri = validate_uri!(url)
      validate_ip!(uri)

      response = make_request(uri, headers)
      validate_response!(response)

      {
        status: response.code.to_i,
        headers: response.each_header.to_h,
        body: response.body
      }
    end

    # Makes a secure HTTP POST request
    # @param url [String] URL to request
    # @param body [String] Request body
    # @param headers [Hash] Additional headers to send
    # @return [Hash] Response with :status, :headers, and :body
    # @raise [SSRFError] If the request would be unsafe
    # @raise [HttpError] If the request fails
    def post(url, body: nil, headers: {})
      uri = validate_uri!(url)
      validate_ip!(uri)

      response = make_post_request(uri, body, headers)
      validate_response!(response)

      {
        status: response.code.to_i,
        headers: response.each_header.to_h,
        body: response.body
      }
    end

    private

    def validate_uri!(url)
      uri = URI(url)
      unless ALLOWED_SCHEMES.include?(uri.scheme)
        raise SSRFError, "URL scheme must be one of: #{ALLOWED_SCHEMES.join(", ")}"
      end

      # Extract and validate host before any network activity
      host = uri.host.to_s.strip
      raise SSRFError, "URL must include host" if host.empty?
      raise SSRFError, "URL must not include fragment" if uri.fragment

      uri
    end

    def validate_ip!(uri)
      # Check if host is an IP address by trying to parse it
      if uri.host =~ /^(\d{1,3}\.){3}\d{1,3}$/
        begin
          ip = IPAddr.new(uri.host)
          raise SSRFError, "Request to forbidden IP address" if forbidden_ip?(ip)
        rescue IPAddr::InvalidAddressError
          # Not a valid IP, will be handled as hostname below
        end
      end

      # Also check resolved IPs for hostnames
      begin
        ips = Resolv::DNS.new.getaddresses(uri.host)
        ips.each do |x|
          ip_addr = IPAddr.new(x.to_s)
          raise SSRFError, "Request to forbidden IP address" if forbidden_ip?(ip_addr)
        rescue IPAddr::InvalidAddressError
          next
        end
      rescue Resolv::ResolvError
        raise SSRFError, "Could not resolve hostname"
      end
    end

    def forbidden_ip?(ip)
      FORBIDDEN_IP_RANGES.any? { |range| range.include?(ip) }
    end

    def make_request(uri, headers = {}, redirect_count = 0)
      http = Net::HTTP.new(uri.host, uri.port)
      configure_http_client!(http)

      request = Net::HTTP::Get.new(uri.request_uri)
      add_security_headers!(request, headers)
      response = http.request(request)
      handle_redirect(
        original_uri: uri,
        response: response,
        headers: headers,
        redirect_count: redirect_count
      )
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise HttpError.new("Request timeout: #{e.message}", nil)
    rescue StandardError => e
      raise HttpError.new("Request failed: #{e.message}", nil)
    end

    def make_post_request(uri, body, headers = {}, redirect_count = 0)
      http = Net::HTTP.new(uri.host, uri.port)
      configure_http_client!(http)

      request = Net::HTTP::Post.new(uri.request_uri)
      add_security_headers!(request, headers)
      request.body = body.is_a?(Hash) ? URI.encode_www_form(body) : body if body

      response = http.request(request)
      handle_redirect(
        original_uri: uri,
        body: body,
        method: :post,
        response: response,
        headers: headers,
        redirect_count: redirect_count
      )
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise HttpError.new("Request timeout: #{e.message}", nil)
    rescue StandardError => e
      raise HttpError.new("Request failed: #{e.message}", nil)
    end

    def configure_http_client!(http)
      http.use_ssl = true
      http.verify_mode = @verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      http.read_timeout = @timeout
      http.open_timeout = @timeout
    end

    def add_security_headers!(request, headers)
      # Prevent caching of sensitive data
      request["Cache-Control"] = "no-store"

      # Add user-provided headers
      headers.each { |k, v| request[k] = v }
    end

    # Handle HTTP redirects
    # kwargs can include:
    # - original_uri: URI of the original request
    # - method: HTTP method of the original request (:get or :post)
    # - response: Net::HTTPResponse object
    # - headers: Hash of headers from the original request
    # - redirect_count: Number of redirects so far
    # - body: Request body for POST requests
    def handle_redirect(**kwargs)
      response = kwargs[:response]
      redirect_count = kwargs[:redirect_count]

      return response unless response.is_a?(Net::HTTPRedirection)
      raise HttpError.new("Too many redirects", response) if redirect_count >= MAX_REDIRECTS

      location = URI(response["location"])
      location = kwargs[:original_uri] + location if location.relative?

      validate_uri!(location.to_s)
      validate_ip!(location)

      # Increment redirect count for the next request
      redirect_count += 1

      # Recursive call to handle the next redirect
      if kwargs[:method] == :post
        make_post_request(location, kwargs[:body], kwargs[:headers], redirect_count)
      else
        make_request(location, kwargs[:headers], redirect_count)
      end
    end

    def validate_response!(response)
      # check_success_status!(response)
      check_content_length!(response)
    end

    def check_success_status!(response)
      return if response.is_a?(Net::HTTPSuccess)

      raise HttpError.new("HTTP request failed: #{response.code} #{response.message}", response)
    end

    def check_content_length!(response)
      content_length = response["content-length"]&.to_i || response.body&.bytesize || 0
      return unless content_length > MAX_RESPONSE_SIZE

      raise HttpError.new("Response too large: #{content_length} bytes", response)
    end
  end
end
