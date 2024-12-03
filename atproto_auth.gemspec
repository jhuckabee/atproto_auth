# frozen_string_literal: true

require_relative "lib/atproto_auth/version"

Gem::Specification.new do |spec|
  spec.name = "atproto_auth"
  spec.version = AtprotoAuth::VERSION
  spec.authors = ["Josh Huckabee"]
  spec.email = ["mail@joshhuckabee.com"]

  spec.summary = "Ruby implementation of the AT Protocol OAuth specification"
  spec.description = "A Ruby library for implementing AT Protocol OAuth flows, including DPoP, PAR, and dynamic client registration. Supports both client and server-side implementations with comprehensive security features." # rubocop:disable Layout/LineLength
  spec.homepage = "https://github.com/jhuckabee/atproto_auth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/jhuckabee/atproto_auth"
  spec.metadata["changelog_uri"] = "https://github.com/jhuckabee/atproto_auth/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "jose", "~> 1.2"
  spec.add_dependency "jwt", "~> 2.9"
end
