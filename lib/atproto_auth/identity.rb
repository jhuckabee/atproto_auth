# frozen_string_literal: true

module AtprotoAuth
  # Handles identity resolution, verification and management for AT Protocol OAuth.
  # This module provides functionality to resolve handles to DIDs, verify identity
  # documents, validate PDS locations, and verify authorization server bindings.
  #
  # The module consists of three main components:
  #
  # 1. {Document} - Represents and validates AT Protocol DID documents,
  #    handling extraction of crucial service endpoints and verification.
  #
  # 2. {Resolver} - Handles resolution of handles to DIDs and fetching of
  #    DID documents, with support for both DNS and HTTP-based resolution.
  #
  # 3. {Error} classes - Structured error hierarchy for handling different
  #    types of identity-related failures.
  module Identity
    class Error < Error; end
    class ResolutionError < Error; end
    class ValidationError < Error; end
    class DocumentError < Error; end
  end
end
