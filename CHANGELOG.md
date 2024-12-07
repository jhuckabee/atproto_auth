# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-07

### Added
- Configurable storage backend system for managing OAuth state
- In-memory storage implementation included by default
- Redis storage implementation for production environments
- Thread-safe storage operations with atomic locks
- Storage encryption for sensitive data
- Automatic cleanup of expired tokens and session data
- Storage interface for custom backend implementations

### Changed
- Storage configuration is now required in AtprotoAuth.configure
- Default configuration uses thread-safe in-memory storage
- Session and token management now use configured storage backend
- Improved thread safety for all storage operations

## [0.0.1] - 2024-12-05

- Initial release
