# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2024-12-11
### Fixed
- Fixed a bug with access token hash generation

## [0.2.0] - 2024-12-10
### Added
- Client#handle_callback now returns session did as part of the response

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
