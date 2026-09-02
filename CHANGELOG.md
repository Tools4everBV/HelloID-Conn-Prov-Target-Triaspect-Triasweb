# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.2.0] - 12-08-2026

### Added

- Added optional Base64 certificate support. A Base64-encoded certificate string can now be used as an alternative to a `.pfx` file. This is configured via the new `UseBase64Certificate` (checkbox) and `CertificateBase64String` settings.
- Added `$actionMessage` to all scripts.
- Added checks for accounts that are already enabled or already disabled.
- Added `-ExcludeProperty 'roleNames', 'authorizedOrganizationCodes'` to `create.ps1` and `update.ps1` when returning account data to HelloID.

### Changed

- Updated `fieldMapping.json`.

## [1.1.0] - 23-09-2025

- Fixes after first implementation.
- Feature: Moved AuthorizedOrganizationCodes to permissions and added a import script for AuthorizedOrganizationCodes.
 
## [1.0.0] - 22-05-2025

This is the first official release of _HelloID-Conn-Prov-Target-Triaspect-Triasweb_. This release is based on template version _v3.0.0_.

### Added

### Changed

### Deprecated

### Removed