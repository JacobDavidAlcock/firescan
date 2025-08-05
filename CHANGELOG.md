# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2025-01-15

### 🏗️ Architecture
- **BREAKING CHANGE**: Refactored monolithic structure to modular architecture
- Split single `firescan.go` file into organized packages under `internal/`
- Created proper Go module structure with `cmd/firescan/main.go` entry point
- Improved separation of concerns with dedicated packages for auth, config, scanner, ui, and wordlist functionality

### ✨ New Features
- **Session Management**: Added `save-quit` command to save and resume authentication sessions
- **Enhanced Authentication**: Added `auth status` and `auth refresh` commands
- **Email Verification**: Automatic email verification for custom test accounts (non-default)
- **Smart Verification**: Only sends verification emails if account is not already verified
- **Resume Sessions**: New `--resume` flag to quickly restore previous sessions

### 🔧 Improvements
- **Thread-Safe State**: Centralized configuration management with proper mutex protection
- **Better Error Handling**: Improved error reporting across all modules
- **Code Organization**: Clean package boundaries for better maintainability and testing
- **Build Process**: Updated build instructions for new modular structure

### 🐛 Bug Fixes
- Fixed email verification detection to check actual verification status
- Improved token refresh logic with proper state updates
- Enhanced session persistence with secure file permissions (0600)

### 📚 Documentation
- Added `BUILD.md` with detailed architecture documentation
- Updated `README.md` with new features and build instructions
- Created `firebase.md` with comprehensive Firebase security enhancement roadmap
- Added proper `.gitignore` for Go projects

### 🔄 Migration Notes
- **100% Backward Compatible**: All existing commands and functionality preserved
- **No Breaking Changes**: User experience remains identical
- **Same CLI Interface**: All command syntax and behavior unchanged
- **Feature Parity**: Every feature from monolithic version maintained

### 🧪 Testing
- All functionality verified against original implementation
- Build process tested across development environment
- Session management thoroughly tested
- Authentication flows validated

### 📦 Technical Details
- Go module structure with proper internal packages
- Dependency injection pattern for better testability
- Interface-based design for component boundaries
- Eliminated global state access between packages
- Improved code reusability and extensibility

---

## Previous Versions

### Initial Release
- Monolithic `firescan.go` implementation
- Core Firebase security scanning functionality
- Interactive console interface
- Authentication and scanning modules