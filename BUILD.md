# Build Instructions

## 🏗️ Architecture

FireScan has been refactored from a monolithic structure to a clean, modular architecture:

```
firescan/
├── cmd/firescan/main.go          # Application entry point
├── internal/
│   ├── types/types.go            # Shared types and constants
│   ├── auth/firebase.go          # Firebase authentication
│   ├── config/
│   │   ├── config.go            # Configuration management
│   │   └── session.go           # Session save/resume
│   ├── scanner/
│   │   ├── scanner.go           # Scanner coordination
│   │   ├── rtdb.go              # Realtime Database scanner
│   │   ├── firestore.go         # Firestore scanner
│   │   ├── functions.go         # Cloud Functions scanner
│   │   ├── storage.go           # Cloud Storage scanner
│   │   └── hosting.go           # Hosting scanner
│   ├── ui/
│   │   ├── commands.go          # Command handlers
│   │   ├── console.go           # Interactive console
│   │   └── output.go            # Output formatting
│   └── wordlist/wordlist.go     # Wordlist management
└── go.mod                       # Module definition
```

## 🔧 Building

### Prerequisites
- Go 1.21 or later
- Git

### Build from Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JacobDavidAlcock/firescan.git
   cd firescan
   ```

2. **Build the application:**
   ```bash
   go build -o firescan cmd/firescan/main.go
   ```

3. **Run the application:**
   ```bash
   ./firescan
   ```

### Cross-Platform Builds

Build for different platforms:

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o firescan.exe cmd/firescan/main.go

# Linux
GOOS=linux GOARCH=amd64 go build -o firescan-linux cmd/firescan/main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o firescan-darwin cmd/firescan/main.go
```

## 🧪 Development

### Running Tests
```bash
go test ./...
```

### Code Formatting
```bash
go fmt ./...
```

### Dependencies
All dependencies are managed via Go modules. To update:
```bash
go mod tidy
```

## 📦 Package Overview

### `internal/types`
Shared data structures and constants used across packages.

### `internal/auth`
Firebase authentication handling including:
- Account creation and login
- Email verification
- Token refresh
- Provider enumeration

### `internal/config`
Configuration and state management:
- Project settings (API key, project ID)
- Authentication state
- Session persistence

### `internal/scanner`
Security scanning modules:
- **rtdb.go**: Realtime Database enumeration
- **firestore.go**: Firestore collection scanning
- **functions.go**: Cloud Functions discovery
- **storage.go**: Cloud Storage bucket testing
- **hosting.go**: Firebase Hosting configuration checks

### `internal/ui`
User interface and interaction:
- Interactive console with tab completion
- Command parsing and handling
- Output formatting and display

### `internal/wordlist`
Wordlist management and generation:
- Built-in wordlists for different attack vectors
- Case variation generation
- Custom wordlist support

## 🔄 Migration from Monolithic

The refactoring maintains 100% backward compatibility. All commands, features, and behaviors remain identical to the original version while providing:

- **Better Maintainability**: Clear separation of concerns
- **Enhanced Testability**: Each package can be tested independently
- **Improved Extensibility**: Easy to add new scanners or features
- **Code Reusability**: Packages can be used in other Firebase security tools

## 🚧 Future Development

The modular architecture enables easy implementation of advanced features outlined in `firebase.md`:

- Security rules deep testing
- Additional Firebase services enumeration
- Enhanced authentication testing
- Write access testing
- Compliance reporting