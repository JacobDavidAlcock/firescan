<div align="center">
<pre>
███████╗██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ██║██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
</pre>
<h1>🔥 FireScan: The Firebase Security Auditor 🔥</h1>
<p>
<strong>A comprehensive, interactive console for auditing the security of Firebase applications.</strong>
</p>
<p>
<a href="https://github.com/JacobDavidAlcock/firescan/releases"><img src="https://img.shields.io/github/v/release/JacobDavidAlcock/firescan" alt="Release"></a>
<a href="https://github.com/JacobDavidAlcock/firescan/blob/main/LICENSE"><img src="https://img.shields.io/github/license/JacobDavidAlcock/firescan" alt="License"></a>
<a href="https://go.dev/"><img src="https://img.shields.io/badge/made%20with-Go-00ADD8.svg" alt="Made with Go"></a>
</p>
</div>

---

**FireScan** is a powerful security tool designed for penetration testers and developers to audit the security posture of Firebase applications. It provides an interactive console to enumerate databases, test storage rules, check function security, and much more, all from a single, easy-to-use interface.

## ✨ Features

- **Interactive Console:** A `msfconsole`-style interface with command history and tab-completion.
- **Automated Authentication:** Automatically create a test account or use your own credentials to get a session token.
- **Automatic Token Refresh:** Seamlessly refreshes expired JWTs during long scans.
- **Comprehensive Enumeration:**
  - **Realtime Database (RTDB):** Discovers readable nodes.
  - **Firestore:** Discovers readable collections.
  - **Cloud Storage:** Checks for listable storage buckets.
  - **Cloud Functions:** Enumerates and tests for publicly invokable functions.
  - **Hosting:** Checks for publicly exposed `firebase.json` configuration files.
- **Auth Provider Enumeration:** Probes the target to discover which authentication methods (Email/Password, Google, etc.) are enabled.
- **Data Extraction:** Dump the contents of any discovered readable database path or collection.
- **Intelligent Wordlists:** Comes with built-in, context-specific wordlists and automatically generates case variations (`users`, `Users`, `USERS`) for thorough testing.
- **Flexible Output:** Supports both human-readable and JSON output for easy integration with other tools.
- **Configuration Files:** Load target configurations from a YAML file for quick setup.

## 🚀 Getting Started

### Installation

You can install `firescan` in one of two ways:

**1. From Source (Recommended for Go users):**

```bash
go install [github.com/JacobDavidAlcock/firescan@latest](https://github.com/JacobDavidAlcock/firescan@latest)
```

**2. From Pre-compiled Binaries:**
Download the latest pre-compiled binary for your operating system from the [**Releases**](https://github.com/JacobDavidAlcock/firescan/releases) page.

### Quick Start

1.  **Launch the tool:**

    ```bash
    firescan
    ```

2.  **Set your target's Project ID and API Key:**

    ```
    firescan > set projectID your-project-id
    firescan > set apiKey your-web-api-key
    ```

    _(You can find these in the client-side `firebaseConfig` object of the target web application)._

3.  **Authenticate:** The easiest way is to let `firescan` create a test account.

    ```
    firescan > auth --create-account
    ```

4.  **Run a full scan:**
    ```
    firescan > scan --all
    ```

## 📖 Usage

`firescan` operates as an interactive console. Here are the main commands:

### `set <variable> <value>`

Sets a configuration variable for the current session.

- **Variables:** `projectID`, `apiKey`, `token`
- **Example:**
  ```
  firescan > set projectID my-cool-app-12345
  ```

### `show options`

Displays the current configuration.

### `auth`

Handles authentication to get a JWT.

- **Flags:**
  - `--create-account`: Creates/logs in with a default test account (`fire@scan.com`).
  - `-e <email> -P <password>`: Logs in with your own credentials.
  - `logout`: Clears the current session token.
  - `--enum-providers`: Probes the backend to discover which auth methods are enabled.
- **Example:**
  ```
  firescan > auth --enum-providers
  firescan > auth --create-account
  ```

### `scan`

Runs enumeration modules against the target.

- **Flags:**
  - `--all`: A shortcut to run all scan modules (`--rtdb`, `--firestore`, `--storage`, `--functions`, `--hosting`) with the `all` wordlist.
  - `--rtdb`: Scans for readable Realtime Database nodes.
  - `--firestore`: Scans for readable Firestore collections.
  - `--storage`: Checks for a listable Cloud Storage bucket.
  - `--functions`: Enumerates Cloud Functions.
  - `--hosting`: Checks for a public `firebase.json`.
  - `-l <list>`: Specifies a wordlist to use. Can be a built-in keyword (`users`, `config`, `all`, etc.) or a file path. Defaults to `all`.
  - `--json`: Outputs findings in JSON format.
- **Example:**
  ```
  firescan > scan --all
  firescan > scan --rtdb --firestore -l users
  ```

### `extract`

Dumps data from a readable database path.

- **Flags:**
  - `--rtdb --path <node_path>`: Dumps data from a Realtime Database node.
  - `--firestore --path <collection_path>`: Dumps all documents from a Firestore collection.
- **Example:**
  ```
  firescan > extract --firestore --path Users
  ```

### `wordlist`

Manages wordlists for the current session.

- **Commands:**
  - `show`: Lists the names of all available built-in wordlists.
  - `show <name>`: Shows the contents of a specific list.
  - `add <name> <word1,word2,...>`: Creates a new wordlist for the current session.
- **Example:**
  ```
  firescan > wordlist show
  firescan > wordlist add custom users,config,settings
  firescan > scan -l custom
  ```

### `make-config`

Prints an example `config.yaml` file that you can use to quickly load settings at startup.

- **Example:**
  ```
  firescan > make-config > my_project.yaml
  # Then launch with:
  ./firescan --config my_project.yaml
  ```

## ⚖️ License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/JacobDavidAlcock/firescan/issues).
