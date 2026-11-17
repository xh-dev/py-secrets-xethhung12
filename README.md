
# py_secrets_xethhung12

An encrypted key-value secret manager CLI and Python library using AES-256-GCM encryption, supporting OS keyring integration, direct CLI keys, and environment variables.

## Features

- **AES-256-GCM Encryption**: Authenticated encryption for storing key-value secrets securely in a base64-encoded file (default: `secrets.sec`).
- **Flexible Key Management**:
  - **OS Keyring (Default)**: Automatically generates and persists a 256-bit key in the system keyring (`service: py-secrets-service`, `user: master`).
  - **Direct Key (`-k`, `--key`)**: Supports 64-character hex strings, 44-character base64 strings, or arbitrary passphrases (derived via PBKDF2-HMAC-SHA256).
  - **Environment Variable**: Fallback support via `SECRETS_KEY`.
- **Full Secret Lifecycle**: View keys, view key-values, get, set (including hidden interactive prompt), delete, export to plaintext JSON, and import from JSON.
- **Python API**: Use directly in Python scripts to load, save, get, set, and delete secrets.

## Installation

```bash
pip install py-secrets-xethhung12
```

Or install from source:
```bash
pip install -e .
```

## CLI Usage

### Global Options

Options can be placed before or after subcommands:

- `-f`, `--file`, `--filename <path>`: Path to the encrypted secrets file (default: `./secrets.sec`).
- `-k`, `--key <key>`: Pass encryption key directly via CLI (cannot be combined with keyring flags).
- `--keyring [service]`: Enable OS keyring mode with an optional service name.
- `--keyring-service <service>`: OS keyring service name (default: `py-secrets-service`).
- `--keyring-user <user>`: OS keyring user name (default: `master`).

### Commands

#### Set a secret
Creates the secrets file (and generates a keyring key if needed) when setting a key for the first time. Omit the value to be prompted securely without echoing to the terminal:
```bash
py-secrets-xethhung12 set db_password
py-secrets-xethhung12 set db_password "super_secret_value"
py-secrets-xethhung12 -f ./my_secrets.sec set api_token "tok_12345"
```

#### Get a secret
```bash
py-secrets-xethhung12 get db_password
```

#### List all secret keys
```bash
py-secrets-xethhung12 view
```

#### List all secret keys and values
```bash
py-secrets-xethhung12 view-all
```

#### Delete a secret
```bash
py-secrets-xethhung12 delete db_password
```

#### Show encryption key stored in OS keyring
```bash
py-secrets-xethhung12 show-key
py-secrets-xethhung12 --keyring-service my-service --keyring-user my-user show-key
```

#### Export secrets to JSON
```bash
py-secrets-xethhung12 export -o secrets.json
```

#### Import secrets from JSON
```bash
py-secrets-xethhung12 import -i secrets.json
```

#### Check Keyring Status
Run with `--keyring` (or `--keyring-service` / `--keyring-user`) without a subcommand to inspect keyring configuration status:
```bash
py-secrets-xethhung12 --keyring
```

#### Using a custom key instead of OS keyring
```bash
py-secrets-xethhung12 -f ./custom.sec -k "my-passphrase" set api_key "12345"
py-secrets-xethhung12 -f ./custom.sec -k "my-passphrase" get api_key
```

### Help

```bash
py-secrets-xethhung12 -h
py-secrets-xethhung12 <command> -h
```

## Library Usage (Python API)

```python
from py_secrets_xethhung12 import (
    get_secret,
    set_secret,
    delete_secret,
    load_secrets,
    save_secrets,
)

# Set and get a secret (using default keyring and secrets file)
set_secret("api_key", "secret_123")
value = get_secret("api_key")

# Using a custom file path and explicit passphrase/key
set_secret("db_pass", "p@ssw0rd", file_path="app.sec", key="my-master-key")
db_pass = get_secret("db_pass", file_path="app.sec", key="my-master-key")

# Load all secrets as a dictionary
all_secrets = load_secrets(file_path="app.sec", key="my-master-key")

# Delete a secret
delete_secret("db_pass", file_path="app.sec", key="my-master-key")
```

## Running the Application

### Through Python module:
```bash
python -m py_secrets_xethhung12 -h
```

### Through installed script:
```bash
py-secrets-xethhung12 -h
```

## Development

The project requires `python` 3.11+ and `pip` for dependency management.

### Setup

Install development dependencies:
```bash
./install-dependencies.sh
```

This script installs:
- Dependencies from `dev-requirements.txt` (build and deployment tools)
- Dependencies from `requirements.txt` (runtime dependencies)

### Build

```bash
./build.sh
```

### Build and Deploy

```bash
./build-and-deploy.sh
```

## Scripts

| Name | Type | Description |
|------|------|-------------|
| install-dependencies.sh | Shell script | Install dev and runtime dependencies |
| build.sh | Shell script | Build the package |
| build-and-deploy.sh | Shell script | Build and deploy the package |
| export-deployment-keys.sh | Shell script | Export PyPI deployment token from Vault |

## Project Versioning

This project uses the [`xh-py-project-versioning`](https://github.com/xh-dev/xh-py-project-versioning) package for version management.

### Update Patch Version (dev):
```bash
python -m xh_py_project_versioning --patch
```
Example: `0.0.1` → `0.0.2-dev+000`

### Promote Dev to Official Release:
```bash
python -m xh_py_project_versioning -r
```
Example: `0.0.2-dev+000` → `0.0.2`

### Update Patch Version (direct):
```bash
python -m xh_py_project_versioning --patch -d
```
Example: `0.0.1` → `0.0.2`

### Update Minor Version (direct):
```bash
python -m xh_py_project_versioning --minor -d
```
Example: `0.0.1` → `0.1.0`

### Update Major Version (direct):
```bash
python -m xh_py_project_versioning --major -d
```
Example: `0.0.1` → `1.0.0`

## Dependencies

- **cryptography** - AES-256-GCM authenticated encryption and decryption
- **keyring** - Cross-platform system keyring access

## License

GPL-3.0-only

## Author

Xeth Hung (admin@xethh.me)

