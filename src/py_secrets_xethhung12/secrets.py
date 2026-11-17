#!/usr/bin/env python3
import os
import sys
import json
import base64
import hashlib
import getpass
import argparse
from pathlib import Path
from typing import Dict, Optional, Union

try:
    import keyring
except ImportError:
    keyring = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[!] Error: 'cryptography' package is required. Install it using: pip install cryptography", file=sys.stderr)
    sys.exit(1)


DEFAULT_KEYRING_SERVICE: str = "py-secrets-service"
DEFAULT_KEYRING_USER: str = "master"
DEFAULT_SECRETS_FILE: Path = Path.cwd() / "secrets.sec"
DEFAULT_KDF_SALT: bytes = b"py-secrets-xethhung12-kdf-salt-v1"
DEFAULT_KDF_ITERATIONS: int = 600_000


def _set_secure_file_permissions(path: Path) -> None:
    """Restrict file permissions to owner read/write (0o600) where supported."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _is_raw_encoded_key(key_input: str) -> Optional[bytes]:
    """Return 32 raw bytes if key_input is a valid 64-char hex or 44-char base64 key, else None."""
    key_str = key_input.strip()
    if len(key_str) == 64:
        try:
            return bytes.fromhex(key_str)
        except ValueError:
            pass

    if len(key_str) == 44 and key_str.endswith("="):
        try:
            decoded = base64.b64decode(key_str)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass

    return None


def _derive_legacy_sha256_key(key_input: str) -> bytes:
    """Legacy unsalted SHA-256 key derivation for backward compatibility."""
    return hashlib.sha256(key_input.strip().encode("utf-8")).digest()


def derive_aes_key(key_input: str, salt: bytes = DEFAULT_KDF_SALT) -> bytes:
    """
    Derive a 32-byte (256-bit) AES key from a string input.
    - If 64 hex characters: decodes as 32 raw bytes.
    - If 44 base64 characters: decodes as 32 raw bytes.
    - Otherwise (passphrase/word): derives 32 bytes via PBKDF2-HMAC-SHA256.
    """
    raw_bytes = _is_raw_encoded_key(key_input)
    if raw_bytes is not None:
        return raw_bytes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=DEFAULT_KDF_ITERATIONS,
    )
    return kdf.derive(key_input.strip().encode("utf-8"))


def resolve_key(
    key_arg: Optional[str] = None,
    keyring_service: Optional[str] = DEFAULT_KEYRING_SERVICE,
    keyring_user: Optional[str] = DEFAULT_KEYRING_USER,
    generate_if_missing: bool = False
) -> bytes:
    """
    Resolve the 256-bit AES key based on CLI arguments or environment:
    1. If key_arg is given (--key), derive 32-byte key directly.
    2. Otherwise, check OS keyring with keyring_service (default: py-secrets-service)
       and keyring_user (default: master).
    3. Fallback to SECRETS_KEY environment variable if keyring entry does not exist.
    4. Generate and persist a random 32-byte key in keyring if generate_if_missing=True.
    """
    # 1. Direct key
    if key_arg:
        return derive_aes_key(key_arg)

    env_key = os.environ.get("SECRETS_KEY")

    # 2. OS Keyring
    if keyring_service or keyring_user:
        if keyring is None:
            if env_key:
                return derive_aes_key(env_key)
            raise RuntimeError("'keyring' package is not installed. Install it with: pip install keyring")

        service_name = (keyring_service or "").strip() or DEFAULT_KEYRING_SERVICE
        user_name = (keyring_user or "").strip() or DEFAULT_KEYRING_USER

        try:
            stored_key = keyring.get_password(service_name, user_name)
        except Exception as e:
            if env_key:
                return derive_aes_key(env_key)
            raise RuntimeError(f"Failed to access system keyring: {e}") from e

        if stored_key:
            return derive_aes_key(stored_key)

        # 3. Fallback to SECRETS_KEY environment variable before generating or failing
        if env_key:
            return derive_aes_key(env_key)

        if generate_if_missing:
            raw_key = os.urandom(32)
            b64_key = base64.b64encode(raw_key).decode("utf-8")
            try:
                keyring.set_password(service_name, user_name, b64_key)
            except Exception as e:
                raise RuntimeError(f"Failed to persist key to system keyring: {e}") from e
            print(f"[i] Generated random 256-bit key and saved to keyring (service: '{service_name}', user: '{user_name}').")
            return raw_key

        raise KeyError(
            f"No encryption key found in keyring for service '{service_name}' and user '{user_name}'. "
            f"Run 'py-secrets-xethhung12 --keyring-service {service_name} --keyring-user {user_name} set <key> <value>' "
            f"to generate one, pass '--key <value>', or set SECRETS_KEY."
        )

    # 3. Environment variable (when keyring_service and keyring_user are both empty/None)
    if env_key:
        return derive_aes_key(env_key)

    raise ValueError(
        "Encryption key is required. Specify '--key <key>', '--keyring-service <service>', '--keyring-user <user>', or set SECRETS_KEY."
    )


def encrypt_secrets(data: Dict[str, str], key: bytes) -> str:
    """
    Encrypt a dictionary of secrets using AES-256-GCM.
    Returns the combined nonce + ciphertext encoded as a base64 string.
    """
    json_bytes = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json_bytes, None)
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt_secrets(b64_content: str, key: bytes) -> Dict[str, str]:
    """
    Decrypt a base64 string using AES-256-GCM and parse into a dictionary.
    """
    content_str = b64_content.strip()
    if not content_str:
        return {}

    try:
        payload = base64.b64decode(content_str)
    except Exception as e:
        raise ValueError(f"Corrupted base64 payload: {e}") from e

    if len(payload) < 28:
        raise ValueError("Invalid encrypted payload: data too short.")

    nonce = payload[:12]
    ciphertext = payload[12:]
    aesgcm = AESGCM(key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise PermissionError(
            "Decryption failed: Authentication tag mismatch. "
            "The key provided does not match this secrets file, or the file is corrupted."
        )

    try:
        parsed = json.loads(decrypted_bytes.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("Decrypted JSON is not a key-value dictionary.")
        return {str(k): str(v) for k, v in parsed.items()}
    except json.JSONDecodeError as e:
        raise ValueError(f"Decrypted data is not valid JSON: {e}") from e


def resolve_file_path(custom_path: Optional[Union[str, Path]]) -> Path:
    """Resolve destination secrets file path."""
    if custom_path:
        return Path(custom_path).resolve()
    return DEFAULT_SECRETS_FILE


def load_secrets(
    file_path: Optional[Union[str, Path]] = None,
    key: Optional[Union[str, bytes]] = None,
    keyring_service: Optional[str] = DEFAULT_KEYRING_SERVICE,
    keyring_user: Optional[str] = DEFAULT_KEYRING_USER,
    create_if_missing: bool = True
) -> Dict[str, str]:
    """
    Load and decrypt all secrets from file.
    If the file does not exist, automatically creates it with empty data ({}) inside.
    """
    target = resolve_file_path(file_path)

    if isinstance(key, bytes):
        key_bytes = key
        legacy_key_bytes = None
    elif key is not None:
        key_bytes = derive_aes_key(key)
        legacy_key_bytes = _derive_legacy_sha256_key(key) if _is_raw_encoded_key(key) is None else None
    else:
        key_bytes = resolve_key(
            key_arg=None,
            keyring_service=keyring_service,
            keyring_user=keyring_user,
            generate_if_missing=True if (create_if_missing and not target.is_file()) else False
        )
        legacy_key_bytes = None

    if not target.is_file():
        if create_if_missing:
            save_secrets(
                data={},
                file_path=target,
                key=key_bytes,
                keyring_service=keyring_service,
                keyring_user=keyring_user
            )
        return {}

    with open(target, "r", encoding="utf-8") as f:
        content = f.read()

    if not content.strip():
        if create_if_missing:
            save_secrets(
                data={},
                file_path=target,
                key=key_bytes,
                keyring_service=keyring_service,
                keyring_user=keyring_user
            )
        return {}

    try:
        return decrypt_secrets(content, key_bytes)
    except PermissionError:
        if legacy_key_bytes is not None:
            return decrypt_secrets(content, legacy_key_bytes)
        raise


def save_secrets(
    data: Dict[str, str],
    file_path: Optional[Union[str, Path]] = None,
    key: Optional[Union[str, bytes]] = None,
    keyring_service: Optional[str] = DEFAULT_KEYRING_SERVICE,
    keyring_user: Optional[str] = DEFAULT_KEYRING_USER
) -> None:
    """
    Encrypt and write secrets dictionary to file.
    """
    target = resolve_file_path(file_path)
    if isinstance(key, bytes):
        key_bytes = key
    elif key is not None:
        key_bytes = derive_aes_key(key)
    else:
        key_bytes = resolve_key(
            key_arg=None,
            keyring_service=keyring_service,
            keyring_user=keyring_user,
            generate_if_missing=True
        )

    b64_str = encrypt_secrets(data, key_bytes)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        f.write(b64_str + "\n")
    _set_secure_file_permissions(target)


def get_secret(
    key_name: str,
    default: Optional[str] = None,
    file_path: Optional[Union[str, Path]] = None,
    key: Optional[Union[str, bytes]] = None,
    keyring_service: Optional[str] = DEFAULT_KEYRING_SERVICE,
    keyring_user: Optional[str] = DEFAULT_KEYRING_USER
) -> Optional[str]:
    """Helper function to fetch a single secret by key name."""
    secrets = load_secrets(file_path, key=key, keyring_service=keyring_service, keyring_user=keyring_user)
    return secrets.get(key_name, default)


def set_secret(
    key_name: str,
    value: str,
    file_path: Optional[Union[str, Path]] = None,
    key: Optional[Union[str, bytes]] = None,
    keyring_service: Optional[str] = DEFAULT_KEYRING_SERVICE,
    keyring_user: Optional[str] = DEFAULT_KEYRING_USER
) -> None:
    """Helper function to set a single secret."""
    secrets = load_secrets(file_path, key=key, keyring_service=keyring_service, keyring_user=keyring_user)
    secrets[str(key_name)] = str(value)
    save_secrets(secrets, file_path, key=key, keyring_service=keyring_service, keyring_user=keyring_user)


def delete_secret(
    key_name: str,
    file_path: Optional[Union[str, Path]] = None,
    key: Optional[Union[str, bytes]] = None,
    keyring_service: Optional[str] = DEFAULT_KEYRING_SERVICE,
    keyring_user: Optional[str] = DEFAULT_KEYRING_USER
) -> bool:
    """Helper function to delete a single secret. Returns True if deleted, False if not found."""
    secrets = load_secrets(file_path, key=key, keyring_service=keyring_service, keyring_user=keyring_user)
    if key_name in secrets:
        del secrets[key_name]
        save_secrets(secrets, file_path, key=key, keyring_service=keyring_service, keyring_user=keyring_user)
        return True
    return False


# ---------------------------------------------------------------------------
# CLI Command Handlers
# ---------------------------------------------------------------------------

def get_cli_key(args: argparse.Namespace, generate_if_missing: bool = False) -> Union[bytes, str]:
    """Extract and resolve the encryption key from CLI arguments."""
    raw_args = getattr(args, "_raw_args", [])
    has_explicit_keyring = any(
        a in ("--keyring", "--keyring-service", "--keyring-user")
        or a.startswith(("--keyring=", "--keyring-service=", "--keyring-user="))
        for a in raw_args
    )

    if args.key and has_explicit_keyring:
        raise ValueError("Cannot specify both --key and keyring options (--keyring, --keyring-service, --keyring-user).")

    if args.key:
        return args.key

    keyring_service = args.keyring_service or args.keyring or DEFAULT_KEYRING_SERVICE
    keyring_user = args.keyring_user or DEFAULT_KEYRING_USER

    return resolve_key(
        key_arg=None,
        keyring_service=keyring_service,
        keyring_user=keyring_user,
        generate_if_missing=generate_if_missing
    )


def cmd_view(args: argparse.Namespace) -> None:
    """List all secret keys."""
    key_bytes = get_cli_key(args, generate_if_missing=False)
    secrets = load_secrets(args.file, key=key_bytes, create_if_missing=False)
    if not secrets:
        print("(No secrets found)")
        return

    for k in sorted(secrets.keys()):
        print(k)


def cmd_view_all(args: argparse.Namespace) -> None:
    """List all secret keys and their values."""
    key_bytes = get_cli_key(args, generate_if_missing=False)
    secrets = load_secrets(args.file, key=key_bytes, create_if_missing=False)
    if not secrets:
        print("(No secrets found)")
        return

    for k in sorted(secrets.keys()):
        print(f"{k} = {secrets[k]}")


def cmd_get(args: argparse.Namespace) -> None:
    """Get the value for a specific key."""
    key_bytes = get_cli_key(args, generate_if_missing=False)
    secrets = load_secrets(args.file, key=key_bytes, create_if_missing=False)
    if args.key_name not in secrets:
        print(f"[!] Error: Key '{args.key_name}' not found.", file=sys.stderr)
        sys.exit(1)

    print(secrets[args.key_name])


def cmd_set(args: argparse.Namespace) -> None:
    """Set or update a key-value pair."""
    secret_value = args.value
    if secret_value is None:
        secret_value = getpass.getpass(f"Enter secret value for '{args.key_name}': ")

    key_bytes = get_cli_key(args, generate_if_missing=True)
    secrets = load_secrets(args.file, key=key_bytes, create_if_missing=True)
    is_new = args.key_name not in secrets
    secrets[str(args.key_name)] = str(secret_value)
    save_secrets(secrets, args.file, key=key_bytes)

    action = "Created" if is_new else "Updated"
    print(f"[OK] {action} secret '{args.key_name}'.")


def cmd_delete(args: argparse.Namespace) -> None:
    """Delete a key-value pair."""
    key_bytes = get_cli_key(args, generate_if_missing=False)
    secrets = load_secrets(args.file, key=key_bytes, create_if_missing=False)
    if args.key_name not in secrets:
        print(f"[!] Error: Key '{args.key_name}' not found.", file=sys.stderr)
        sys.exit(1)

    del secrets[args.key_name]
    save_secrets(secrets, args.file, key=key_bytes)
    print(f"[OK] Deleted secret '{args.key_name}'.")


def cmd_show_key(args: argparse.Namespace) -> None:
    """Print the actual key value for the current keyring service and user."""
    if keyring is None:
        print("[!] Error: 'keyring' package is not installed. Install it with: pip install keyring", file=sys.stderr)
        sys.exit(1)

    service_name = (args.keyring_service or args.keyring or "").strip() or DEFAULT_KEYRING_SERVICE
    user_name = (args.keyring_user or "").strip() or DEFAULT_KEYRING_USER

    try:
        stored_key = keyring.get_password(service_name, user_name)
    except Exception as e:
        print(f"[!] Error accessing system keyring: {e}", file=sys.stderr)
        sys.exit(1)

    if not stored_key:
        print(f"[!] No key found in keyring for service '{service_name}' and user '{user_name}'.", file=sys.stderr)
        sys.exit(1)

    print(stored_key)


def cmd_export(args: argparse.Namespace) -> None:
    """Decrypt the secrets file and export it as formatted plaintext JSON."""
    key_bytes = get_cli_key(args, generate_if_missing=False)
    secrets = load_secrets(args.file, key=key_bytes, create_if_missing=False)

    json_str = json.dumps(secrets, indent=2, ensure_ascii=False)

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json_str + "\n")
    _set_secure_file_permissions(out_path)

    print(f"[OK] Exported {len(secrets)} secrets to '{out_path}'.")


def cmd_import(args: argparse.Namespace) -> None:
    """Import a JSON file of key-value pairs into the encrypted secrets file."""
    json_path = Path(args.input_file).resolve()
    if not json_path.is_file():
        print(f"[!] Error: Input JSON file not found: '{json_path}'.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading/parsing JSON file '{json_path}': {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print(f"[!] Error: JSON root in '{json_path}' must be an object/dictionary of key-value pairs.", file=sys.stderr)
        sys.exit(1)

    key_bytes = get_cli_key(args, generate_if_missing=True)
    secrets = load_secrets(args.file, key=key_bytes, create_if_missing=True)

    imported_count = 0
    for k, v in data.items():
        secrets[str(k)] = str(v)
        imported_count += 1

    save_secrets(secrets, args.file, key=key_bytes)
    print(f"[OK] Successfully imported {imported_count} secrets from '{json_path}' into '{resolve_file_path(args.file)}'.")


# ---------------------------------------------------------------------------
# Main CLI Parser & Normalizer
# ---------------------------------------------------------------------------

SUBCOMMANDS = {"view", "view-all", "get", "set", "delete", "show-key", "export", "import"}


def normalize_argv(argv: list[str]) -> list[str]:
    """
    Normalize command-line arguments to handle optional --keyring value
    and allow flags (--key, --keyring, --keyring-service, --keyring-user, --file, --filename)
    before or after subcommands.
    """
    pre_sub: list[str] = []
    post_sub: list[str] = []
    sub_found = False

    global_opts = ("--key", "-k", "--file", "-f", "--filename", "--keyring-service", "--keyring-user")
    global_eq_prefixes = ("--key=", "-k=", "--file=", "-f=", "--filename=", "--keyring-service=", "--keyring-user=")
    sub_opts = ("--output", "-o", "--input", "-i")
    sub_eq_prefixes = ("--output=", "-o=", "--input=", "-i=")

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("--help", "-h"):
            return argv

        if arg == "--keyring":
            # Check if next argument is a custom service name
            if i + 1 < len(argv) and argv[i + 1] not in SUBCOMMANDS and not argv[i + 1].startswith("-"):
                pre_sub.extend(["--keyring-service", argv[i + 1]])
                i += 2
                continue
            else:
                pre_sub.extend(["--keyring", DEFAULT_KEYRING_SERVICE])
                i += 1
                continue
        elif arg.startswith("--keyring="):
            val = arg.split("=", 1)[1] or DEFAULT_KEYRING_SERVICE
            pre_sub.extend(["--keyring-service", val])
            i += 1
            continue
        elif arg in sub_opts:
            # Subcommand-specific options (export -o output_file, import -i input_file)
            post_sub.append(arg)
            if i + 1 < len(argv):
                post_sub.append(argv[i + 1])
                i += 2
                continue
            i += 1
            continue
        elif arg.startswith(sub_eq_prefixes):
            post_sub.append(arg)
            i += 1
            continue
        elif arg in global_opts:
            if i + 1 < len(argv):
                pre_sub.extend([arg, argv[i + 1]])
                i += 2
                continue
        elif arg.startswith(global_eq_prefixes):
            pre_sub.append(arg)
            i += 1
            continue
        elif arg in SUBCOMMANDS:
            sub_found = True
            post_sub.append(arg)
            i += 1
            continue

        if sub_found:
            post_sub.append(arg)
        else:
            pre_sub.append(arg)
        i += 1

    return pre_sub + post_sub


def main():
    parser = argparse.ArgumentParser(
        prog="py-secrets-xethhung12",
        description="Encrypted secret manager using AES-256 (via CLI key or OS keyring)."
    )
    parser.add_argument(
        "--file",
        "--filename",
        "-f",
        dest="file",
        default=str(DEFAULT_SECRETS_FILE),
        help="Path or name of secrets file (default: ./secrets.sec)"
    )
    parser.add_argument(
        "--key",
        "-k",
        default=None,
        help="Pass encryption key directly via CLI"
    )
    parser.add_argument(
        "--keyring",
        default=None,
        help=f"Enable OS keyring mode (optional service name, default: {DEFAULT_KEYRING_SERVICE})"
    )
    parser.add_argument(
        "--keyring-service",
        default=DEFAULT_KEYRING_SERVICE,
        help=f"OS keyring service name (default: {DEFAULT_KEYRING_SERVICE})"
    )
    parser.add_argument(
        "--keyring-user",
        default=DEFAULT_KEYRING_USER,
        help=f"OS keyring user name (default: {DEFAULT_KEYRING_USER})"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="Commands",
        description="Available commands",
        help="Use 'py-secrets-xethhung12 <command> --help' for details on each command"
    )

    # Command: view
    sub_view = subparsers.add_parser("view", help="List all the keys")
    sub_view.set_defaults(func=cmd_view)

    # Command: view-all
    sub_view_all = subparsers.add_parser("view-all", help="List all the keys and values")
    sub_view_all.set_defaults(func=cmd_view_all)

    # Command: get
    sub_get = subparsers.add_parser("get", help="Get the value of a key")
    sub_get.add_argument("key_name", help="The secret key name")
    sub_get.set_defaults(func=cmd_get)

    # Command: set
    sub_set = subparsers.add_parser("set", help="Set key and value (prompts securely if value is omitted)")
    sub_set.add_argument("key_name", help="The secret key name")
    sub_set.add_argument("value", nargs="?", default=None, help="The secret value to store (omit to prompt securely)")
    sub_set.set_defaults(func=cmd_set)

    # Command: delete
    sub_delete = subparsers.add_parser("delete", help="Delete a key and its value")
    sub_delete.add_argument("key_name", help="The secret key name to delete")
    sub_delete.set_defaults(func=cmd_delete)

    # Command: show-key
    sub_show_key = subparsers.add_parser(
        "show-key",
        help="Print the actual encryption key value stored in the current keyring"
    )
    sub_show_key.set_defaults(func=cmd_show_key)

    # Command: export
    sub_export = subparsers.add_parser(
        "export",
        help="Decrypt and export secrets as formatted JSON"
    )
    sub_export.add_argument(
        "--output",
        "-o",
        required=True,
        help="Destination path for exported JSON file"
    )
    sub_export.set_defaults(func=cmd_export)

    # Command: import
    sub_import = subparsers.add_parser(
        "import",
        help="Load key-value pairs from a JSON file into secrets file"
    )
    sub_import.add_argument(
        "--input",
        "-i",
        dest="input_file",
        required=True,
        help="Path to JSON file containing key-value pairs to import"
    )
    sub_import.set_defaults(func=cmd_import)

    raw_args = sys.argv[1:]
    norm_args = normalize_argv(raw_args)
    args = parser.parse_args(norm_args)
    args._raw_args = raw_args

    # If keyring option was passed without a subcommand
    if not args.command:
        has_keyring_arg = any(
            a in ("--keyring", "--keyring-service", "--keyring-user")
            or a.startswith(("--keyring=", "--keyring-service=", "--keyring-user="))
            for a in raw_args
        )
        if has_keyring_arg:
            service_name = (args.keyring_service or args.keyring or "").strip() or DEFAULT_KEYRING_SERVICE
            user_name = (args.keyring_user or "").strip() or DEFAULT_KEYRING_USER
            has_key = False
            if keyring is not None:
                try:
                    has_key = keyring.get_password(service_name, user_name) is not None
                except Exception:
                    pass
            print(f"Keyring Service : {service_name}")
            print(f"Keyring User    : {user_name}")
            print(f"Key Status      : {'Configured in keyring' if has_key else 'Not generated yet'}")
            print("\nUsage:")
            print(f"  py-secrets-xethhung12 --keyring-service {service_name} --keyring-user {user_name} <command>")
            print("  Commands: view, view-all, get, set, delete, show-key, export, import")
            sys.exit(0)

        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()