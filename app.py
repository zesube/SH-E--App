import getpass
import hashlib
import os
import shutil
import subprocess
from pathlib import Path


USERS = {
    "admin": {
        "password_hash": hashlib.sha256("Admin123!".encode("utf-8")).hexdigest(),
        "role": "admin",
    },
    "student": {
        "password_hash": hashlib.sha256("Student123!".encode("utf-8")).hexdigest(),
        "role": "user",
    },
}


ROLE_PERMISSIONS = {
    "admin": {
        "hash_string",
        "hash_file",
        "cipher",
        "generate_keys",
        "sign_file",
        "verify_signature",
    },
    "user": {"hash_string", "cipher"},
}


BASE_DIR = Path(__file__).resolve().parent


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def hash_string(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as source:
        for chunk in iter(lambda: source.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift

    output = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            rotated = (ord(char) - base + shift) % 26
            output.append(chr(base + rotated))
        else:
            output.append(char)
    return "".join(output)


def require_openssl() -> str:
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        raise FileNotFoundError("OpenSSL is not installed or not available in PATH.")
    return openssl_path


def run_openssl_command(args):
    openssl_path = require_openssl()
    completed = subprocess.run(
        [openssl_path, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "Unknown OpenSSL error."
        raise RuntimeError(error_text)
    return completed.stdout.strip()


def generate_key_pair(private_key: Path, public_key: Path) -> None:
    run_openssl_command(["genpkey", "-algorithm", "RSA", "-out", str(private_key)])
    run_openssl_command(["rsa", "-pubout", "-in", str(private_key), "-out", str(public_key)])


def sign_file(input_file: Path, signature_file: Path, private_key: Path) -> None:
    run_openssl_command(
        [
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
            "-out",
            str(signature_file),
            str(input_file),
        ]
    )


def verify_signature(input_file: Path, signature_file: Path, public_key: Path) -> str:
    return run_openssl_command(
        [
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature_file),
            str(input_file),
        ]
    )


def login():
    print("Secure Coding Demo")
    print("Sample accounts:")
    print("  admin / Admin123!")
    print("  student / Student123!")
    print()

    for attempt in range(3):
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        user = USERS.get(username)

        if user and hash_string(password) == user["password_hash"]:
            print(f"\nLogin successful. Role: {user['role']}\n")
            return username, user["role"]

        print("Invalid username or password.\n")

    print("Too many failed login attempts.")
    return None, None


def show_menu(role: str) -> None:
    print("Choose an option:")
    print("  1. Generate SHA-256 hash for a string")
    print("  2. Encrypt text with Caesar cipher")
    print("  3. Decrypt text with Caesar cipher")
    if has_permission(role, "hash_file"):
        print("  4. Generate SHA-256 hash for a file")
    if has_permission(role, "generate_keys"):
        print("  5. Generate RSA key pair with OpenSSL")
    if has_permission(role, "sign_file"):
        print("  6. Sign a file with OpenSSL")
    if has_permission(role, "verify_signature"):
        print("  7. Verify a file signature with OpenSSL")
    print("  0. Exit")


def handle_hash_string():
    value = input("Enter text to hash: ")
    print(f"SHA-256: {hash_string(value)}\n")


def handle_hash_file():
    file_name = input("Enter the file path: ").strip()
    file_path = (BASE_DIR / file_name).resolve() if not os.path.isabs(file_name) else Path(file_name)

    if not file_path.exists() or not file_path.is_file():
        print("File not found.\n")
        return

    print(f"SHA-256: {hash_file(file_path)}\n")


def handle_cipher(decrypt: bool):
    text = input("Enter text: ")
    shift_text = input("Enter shift value: ").strip()

    try:
        shift = int(shift_text)
    except ValueError:
        print("Shift must be a whole number.\n")
        return

    result = caesar_cipher(text, shift, decrypt=decrypt)
    label = "Decrypted" if decrypt else "Encrypted"
    print(f"{label} text: {result}\n")


def handle_generate_keys():
    private_name = input("Private key file name [private_key.pem]: ").strip() or "private_key.pem"
    public_name = input("Public key file name [public_key.pem]: ").strip() or "public_key.pem"
    private_key = BASE_DIR / private_name
    public_key = BASE_DIR / public_name

    try:
        generate_key_pair(private_key, public_key)
        print(f"Private key saved to: {private_key}")
        print(f"Public key saved to:  {public_key}\n")
    except Exception as exc:
        print(f"Key generation failed: {exc}\n")


def handle_sign_file():
    input_name = input("File to sign: ").strip()
    private_name = input("Private key file [private_key.pem]: ").strip() or "private_key.pem"
    signature_name = input("Signature file [signature.sig]: ").strip() or "signature.sig"

    input_file = BASE_DIR / input_name
    private_key = BASE_DIR / private_name
    signature_file = BASE_DIR / signature_name

    if not input_file.exists() or not input_file.is_file():
        print("Input file not found.\n")
        return
    if not private_key.exists() or not private_key.is_file():
        print("Private key not found.\n")
        return

    try:
        sign_file(input_file, signature_file, private_key)
        print(f"Signature saved to: {signature_file}\n")
    except Exception as exc:
        print(f"Signing failed: {exc}\n")


def handle_verify_signature():
    input_name = input("File to verify: ").strip()
    public_name = input("Public key file [public_key.pem]: ").strip() or "public_key.pem"
    signature_name = input("Signature file [signature.sig]: ").strip() or "signature.sig"

    input_file = BASE_DIR / input_name
    public_key = BASE_DIR / public_name
    signature_file = BASE_DIR / signature_name

    if not input_file.exists() or not input_file.is_file():
        print("Input file not found.\n")
        return
    if not public_key.exists() or not public_key.is_file():
        print("Public key not found.\n")
        return
    if not signature_file.exists() or not signature_file.is_file():
        print("Signature file not found.\n")
        return

    try:
        result = verify_signature(input_file, signature_file, public_key)
        print(f"Verification result: {result}\n")
    except Exception as exc:
        print(f"Verification failed: {exc}\n")


def main():
    username, role = login()
    if not username:
        return

    actions = {
        "1": ("hash_string", handle_hash_string),
        "2": ("cipher", lambda: handle_cipher(decrypt=False)),
        "3": ("cipher", lambda: handle_cipher(decrypt=True)),
        "4": ("hash_file", handle_hash_file),
        "5": ("generate_keys", handle_generate_keys),
        "6": ("sign_file", handle_sign_file),
        "7": ("verify_signature", handle_verify_signature),
    }

    while True:
        show_menu(role)
        choice = input("Selection: ").strip()
        print()

        if choice == "0":
            print("Goodbye.")
            break

        action = actions.get(choice)
        if not action:
            print("Invalid option.\n")
            continue

        permission_name, handler = action
        if not has_permission(role, permission_name):
            print("Access denied for your role.\n")
            continue

        handler()


if __name__ == "__main__":
    main()
