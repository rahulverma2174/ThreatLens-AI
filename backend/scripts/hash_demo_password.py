"""Generate a scrypt password hash for THREATLENS_DEMO_PASSWORD_HASH."""

import getpass

from app.auth import hash_password


def main() -> None:
    password = getpass.getpass("Demo password: ")
    confirmation = getpass.getpass("Confirm demo password: ")
    if not password or password != confirmation:
        raise SystemExit("Passwords must be non-empty and match.")
    print(hash_password(password))


if __name__ == "__main__":
    main()
