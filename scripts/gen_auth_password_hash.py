#!/usr/bin/env python3
"""Generate AUTH_PASSWORD_HASH (Argon2id) for .env — run from repo root."""

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_password import hash_password  # noqa: E402


def main() -> None:
    if sys.stdin.isatty():
        pw = getpass.getpass('Senha / Password: ')
        pw2 = getpass.getpass('Confirmar / Confirm: ')
    else:
        pw = sys.stdin.readline().rstrip('\n')
        pw2 = pw
    if not pw:
        print('Empty password.', file=sys.stderr)
        sys.exit(1)
    if pw != pw2:
        print('Passwords do not match.', file=sys.stderr)
        sys.exit(1)
    print('Add to .env as AUTH_PASSWORD_HASH=<value below>')
    print(hash_password(pw))


if __name__ == '__main__':
    main()
