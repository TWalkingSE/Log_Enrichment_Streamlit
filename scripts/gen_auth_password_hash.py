#!/usr/bin/env python3
"""Generate AUTH_PASSWORD_HASH (Argon2) for .env — run from repo root."""

import getpass
import sys

from passlib.hash import argon2


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
    print(argon2.hash(pw))


if __name__ == '__main__':
    main()
