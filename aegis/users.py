"""Manage operator accounts.

    python -m aegis.users add akshith --role analyst --name "Akshith"
    python -m aegis.users list
    python -m aegis.users remove akshith
"""

import argparse
import getpass
import sys

from . import auth


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m aegis.users", description="Manage AEGIS operator accounts.")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add", help="create or reset an account")
    add.add_argument("username")
    add.add_argument("--role", choices=list(auth.ROLES), required=True)
    add.add_argument("--name", help="display name shown in the console")
    sub.add_parser("list", help="list accounts")
    remove = sub.add_parser("remove", help="delete an account")
    remove.add_argument("username")
    args = parser.parse_args()

    if args.command == "add":
        password = getpass.getpass("Password (8+ characters): ")
        if password != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match.")
        try:
            user = auth.add_user(args.username, password, args.role, args.name)
        except ValueError as error:
            sys.exit(str(error))
        print(f"Saved {user['username']} ({user['role_label']}).")
    elif args.command == "list":
        for username, record in sorted(auth.load_users().items()):
            print(f"{username:<20} {auth.ROLES[record['role']]:<20} {record['name']}")
    elif args.command == "remove":
        print("Removed." if auth.remove_user(args.username) else "No such account.")


if __name__ == "__main__":
    main()
