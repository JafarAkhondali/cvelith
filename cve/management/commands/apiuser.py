"""
Manage API users and their tokens.

The API uses DRF token auth and has no sign-up endpoint, so accounts are created here.

    python manage.py apiuser create alice              # prompts for a password, prints a token
    python manage.py apiuser create bot --token-only   # no password (can't use the web login), token only
    python manage.py apiuser list
    python manage.py apiuser token alice [--rotate]    # show (or replace) the token
    python manage.py apiuser revoke alice              # delete the token (user logs in again for a new one)
    python manage.py apiuser password alice            # set a new password
    python manage.py apiuser delete alice
"""
import getpass
import sys

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    help = "Create and manage API users and their access tokens."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)

        p = sub.add_parser("create", help="Create a user and print its API token.")
        p.add_argument("username")
        p.add_argument("--email", default="")
        p.add_argument("--token-only", action="store_true",
                       help="No password: the account can only use its token (not the web login).")
        p.add_argument("--password-stdin", action="store_true",
                       help="Read the password from stdin instead of prompting (for scripts).")
        p.add_argument("--superuser", action="store_true", help="Also grant staff/superuser flags.")

        sub.add_parser("list", help="List users and whether they have a token.")

        p = sub.add_parser("token", help="Print a user's token, creating one if missing.")
        p.add_argument("username")
        p.add_argument("--rotate", action="store_true", help="Delete the old token and issue a new one.")

        p = sub.add_parser("revoke", help="Delete a user's token.")
        p.add_argument("username")

        p = sub.add_parser("password", help="Set a user's password.")
        p.add_argument("username")
        p.add_argument("--password-stdin", action="store_true")

        p = sub.add_parser("delete", help="Delete a user and its token.")
        p.add_argument("username")

    # -- helpers ---------------------------------------------------------------

    def _user(self, username):
        User = get_user_model()
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User '{username}' does not exist.")

    def _read_password(self, user, from_stdin):
        if from_stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass("Password: ")
            if password != getpass.getpass("Password (again): "):
                raise CommandError("Passwords do not match.")
        if not password:
            raise CommandError("Password must not be empty.")
        try:
            validate_password(password, user)
        except ValidationError as e:
            raise CommandError("Password rejected: " + " ".join(e.messages))
        return password

    def _print_token(self, user, token):
        self.stdout.write(self.style.SUCCESS(f"Token for '{user.username}':"))
        # Token alone on its own line, so scripts can capture it with `tail -1`.
        self.stdout.write(token.key)

    # -- actions ---------------------------------------------------------------

    def handle(self, *args, **opts):
        getattr(self, f"do_{opts['action']}")(opts)

    @transaction.atomic
    def do_create(self, opts):
        User = get_user_model()
        username = opts["username"]
        if User.objects.filter(username=username).exists():
            raise CommandError(f"User '{username}' already exists. Use `apiuser token {username}`.")
        user = User(username=username, email=opts["email"])
        if opts["superuser"]:
            user.is_staff = user.is_superuser = True
        if opts["token_only"]:
            user.set_unusable_password()
        else:
            user.set_password(self._read_password(user, opts["password_stdin"]))
        user.save()
        token = Token.objects.create(user=user)
        self._print_token(user, token)

    def do_list(self, opts):
        User = get_user_model()
        users = User.objects.order_by("username").select_related("auth_token")
        if not users:
            self.stdout.write("No users.")
            return
        self.stdout.write(f"{'username':<24} {'token':<6} {'password':<9} {'superuser':<9} last_login")
        for u in users:
            has_token = Token.objects.filter(user=u).exists()
            self.stdout.write(
                f"{u.username:<24} {'yes' if has_token else 'no':<6} "
                f"{'yes' if u.has_usable_password() else 'no':<9} "
                f"{'yes' if u.is_superuser else 'no':<9} {u.last_login or '-'}"
            )

    @transaction.atomic
    def do_token(self, opts):
        user = self._user(opts["username"])
        if opts["rotate"]:
            Token.objects.filter(user=user).delete()
        token, _ = Token.objects.get_or_create(user=user)
        self._print_token(user, token)

    def do_revoke(self, opts):
        user = self._user(opts["username"])
        deleted, _ = Token.objects.filter(user=user).delete()
        self.stdout.write(self.style.SUCCESS(
            f"Revoked token for '{user.username}'." if deleted else f"'{user.username}' had no token."))

    def do_password(self, opts):
        user = self._user(opts["username"])
        user.set_password(self._read_password(user, opts["password_stdin"]))
        user.save(update_fields=["password"])
        self.stdout.write(self.style.SUCCESS(f"Password updated for '{user.username}'."))

    def do_delete(self, opts):
        user = self._user(opts["username"])
        user.delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted '{opts['username']}'."))
