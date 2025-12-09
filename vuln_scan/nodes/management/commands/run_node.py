"""
Django management command to run the vuln_scan distributed node server.
Replaces running nodes/server.py directly.
"""

from django.core.management.base import BaseCommand
from django.conf import settings
import os
import sys


class Command(BaseCommand):
    help = "Run the vuln_scan distributed node server (replaces Flask nodes/server.py)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--port",
            type=int,
            default=int(os.getenv("PORT", 5000)),
            help="Port to listen on (default: 5000 or PORT env var)."
        )
        parser.add_argument(
            "--host",
            type=str,
            default="0.0.0.0",
            help="Host to bind to (default: 0.0.0.0)."
        )

    def handle(self, *args, **options):
        port = options["port"]
        host = options["host"]
        node_id = os.getenv("NODE_ID", "local")
        self.stdout.write(f"Starting vuln_scan node server on {host}:{port} (NODE_ID={node_id})")
        # Use Django's runserver for simplicity; for production, use gunicorn/uwsgi.
        from django.core.management import call_command
        call_command("runserver", f"{host}:{port}")
