#!/usr/bin/env python3
"""Testhelper CLI for VaultSandbox Python SDK interoperability testing."""

import asyncio
import json
import os
import sys

from vaultsandbox import ExportedInbox, VaultSandboxClient


async def create_inbox(client: VaultSandboxClient) -> None:
    """Create a new inbox and output export JSON."""
    inbox = await client.create_inbox()
    exported = inbox.export()
    # Convert to JSON-serializable dict with camelCase keys
    output = {
        "version": exported.version,
        "emailAddress": exported.email_address,
        "expiresAt": exported.expires_at,
        "inboxHash": exported.inbox_hash,
        "encrypted": exported.encrypted,
        "serverSigPk": exported.server_sig_pk,
        "secretKey": exported.secret_key,
        "exportedAt": exported.exported_at,
    }
    print(json.dumps(output))


async def import_inbox(client: VaultSandboxClient) -> None:
    """Import an inbox from stdin JSON."""
    data = json.loads(sys.stdin.read())

    # Convert camelCase to snake_case for Python SDK
    exported = ExportedInbox(
        version=data["version"],
        email_address=data["emailAddress"],
        expires_at=data["expiresAt"],
        inbox_hash=data["inboxHash"],
        server_sig_pk=data["serverSigPk"],
        secret_key=data["secretKey"],
        exported_at=data.get("exportedAt", ""),
    )

    await client.import_inbox(exported)
    print(json.dumps({"success": True}))


async def read_emails(client: VaultSandboxClient) -> None:
    """Import inbox and read all emails."""
    data = json.loads(sys.stdin.read())

    # Convert camelCase to snake_case for Python SDK
    exported = ExportedInbox(
        version=data["version"],
        email_address=data["emailAddress"],
        expires_at=data["expiresAt"],
        inbox_hash=data["inboxHash"],
        server_sig_pk=data["serverSigPk"],
        secret_key=data["secretKey"],
        exported_at=data.get("exportedAt", ""),
    )

    inbox = await client.import_inbox(exported)
    emails = await inbox.list_emails()

    output = {
        "emails": [
            {
                "id": email.id,
                "subject": email.subject,
                "from": email.from_address,
                "to": email.to,
                "text": email.text or "",
                "html": email.html or "",
                "attachments": [
                    {
                        "filename": att.filename,
                        "contentType": att.content_type,
                        "size": len(att.content) if att.content else 0,
                    }
                    for att in (email.attachments or [])
                ],
                "receivedAt": email.received_at.isoformat() if email.received_at else "",
            }
            for email in emails
        ]
    }

    print(json.dumps(output))


async def cleanup(client: VaultSandboxClient, address: str) -> None:
    """Delete an inbox."""
    await client.delete_inbox(address)
    print(json.dumps({"success": True}))


async def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("usage: testhelper.py <command> [args]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    async with VaultSandboxClient(
        base_url=os.environ["VAULTSANDBOX_URL"],
        api_key=os.environ["VAULTSANDBOX_API_KEY"],
    ) as client:
        if command == "create-inbox":
            await create_inbox(client)
        elif command == "import-inbox":
            await import_inbox(client)
        elif command == "read-emails":
            await read_emails(client)
        elif command == "cleanup":
            if len(sys.argv) < 3:
                print("usage: testhelper.py cleanup <address>", file=sys.stderr)
                sys.exit(1)
            await cleanup(client, sys.argv[2])
        else:
            print(f"unknown command: {command}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
