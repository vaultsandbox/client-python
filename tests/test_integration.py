"""Integration tests for VaultSandbox SDK using real server.

These tests connect to a real VaultSandbox server and send actual emails
via SMTP to test the complete email workflow.

Requirements:
- .env file with VAULTSANDBOX_URL, VAULTSANDBOX_API_KEY, SMTP_HOST, SMTP_PORT
- Network access to the VaultSandbox server and SMTP port

Note on authentication results:
When sending emails directly to the SMTP server (not through a proper mail
infrastructure), SPF and DKIM will NOT pass because:
- SPF: The sending IP is not authorized in the sender domain's SPF record
- DKIM: Emails are not signed with the domain's DKIM key
Tests verify these expected failures.
"""

import asyncio
import contextlib
import os
import re
import smtplib
import uuid
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest
from dotenv import load_dotenv

from vaultsandbox import VaultSandboxClient, WaitForEmailOptions
from vaultsandbox.types import (
    CreateInboxOptions,
    DKIMStatus,
    DMARCStatus,
    SPFStatus,
    WaitForCountOptions,
)

# Load environment variables
load_dotenv()


def get_env_or_skip(name: str) -> str:
    """Get environment variable or skip test if not set."""
    value = os.getenv(name)
    if not value:
        pytest.skip(f"{name} environment variable not set")
    return value


@pytest.fixture(scope="module")
def smtp_config() -> dict[str, str | int]:
    """Get SMTP configuration from environment."""
    return {
        "host": get_env_or_skip("SMTP_HOST"),
        "port": int(os.getenv("SMTP_PORT", "25")),
    }


@pytest.fixture(scope="module")
def api_config() -> dict[str, str]:
    """Get API configuration from environment."""
    return {
        "api_key": get_env_or_skip("VAULTSANDBOX_API_KEY"),
        "base_url": get_env_or_skip("VAULTSANDBOX_URL"),
    }


def send_email(
    smtp_host: str,
    smtp_port: int,
    to_address: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
    from_address: str = "test@example.com",
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> None:
    """Send an email via SMTP.

    Args:
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port.
        to_address: Recipient email address.
        subject: Email subject.
        body_text: Plain text body.
        body_html: Optional HTML body.
        from_address: Sender email address.
        attachments: Optional list of (filename, content, content_type) tuples.
    """
    if body_html or attachments:
        msg = MIMEMultipart("alternative" if body_html and not attachments else "mixed")
        msg.attach(MIMEText(body_text, "plain"))
        if body_html:
            msg.attach(MIMEText(body_html, "html"))
        if attachments:
            for filename, content, content_type in attachments:
                maintype, subtype = content_type.split("/", 1)
                part = MIMEBase(maintype, subtype)
                part.set_payload(content)
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=filename,
                )
                msg.attach(part)
    else:
        msg = MIMEText(body_text, "plain")

    msg["Subject"] = subject
    msg["From"] = from_address
    msg["To"] = to_address

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.sendmail(from_address, [to_address], msg.as_string())


class TestServerConnection:
    """Tests for basic server connectivity."""

    @pytest.mark.asyncio
    async def test_check_api_key(self, api_config: dict[str, str]) -> None:
        """Test that API key validation works."""
        async with VaultSandboxClient(**api_config) as client:
            is_valid = await client.check_key()
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_get_server_info(self, api_config: dict[str, str]) -> None:
        """Test that server info can be retrieved."""
        async with VaultSandboxClient(**api_config) as client:
            server_info = await client.get_server_info()
            assert server_info.server_sig_pk is not None
            assert len(server_info.algs) > 0
            assert server_info.max_ttl > 0
            assert server_info.default_ttl > 0
            assert len(server_info.allowed_domains) > 0

    @pytest.mark.asyncio
    async def test_invalid_api_key(self, api_config: dict[str, str]) -> None:
        """Test that invalid API key is rejected."""
        from vaultsandbox.errors import ApiError

        async with VaultSandboxClient(
            api_key="invalid-key",
            base_url=api_config["base_url"],
        ) as client:
            # The API throws an error for invalid keys rather than returning False
            with pytest.raises(ApiError) as exc_info:
                await client.check_key()
            assert exc_info.value.status_code == 401


class TestInboxLifecycle:
    """Tests for inbox creation, listing, and deletion."""

    @pytest.mark.asyncio
    async def test_create_inbox(self, api_config: dict[str, str]) -> None:
        """Test creating an inbox."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            assert inbox.email_address is not None
            assert "@" in inbox.email_address
            assert inbox.expires_at is not None
            assert inbox.inbox_hash is not None

    @pytest.mark.asyncio
    async def test_create_inbox_with_ttl(self, api_config: dict[str, str]) -> None:
        """Test creating an inbox with custom TTL."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox(
                CreateInboxOptions(ttl=300)  # 5 minutes
            )
            assert inbox.email_address is not None
            # Inbox should be created successfully with custom TTL

    @pytest.mark.asyncio
    async def test_create_inbox_with_email_auth_disabled(self, api_config: dict[str, str]) -> None:
        """Test creating an inbox with email authentication disabled."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox(CreateInboxOptions(email_auth=False))
            assert inbox.email_address is not None
            # Inbox should be created successfully with email auth disabled

    @pytest.mark.asyncio
    async def test_delete_inbox(self, api_config: dict[str, str]) -> None:
        """Test deleting an inbox."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Delete the inbox
            await inbox.delete()

            # Inbox should no longer be accessible (would need to verify via list)


class TestEmailReceiving:
    """Tests for receiving and reading emails."""

    @pytest.mark.asyncio
    async def test_receive_simple_email(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test receiving a simple text email."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Test Email {unique_id}"
        body = f"This is a test email body. ID: {unique_id}"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send email
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text=body,
            )

            # Wait for email
            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email is not None
            assert email.subject == subject
            assert unique_id in (email.text or "")
            assert email.from_address == "test@example.com"

    @pytest.mark.asyncio
    async def test_receive_html_email(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test receiving an email with HTML body."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"HTML Test Email {unique_id}"
        body_text = f"Plain text version. ID: {unique_id}"
        body_html = f"<html><body><h1>HTML Test</h1><p>ID: {unique_id}</p></body></html>"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send email
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
            )

            # Wait for email
            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email is not None
            assert email.subject == subject
            assert email.html is not None
            assert unique_id in email.html
            assert email.text is not None
            assert unique_id in email.text

    @pytest.mark.asyncio
    async def test_receive_email_with_attachment(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test receiving an email with an attachment."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Attachment Test Email {unique_id}"
        body = f"Email with attachment. ID: {unique_id}"

        # Create a simple text file attachment
        attachment_content = f"Attachment content for {unique_id}".encode()
        attachment_filename = "test.txt"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send email with attachment
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text=body,
                attachments=[(attachment_filename, attachment_content, "text/plain")],
            )

            # Wait for email
            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email is not None
            assert email.subject == subject
            assert len(email.attachments) >= 1

            # Find our attachment
            attachment = next(
                (a for a in email.attachments if a.filename == attachment_filename),
                None,
            )
            assert attachment is not None
            assert attachment.content == attachment_content
            assert attachment.content_type == "text/plain"

    @pytest.mark.asyncio
    async def test_list_emails(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test listing all emails in an inbox."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send multiple emails
            for i in range(3):
                send_email(
                    smtp_host=str(smtp_config["host"]),
                    smtp_port=int(smtp_config["port"]),
                    to_address=inbox.email_address,
                    subject=f"List Test {unique_id} - Email {i + 1}",
                    body_text=f"Body {i + 1}",
                )

            # Wait for all emails to arrive
            await inbox.wait_for_email_count(3, WaitForCountOptions(timeout=30000))

            # List emails
            emails = await inbox.list_emails()
            assert len(emails) >= 3

    @pytest.mark.asyncio
    async def test_mark_email_as_read(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test marking an email as read."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Read Test {unique_id}"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text="Test body",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.is_read is False

            await email.mark_as_read()

            # Fetch the email again to verify
            updated_email = await inbox.get_email(email.id)
            assert updated_email.is_read is True

    @pytest.mark.asyncio
    async def test_delete_email(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test deleting an email."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Delete Test {unique_id}"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text="Test body",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            email_id = email.id

            # Delete the email
            await email.delete()

            # Verify email count decreased
            emails = await inbox.list_emails()
            assert all(e.id != email_id for e in emails)


class TestEmailFiltering:
    """Tests for email filtering options."""

    @pytest.mark.asyncio
    async def test_filter_by_subject_string(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test filtering emails by subject string."""
        unique_id = str(uuid.uuid4())[:8]
        target_subject = f"Target Subject {unique_id}"
        other_subject = f"Other Subject {unique_id}"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send other email first
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=other_subject,
                body_text="Other body",
            )

            # Send target email
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=target_subject,
                body_text="Target body",
            )

            # Wait for specific email by subject
            email = await inbox.wait_for_email(
                WaitForEmailOptions(
                    subject="Target Subject",
                    timeout=30000,
                )
            )

            assert email is not None
            assert "Target Subject" in email.subject

    @pytest.mark.asyncio
    async def test_filter_by_subject_regex(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test filtering emails by subject regex pattern."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Order #12345 Confirmation {unique_id}"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text="Order details",
            )

            # Wait using regex pattern
            email = await inbox.wait_for_email(
                WaitForEmailOptions(
                    subject=re.compile(r"Order #\d+ Confirmation"),
                    timeout=30000,
                )
            )

            assert email is not None
            assert "Order #12345 Confirmation" in email.subject

    @pytest.mark.asyncio
    async def test_filter_by_from_address(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test filtering emails by sender address."""
        unique_id = str(uuid.uuid4())[:8]
        target_sender = f"target-{unique_id}@example.com"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send from other address
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"From Other {unique_id}",
                body_text="Other body",
                from_address="other@example.com",
            )

            # Send from target address
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"From Target {unique_id}",
                body_text="Target body",
                from_address=target_sender,
            )

            # Wait for email from specific sender
            email = await inbox.wait_for_email(
                WaitForEmailOptions(
                    from_address=target_sender,
                    timeout=30000,
                )
            )

            assert email is not None
            assert email.from_address == target_sender

    @pytest.mark.asyncio
    async def test_filter_by_predicate(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test filtering emails using a custom predicate function."""
        unique_id = str(uuid.uuid4())[:8]
        magic_word = f"MAGIC-{unique_id}"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send email without magic word
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Without Magic {unique_id}",
                body_text="Normal body",
            )

            # Send email with magic word in body
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"With Magic {unique_id}",
                body_text=f"Body contains {magic_word} here",
            )

            # Wait for email matching predicate
            email = await inbox.wait_for_email(
                WaitForEmailOptions(
                    predicate=lambda e: magic_word in (e.text or ""),
                    timeout=30000,
                )
            )

            assert email is not None
            assert magic_word in (email.text or "")


class TestAuthenticationResults:
    """Tests for email authentication (SPF, DKIM, DMARC) validation.

    When sending emails directly to the SMTP server without proper mail
    infrastructure, SPF and DKIM are expected to fail because:
    - SPF: Our IP is not in the sender domain's SPF record
    - DKIM: We don't sign emails with the domain's DKIM key
    """

    @pytest.mark.asyncio
    async def test_auth_results_present(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test that authentication results are present on received emails."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Auth Test {unique_id}",
                body_text="Test body",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results is not None

    @pytest.mark.asyncio
    async def test_spf_fails_for_direct_send(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test that SPF fails when sending directly (expected behavior).

        When we send directly to the SMTP server, our IP is not authorized
        in example.com's SPF record, so SPF should fail or softfail.
        """
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"SPF Test {unique_id}",
                body_text="Test body",
                from_address="test@example.com",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # SPF should NOT pass since we're not authorized to send for example.com
            if email.auth_results.spf:
                assert email.auth_results.spf.result != SPFStatus.PASS, (
                    "SPF should not pass when sending directly without authorization"
                )

    @pytest.mark.asyncio
    async def test_dkim_fails_for_direct_send(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test that DKIM fails when sending directly (expected behavior).

        When we send directly without signing, DKIM should fail or be none.
        """
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"DKIM Test {unique_id}",
                body_text="Test body",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # DKIM should NOT pass since we didn't sign the email
            for dkim_result in email.auth_results.dkim:
                assert dkim_result.result != DKIMStatus.PASS, (
                    "DKIM should not pass when sending unsigned emails"
                )

    @pytest.mark.asyncio
    async def test_auth_validation_for_direct_send(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test auth validation behavior for directly sent emails.

        When sending directly without proper mail infrastructure, validation
        requires explicit 'pass' status - 'none' is NOT considered passing.
        This means directly sent emails will typically fail validation since:
        - SPF: Not authorized to send for the domain
        - DKIM: Email not signed with domain's DKIM key
        - DMARC: Depends on SPF and DKIM
        """
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Validation Test {unique_id}",
                body_text="Test body",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()

            # Verify individual pass flags are consistent with 'pass' or 'skipped' result
            # (skipped is treated as passing since auth checks were disabled)
            expected_spf_passed = (
                email.auth_results.spf is not None
                and email.auth_results.spf.result in (SPFStatus.PASS, SPFStatus.SKIPPED)
            )
            expected_dkim_passed = (
                (
                    any(d.result == DKIMStatus.PASS for d in email.auth_results.dkim)
                    or all(d.result == DKIMStatus.SKIPPED for d in email.auth_results.dkim)
                )
                if email.auth_results.dkim
                else False
            )
            expected_dmarc_passed = (
                email.auth_results.dmarc is not None
                and email.auth_results.dmarc.result in (DMARCStatus.PASS, DMARCStatus.SKIPPED)
            )

            assert validation.spf_passed == expected_spf_passed
            assert validation.dkim_passed == expected_dkim_passed
            assert validation.dmarc_passed == expected_dmarc_passed

            # Overall passed flag is SPF AND DKIM AND DMARC (not reverse DNS)
            expected_passed = expected_spf_passed and expected_dkim_passed and expected_dmarc_passed
            assert validation.passed == expected_passed, (
                f"Validation result inconsistent: passed={validation.passed}, "
                f"expected={expected_passed}, "
                f"spf_passed={validation.spf_passed}, dkim_passed={validation.dkim_passed}, "
                f"dmarc_passed={validation.dmarc_passed}"
            )


class TestInboxMonitor:
    """Tests for monitoring multiple inboxes."""

    @pytest.mark.asyncio
    async def test_monitor_single_inbox(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test monitoring a single inbox for new emails."""
        unique_id = str(uuid.uuid4())[:8]
        received_emails: list = []

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Set up monitor
            monitor = client.monitor_inboxes([inbox])
            monitor.on_email(lambda inbox, email: received_emails.append(email))
            await monitor.start()

            # Give monitor time to establish connection
            await asyncio.sleep(1)

            # Send email
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Monitor Test {unique_id}",
                body_text="Test body",
            )

            # Wait for email to be received via monitor
            for _ in range(30):
                if received_emails:
                    break
                await asyncio.sleep(1)

            await monitor.unsubscribe()

            assert len(received_emails) >= 1
            assert unique_id in received_emails[0].subject

    @pytest.mark.asyncio
    async def test_monitor_multiple_inboxes(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test monitoring multiple inboxes simultaneously."""
        unique_id = str(uuid.uuid4())[:8]
        received_emails: list = []

        async with VaultSandboxClient(**api_config) as client:
            inbox1 = await client.create_inbox()
            inbox2 = await client.create_inbox()

            # Set up monitor for both inboxes
            monitor = client.monitor_inboxes([inbox1, inbox2])
            monitor.on_email(lambda inbox, email: received_emails.append(email))
            await monitor.start()

            await asyncio.sleep(1)

            # Send email to each inbox
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox1.email_address,
                subject=f"Monitor Multi 1 - {unique_id}",
                body_text="Body 1",
            )

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox2.email_address,
                subject=f"Monitor Multi 2 - {unique_id}",
                body_text="Body 2",
            )

            # Wait for both emails
            for _ in range(30):
                if len(received_emails) >= 2:
                    break
                await asyncio.sleep(1)

            await monitor.unsubscribe()

            assert len(received_emails) >= 2
            subjects = [e.subject for e in received_emails]
            assert any("Multi 1" in s for s in subjects)
            assert any("Multi 2" in s for s in subjects)


class TestRawEmail:
    """Tests for raw email access."""

    @pytest.mark.asyncio
    async def test_get_raw_email(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test retrieving raw email MIME source."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Raw Email Test {unique_id}"
        body_text = "Test body for raw email"
        from_address = "test@example.com"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text=body_text,
                from_address=from_address,
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            raw_email = await email.get_raw()

            assert raw_email is not None
            assert raw_email.id == email.id
            assert len(raw_email.raw) > 0
            # Raw email should contain MIME headers and content
            # These checks ensure the content is properly decoded (not double base64 encoded)
            assert "Subject:" in raw_email.raw, "Missing Subject header"
            assert unique_id in raw_email.raw, "Missing unique ID in subject"
            assert "From:" in raw_email.raw, "Missing From header"
            assert from_address in raw_email.raw, f"Missing sender {from_address}"
            assert "To:" in raw_email.raw, "Missing To header"
            assert inbox.email_address in raw_email.raw, "Missing recipient address"
            assert body_text in raw_email.raw, "Missing body text"

    @pytest.mark.asyncio
    async def test_get_raw_email_plain_inbox(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test retrieving raw email MIME source from plain (unencrypted) inbox."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Plain Raw Email Test {unique_id}"
        body_text = "Test body for plain inbox raw email"
        from_address = "test@example.com"

        async with VaultSandboxClient(**api_config) as client:
            # Create plain (unencrypted) inbox
            inbox = await client.create_inbox(CreateInboxOptions(encryption="plain"))
            assert inbox.encrypted is False, "Inbox should be plain (unencrypted)"

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text=body_text,
                from_address=from_address,
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            raw_email = await email.get_raw()

            assert raw_email is not None
            assert raw_email.id == email.id
            assert len(raw_email.raw) > 0
            # Raw email should contain MIME headers and content
            # These checks ensure the content is properly decoded (not double base64 encoded)
            assert "Subject:" in raw_email.raw, "Missing Subject header"
            assert unique_id in raw_email.raw, "Missing unique ID in subject"
            assert "From:" in raw_email.raw, "Missing From header"
            assert from_address in raw_email.raw, f"Missing sender {from_address}"
            assert "To:" in raw_email.raw, "Missing To header"
            assert inbox.email_address in raw_email.raw, "Missing recipient address"
            assert body_text in raw_email.raw, "Missing body text"


class TestExportImport:
    """Tests for inbox export and import functionality."""

    @pytest.mark.asyncio
    async def test_export_and_import_inbox(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test exporting and importing an inbox.

        Note: This test manually manages the client lifecycle to prevent
        auto-deletion of the inbox when the first client closes.
        """
        unique_id = str(uuid.uuid4())[:8]

        # Create first client - don't use context manager to avoid auto-cleanup
        client1 = VaultSandboxClient(**api_config)

        try:
            # Create inbox and send an email
            inbox = await client1.create_inbox()
            original_address = inbox.email_address

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Export Test {unique_id}",
                body_text="Test body",
            )

            await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # Export the inbox (this saves keypair info for later use)
            exported = client1.export_inbox(inbox)

            assert exported.version == 1  # Per spec Section 9.3
            assert exported.email_address == original_address
            assert exported.secret_key is not None  # base64url encoded

            # Close the API client but don't delete the inbox
            # (manually close without calling close() which deletes inboxes)
            await client1._api_client.close()
            if client1._strategy:
                await client1._strategy.close()

        except Exception:
            # On error, try to clean up
            with contextlib.suppress(Exception):
                await client1.close()
            raise

        # Import in a new client session
        async with VaultSandboxClient(**api_config) as client2:
            imported_inbox = await client2.import_inbox(exported)

            assert imported_inbox.email_address == original_address

            # Should be able to list emails from imported inbox
            emails = await imported_inbox.list_emails()
            assert len(emails) >= 1
            assert any(unique_id in e.subject for e in emails)


class TestServerInfoAlgorithms:
    """Tests for server info algorithm values."""

    @pytest.mark.asyncio
    async def test_server_info_algorithm_values(self, api_config: dict[str, str]) -> None:
        """Check returned algorithms match expected values."""
        async with VaultSandboxClient(**api_config) as client:
            info = await client.get_server_info()
            # Check all required algorithms are present (algs is a dict)
            assert info.algs.get("kem") == "ML-KEM-768"
            assert info.algs.get("sig") == "ML-DSA-65"
            assert info.algs.get("aead") == "AES-256-GCM"
            assert info.algs.get("kdf") == "HKDF-SHA-512"


class TestClientClose:
    """Tests for client close behavior."""

    @pytest.mark.asyncio
    async def test_graceful_close(self, api_config: dict[str, str]) -> None:
        """Close client after operations without errors."""
        client = VaultSandboxClient(**api_config)
        # Creating an inbox triggers auto-initialization
        await client.create_inbox()
        await client.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_close_with_active_subscriptions(
        self,
        api_config: dict[str, str],
    ) -> None:
        """Close with active subscriptions cleans them up."""
        client = VaultSandboxClient(**api_config)
        # Creating an inbox triggers auto-initialization
        inbox = await client.create_inbox()
        # Start monitoring
        monitor = client.monitor_inboxes([inbox])
        await monitor.start()
        await client.close()  # Should clean up subscriptions


class TestSyncStatus:
    """Tests for inbox sync status."""

    @pytest.mark.asyncio
    async def test_empty_inbox_sync_status(self, api_config: dict[str, str]) -> None:
        """Get sync status of new inbox shows email_count=0."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            status = await inbox.get_sync_status()
            assert status.email_count == 0
            assert status.emails_hash is not None

    @pytest.mark.asyncio
    async def test_consistent_hash_without_changes(self, api_config: dict[str, str]) -> None:
        """Multiple calls without changes return same emails_hash."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            status1 = await inbox.get_sync_status()
            status2 = await inbox.get_sync_status()
            assert status1.emails_hash == status2.emails_hash


class TestAccessAfterDelete:
    """Tests for accessing deleted inbox."""

    @pytest.mark.asyncio
    async def test_access_after_delete(self, api_config: dict[str, str]) -> None:
        """Try to access deleted inbox throws InboxNotFoundError."""
        from vaultsandbox.errors import InboxNotFoundError

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            await inbox.delete()
            # Trying to list emails on deleted inbox should raise InboxNotFoundError
            with pytest.raises(InboxNotFoundError):
                await inbox.list_emails()


class TestInboxOperationsNoEmail:
    """Tests for inbox operations without email."""

    @pytest.mark.asyncio
    async def test_list_emails_empty_inbox(self, api_config: dict[str, str]) -> None:
        """List emails in new inbox returns empty array."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            emails = await inbox.list_emails()
            assert emails == []

    @pytest.mark.asyncio
    async def test_get_nonexistent_email(self, api_config: dict[str, str]) -> None:
        """Get email with fake ID throws EmailNotFoundError."""
        from vaultsandbox.errors import EmailNotFoundError

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            with pytest.raises(EmailNotFoundError):
                await inbox.get_email("fake-email-id-12345")


class TestNetworkErrors:
    """Tests for network error handling."""

    @pytest.mark.asyncio
    async def test_invalid_host_network_error(self) -> None:
        """Connect to non-existent server throws NetworkError."""
        from vaultsandbox.errors import NetworkError

        client = VaultSandboxClient(
            api_key="test",
            base_url="https://nonexistent.invalid.host.example",
        )
        # Creating an inbox triggers initialization which should fail
        with pytest.raises(NetworkError):
            await client.create_inbox()


class TestEmailTimeouts:
    """Tests for email waiting timeouts."""

    @pytest.mark.asyncio
    async def test_wait_for_email_timeout(self, api_config: dict[str, str]) -> None:
        """Wait for email without sending times out."""
        from vaultsandbox.errors import TimeoutError

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            with pytest.raises(TimeoutError):
                await inbox.wait_for_email(WaitForEmailOptions(timeout=1000))  # 1 second

    @pytest.mark.asyncio
    async def test_wait_for_count_timeout(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Wait for more emails than sent times out."""
        from vaultsandbox.errors import TimeoutError

        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Count Timeout Test {unique_id}",
                body_text="Test body",
            )
            with pytest.raises(TimeoutError):
                await inbox.wait_for_email_count(5, WaitForCountOptions(timeout=2000))  # Wait for 5

    @pytest.mark.asyncio
    async def test_filter_by_subject_no_match_timeout(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Wait for subject that doesn't exist times out."""
        from vaultsandbox.errors import TimeoutError

        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Hello World {unique_id}",
                body_text="Test body",
            )
            with pytest.raises(TimeoutError):
                await inbox.wait_for_email(
                    WaitForEmailOptions(
                        subject="NonExistent Subject",
                        timeout=2000,
                    )
                )


class TestEmailOperationsViaEmail:
    """Tests for email operations via email object."""

    @pytest.mark.asyncio
    async def test_get_email_by_id(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Get email by its ID returns same email."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Get By ID Test {unique_id}",
                body_text="Test body",
            )
            email1 = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))
            email2 = await inbox.get_email(email1.id)
            assert email1.id == email2.id
            assert email1.subject == email2.subject


class TestMultipleAttachments:
    """Tests for multiple attachments."""

    @pytest.mark.asyncio
    async def test_receive_email_with_multiple_attachments(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Send email with multiple attachments, all accessible."""
        unique_id = str(uuid.uuid4())[:8]
        subject = f"Multi Attachment Test {unique_id}"

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=subject,
                body_text="Email with multiple attachments",
                attachments=[
                    ("file1.txt", b"content1", "text/plain"),
                    ("file2.pdf", b"content2", "application/pdf"),
                ],
            )
            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))
            assert len(email.attachments) >= 2
            filenames = [a.filename for a in email.attachments]
            assert "file1.txt" in filenames
            assert "file2.pdf" in filenames


class TestFilterByFromRegex:
    """Tests for filtering by from address regex."""

    @pytest.mark.asyncio
    async def test_filter_by_from_regex(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Wait for email from address matching pattern."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"From Regex Test {unique_id}",
                body_text="Test body",
                from_address="test@example.com",
            )
            email = await inbox.wait_for_email(
                WaitForEmailOptions(
                    from_address=re.compile(r".*@example\.com"),
                    timeout=30000,
                )
            )
            assert "example.com" in email.from_address


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_timeout_value_zero(self, api_config: dict[str, str]) -> None:
        """Wait with timeout=0 returns immediately with timeout error."""
        import time

        from vaultsandbox.errors import TimeoutError

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            start = time.time()
            with pytest.raises(TimeoutError):
                await inbox.wait_for_email(WaitForEmailOptions(timeout=0))
            elapsed = time.time() - start
            assert elapsed < 1.0  # Should be nearly instant

    @pytest.mark.asyncio
    async def test_404_inbox_not_found(self, api_config: dict[str, str]) -> None:
        """Access non-existent inbox throws InboxNotFoundError."""
        from vaultsandbox.errors import InboxNotFoundError

        async with VaultSandboxClient(**api_config) as client:
            # Create and then delete an inbox to get a valid but deleted inbox
            inbox = await client.create_inbox()
            await inbox.delete()
            # Trying to access the deleted inbox should raise InboxNotFoundError
            with pytest.raises(InboxNotFoundError):
                await inbox.get_sync_status()

    @pytest.mark.asyncio
    async def test_404_email_not_found(self, api_config: dict[str, str]) -> None:
        """Access non-existent email throws EmailNotFoundError."""
        from vaultsandbox.errors import EmailNotFoundError

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            with pytest.raises(EmailNotFoundError):
                await inbox.get_email("nonexistent-email-id")
