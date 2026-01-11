"""Tests for README code examples.

These tests verify that all code examples in the README work correctly
by running them against a real VaultSandbox server.

Requirements:
- .env file with VAULTSANDBOX_URL, VAULTSANDBOX_API_KEY, SMTP_HOST, SMTP_PORT
- Network access to the VaultSandbox server and SMTP port
"""

import asyncio
import contextlib
import os
import re
import smtplib
import tempfile
import uuid
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pytest
from dotenv import load_dotenv

from vaultsandbox import (
    ApiError,
    CreateInboxOptions,
    DecryptionError,
    DeliveryStrategyType,
    Email,
    EmailNotFoundError,
    Inbox,
    InboxNotFoundError,
    NetworkError,
    SignatureVerificationError,
    TimeoutError,
    VaultSandboxClient,
    # Error types from README
    VaultSandboxError,
    WaitForCountOptions,
    WaitForEmailOptions,
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
    """Send an email via SMTP."""
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


class TestQuickStart:
    """Tests for the Quick Start example in README."""

    @pytest.mark.asyncio
    async def test_quick_start_example(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test the basic quick start example from README."""
        unique_id = str(uuid.uuid4())[:8]

        # README example (adapted for test)
        async with VaultSandboxClient(**api_config) as client:
            # Create a temporary inbox
            inbox = await client.create_inbox()
            assert inbox.email_address is not None
            print(f"Send emails to: {inbox.email_address}")

            # Send a test email
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Quick Start Test {unique_id}",
                body_text=f"Hello from quick start test! ID: {unique_id}",
            )

            # Wait for an email (with 30 second timeout)
            email = await inbox.wait_for_email()

            print(f"From: {email.from_address}")
            print(f"Subject: {email.subject}")
            print(f"Body: {email.text}")

            assert email.from_address is not None
            assert email.subject is not None
            assert email.text is not None
            assert unique_id in email.subject

            # Clean up
            await inbox.delete()


class TestConfiguration:
    """Tests for configuration options shown in README."""

    @pytest.mark.asyncio
    async def test_client_options(self, api_config: dict[str, str]) -> None:
        """Test that client accepts all documented options."""
        # README example: Client Options
        client = VaultSandboxClient(
            api_key=api_config["api_key"],
            base_url=api_config["base_url"],
            timeout=30000,  # HTTP timeout in ms
            max_retries=3,  # Retry attempts
            retry_delay=1000,  # Initial retry delay in ms
            strategy=DeliveryStrategyType.SSE,  # SSE or POLLING
        )
        assert client is not None
        await client.close()

    def test_delivery_strategy_enum_values(self) -> None:
        """Test that DeliveryStrategyType has documented values."""
        # README documents these two strategies
        assert DeliveryStrategyType.SSE is not None
        assert DeliveryStrategyType.POLLING is not None

    @pytest.mark.asyncio
    async def test_environment_variable_pattern(self, api_config: dict[str, str]) -> None:
        """Test the env var loading pattern from README."""
        # README example: Environment Variables
        # from dotenv import load_dotenv
        # load_dotenv()

        client = VaultSandboxClient(
            api_key=os.getenv("VAULTSANDBOX_API_KEY"),
            base_url=os.getenv("VAULTSANDBOX_URL"),
        )
        assert client is not None

        # Verify it works
        async with client:
            is_valid = await client.check_key()
            assert is_valid is True


class TestCreateInboxOptions:
    """Tests for inbox creation options shown in README."""

    @pytest.mark.asyncio
    async def test_create_inbox_with_ttl(self, api_config: dict[str, str]) -> None:
        """Test creating inbox with custom TTL."""
        async with VaultSandboxClient(**api_config) as client:
            # README example: Custom TTL (time-to-live)
            inbox = await client.create_inbox(
                CreateInboxOptions(ttl=3600)  # 1 hour
            )
            assert inbox is not None
            assert inbox.email_address is not None
            await inbox.delete()

    @pytest.mark.asyncio
    async def test_create_inbox_with_email_address(self, api_config: dict[str, str]) -> None:
        """Test requesting specific email address prefix."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            # Get an allowed domain from server info
            server_info = await client.get_server_info()
            if not server_info.allowed_domains:
                pytest.skip("No allowed domains configured on server")

            allowed_domain = server_info.allowed_domains[0]

            # README example: Request specific email address
            inbox = await client.create_inbox(
                CreateInboxOptions(email_address=f"test-readme-{unique_id}@{allowed_domain}")
            )
            assert inbox is not None
            assert inbox.email_address is not None
            assert f"test-readme-{unique_id}" in inbox.email_address
            await inbox.delete()


class TestWaitForEmailFilters:
    """Tests for wait_for_email filter options shown in README."""

    @pytest.mark.asyncio
    async def test_wait_for_email_with_subject_filter(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test waiting for email with specific subject."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send email with specific subject
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Welcome {unique_id}",
                body_text="Welcome email body",
            )

            # README example: Wait for email with specific subject
            email = await inbox.wait_for_email(WaitForEmailOptions(subject="Welcome"))

            assert email is not None
            assert "Welcome" in email.subject
            await inbox.delete()

    @pytest.mark.asyncio
    async def test_wait_for_email_with_regex_from_address(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test waiting for email from sender matching regex."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send from a company.com address
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Regex From Test {unique_id}",
                body_text="Test body",
                from_address="noreply@company.com",
            )

            # README example: Wait for email from specific sender (regex)
            email = await inbox.wait_for_email(
                WaitForEmailOptions(from_address=re.compile(r".*@company\.com"))
            )

            assert email is not None
            assert email.from_address.endswith("@company.com")
            await inbox.delete()

    @pytest.mark.asyncio
    async def test_wait_for_email_with_predicate(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test waiting for email with custom predicate."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send email with attachment
            attachment_content = b"Test attachment content"
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Predicate Test {unique_id}",
                body_text="Email with attachment",
                attachments=[("test.txt", attachment_content, "text/plain")],
            )

            # README example: Custom predicate
            email = await inbox.wait_for_email(
                WaitForEmailOptions(
                    predicate=lambda e: len(e.attachments) > 0,
                    timeout=60000,  # 60 seconds
                )
            )

            assert email is not None
            assert len(email.attachments) > 0
            await inbox.delete()


class TestWaitForMultipleEmails:
    """Tests for wait_for_email_count shown in README."""

    @pytest.mark.asyncio
    async def test_wait_for_email_count(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test waiting until inbox has at least N emails."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send 3 emails
            for i in range(3):
                send_email(
                    smtp_host=str(smtp_config["host"]),
                    smtp_port=int(smtp_config["port"]),
                    to_address=inbox.email_address,
                    subject=f"Count Test {unique_id} - Email {i + 1}",
                    body_text=f"Body {i + 1}",
                )

            # README example: Wait until inbox has at least 3 emails
            emails = await inbox.wait_for_email_count(3, WaitForCountOptions(timeout=60000))

            assert len(emails) >= 3
            await inbox.delete()


class TestSubscribeToNewEmails:
    """Tests for on_new_email subscription shown in README."""

    @pytest.mark.asyncio
    async def test_on_new_email_subscription(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test subscribing to new emails."""
        unique_id = str(uuid.uuid4())[:8]
        received_emails: list = []

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # README example: Subscribe to new emails
            async def handle_email(email):
                print(f"New email: {email.subject}")
                received_emails.append(email)
                await email.mark_as_read()

            subscription = await inbox.on_new_email(handle_email)

            # Give subscription time to establish
            await asyncio.sleep(1)

            # Send an email
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Subscription Test {unique_id}",
                body_text="Test body",
            )

            # Wait for email to arrive via subscription
            for _ in range(30):
                if received_emails:
                    break
                await asyncio.sleep(1)

            # README example: Later, unsubscribe
            await inbox.unsubscribe(subscription)

            assert len(received_emails) >= 1
            assert unique_id in received_emails[0].subject
            await inbox.delete()


class TestMonitorMultipleInboxes:
    """Tests for monitor_inboxes shown in README."""

    @pytest.mark.asyncio
    async def test_monitor_multiple_inboxes(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test monitoring multiple inboxes."""
        unique_id = str(uuid.uuid4())[:8]
        received_emails: list = []

        async with VaultSandboxClient(**api_config) as client:
            # README example: Monitor Multiple Inboxes
            inbox1 = await client.create_inbox()
            inbox2 = await client.create_inbox()

            def on_email(inbox, email):
                print(f"Email to {email.to}: {email.subject}")
                received_emails.append(email)

            monitor = client.monitor_inboxes([inbox1, inbox2])
            monitor.on_email(on_email)
            await monitor.start()

            await asyncio.sleep(1)

            # Send email to each inbox
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox1.email_address,
                subject=f"Monitor Test 1 - {unique_id}",
                body_text="Body 1",
            )

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox2.email_address,
                subject=f"Monitor Test 2 - {unique_id}",
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
            assert any("Monitor Test 1" in s for s in subjects)
            assert any("Monitor Test 2" in s for s in subjects)


class TestEmailContentAndAttachments:
    """Tests for email content access shown in README."""

    @pytest.mark.asyncio
    async def test_email_content_access(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test accessing email content and attachments."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # Send email with HTML and attachment
            body_html = (
                "<html><body><h1>Test</h1><a href='https://example.com/link'>Link</a></body></html>"
            )
            attachment_content = b"PDF content here"
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Content Test {unique_id}",
                body_text=f"Plain text body {unique_id}",
                body_html=body_html,
                attachments=[("document.pdf", attachment_content, "application/pdf")],
            )

            email = await inbox.wait_for_email()

            # README example: Email Content and Attachments
            # Text and HTML content
            print(email.text)  # Plain text body
            print(email.html)  # HTML body
            assert email.text is not None
            assert email.html is not None

            # Headers
            print(email.headers.get("message-id"))
            # message-id may or may not be present depending on mail client

            # Attachments
            for attachment in email.attachments:
                print(f"{attachment.filename}: {attachment.size} bytes")
                assert attachment.filename is not None
                assert attachment.size > 0
                # attachment.content is bytes
                assert isinstance(attachment.content, bytes)

            # Links found in the email
            for link in email.links:
                print(link)
                assert isinstance(link, str)

            # Raw email source (MIME)
            raw_email = await email.get_raw()
            print(raw_email.id)  # Email ID
            print(raw_email.raw)  # Raw MIME content
            assert raw_email is not None
            assert raw_email.id is not None
            assert len(raw_email.raw) > 0

            await inbox.delete()


class TestEmailAuthenticationResults:
    """Tests for email authentication results shown in README."""

    @pytest.mark.asyncio
    async def test_auth_results_access(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test accessing authentication results."""
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

            email = await inbox.wait_for_email()

            # README example: Email Authentication Results
            # Individual results
            print(f"SPF: {email.auth_results.spf.result}")
            print(f"DKIM: {[d.result for d in email.auth_results.dkim]}")
            print(f"DMARC: {email.auth_results.dmarc.result}")

            assert email.auth_results.spf is not None
            assert email.auth_results.dkim is not None
            assert email.auth_results.dmarc is not None

            # Validate all at once
            validation = email.auth_results.validate()
            if validation.passed:
                print("All authentication checks passed")
            else:
                print(f"Failures: {validation.failures}")

            # validation object exists and has expected attributes
            assert hasattr(validation, "passed")
            assert hasattr(validation, "spf_passed")
            assert hasattr(validation, "dkim_passed")
            assert hasattr(validation, "dmarc_passed")
            assert hasattr(validation, "reverse_dns_passed")
            assert hasattr(validation, "failures")

            await inbox.delete()


class TestExportImportInboxes:
    """Tests for inbox export/import shown in README."""

    @pytest.mark.asyncio
    async def test_export_inbox_to_object(
        self,
        api_config: dict[str, str],
    ) -> None:
        """Test exporting inbox to object."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # README example: Export to object
            exported = client.export_inbox(inbox)

            assert exported is not None
            assert exported.version == 1  # Per spec Section 9.3
            assert exported.email_address == inbox.email_address
            assert exported.secret_key is not None  # base64url encoded

            await inbox.delete()

    @pytest.mark.asyncio
    async def test_export_inbox_to_file(
        self,
        api_config: dict[str, str],
    ) -> None:
        """Test exporting inbox to file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            async with VaultSandboxClient(**api_config) as client:
                inbox = await client.create_inbox()

                # README example: Export to file
                await client.export_inbox_to_file(inbox, temp_path)

                # Verify file was created with content
                assert Path(temp_path).exists()
                content = Path(temp_path).read_text()
                assert inbox.email_address in content

                await inbox.delete()
        finally:
            Path(temp_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_import_inbox_from_object(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test importing inbox from object."""
        unique_id = str(uuid.uuid4())[:8]

        # First client: create inbox and export
        client1 = VaultSandboxClient(**api_config)
        try:
            inbox = await client1.create_inbox()
            original_address = inbox.email_address

            # Send an email to the inbox
            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Import Test {unique_id}",
                body_text="Test body",
            )

            await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # README example: Export to object
            exported = client1.export_inbox(inbox)

            # Close client without deleting inbox
            await client1._api_client.close()
            if client1._strategy:
                await client1._strategy.close()
        except Exception:
            with contextlib.suppress(Exception):
                await client1.close()
            raise

        # Second client: import inbox
        async with VaultSandboxClient(**api_config) as client2:
            # README example: Import from object
            imported_inbox = await client2.import_inbox(exported)

            assert imported_inbox.email_address == original_address

            # Should be able to access emails from imported inbox
            emails = await imported_inbox.list_emails()
            assert len(emails) >= 1
            assert any(unique_id in e.subject for e in emails)

    @pytest.mark.asyncio
    async def test_import_inbox_from_file(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test importing inbox from file."""
        unique_id = str(uuid.uuid4())[:8]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            # First client: create inbox and export to file
            client1 = VaultSandboxClient(**api_config)
            try:
                inbox = await client1.create_inbox()
                original_address = inbox.email_address

                send_email(
                    smtp_host=str(smtp_config["host"]),
                    smtp_port=int(smtp_config["port"]),
                    to_address=inbox.email_address,
                    subject=f"File Import Test {unique_id}",
                    body_text="Test body",
                )

                await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

                # README example: Export to file
                await client1.export_inbox_to_file(inbox, temp_path)

                await client1._api_client.close()
                if client1._strategy:
                    await client1._strategy.close()
            except Exception:
                with contextlib.suppress(Exception):
                    await client1.close()
                raise

            # Second client: import from file
            async with VaultSandboxClient(**api_config) as client2:
                # README example: Import from file
                imported_inbox = await client2.import_inbox_from_file(temp_path)

                assert imported_inbox.email_address == original_address

                emails = await imported_inbox.list_emails()
                assert len(emails) >= 1
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestDeleteInboxes:
    """Tests for inbox deletion shown in README."""

    @pytest.mark.asyncio
    async def test_delete_single_inbox(self, api_config: dict[str, str]) -> None:
        """Test deleting a single inbox."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()
            email_address = inbox.email_address

            # README example: Delete single inbox
            await inbox.delete()

            # Verify inbox was deleted (creating new inbox shouldn't conflict)
            new_inbox = await client.create_inbox()
            assert new_inbox.email_address != email_address
            await new_inbox.delete()


class TestErrorHandling:
    """Tests for error handling patterns shown in README."""

    def test_error_hierarchy(self) -> None:
        """Test that all documented errors exist and inherit correctly."""
        # README documents these errors
        assert issubclass(ApiError, VaultSandboxError)
        assert issubclass(NetworkError, VaultSandboxError)
        assert issubclass(TimeoutError, VaultSandboxError)
        assert issubclass(InboxNotFoundError, VaultSandboxError)
        assert issubclass(EmailNotFoundError, VaultSandboxError)
        assert issubclass(DecryptionError, VaultSandboxError)
        assert issubclass(SignatureVerificationError, VaultSandboxError)

    def test_api_error_attributes(self) -> None:
        """Test ApiError has documented attributes."""
        # README shows: print(f"API error {e.status_code}: {e.message}")
        error = ApiError(status_code=404, message="Not found")
        assert error.status_code == 404
        assert error.message == "Not found"

    @pytest.mark.asyncio
    async def test_timeout_error_handling(self, api_config: dict[str, str]) -> None:
        """Test the timeout error handling pattern from README."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            # README example: Error Handling
            try:
                await inbox.wait_for_email(
                    WaitForEmailOptions(timeout=1000)  # Very short timeout
                )
            except TimeoutError:
                print("No email received within timeout")
                # Expected - no email was sent
            except SignatureVerificationError:
                print("CRITICAL: Email signature verification failed!")
            except DecryptionError as e:
                print(f"Failed to decrypt email: {e}")
            except ApiError as e:
                print(f"API error {e.status_code}: {e.message}")
            except NetworkError:
                print("Network connection failed")
            except VaultSandboxError as e:
                print(f"VaultSandbox error: {e}")

            await inbox.delete()


class TestAPIReferenceClientMethods:
    """Tests verifying VaultSandboxClient has documented API methods."""

    @pytest.mark.asyncio
    async def test_check_key(self, api_config: dict[str, str]) -> None:
        """Test check_key method from API Reference."""
        async with VaultSandboxClient(**api_config) as client:
            # README API Reference: check_key() - Validate the API key
            is_valid = await client.check_key()
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_get_server_info(self, api_config: dict[str, str]) -> None:
        """Test get_server_info method from API Reference."""
        async with VaultSandboxClient(**api_config) as client:
            # README API Reference: get_server_info() - Get server capabilities
            server_info = await client.get_server_info()
            assert server_info is not None
            assert server_info.server_sig_pk is not None

    def test_client_has_all_documented_methods(self) -> None:
        """Test that client has all methods from API Reference table."""
        client = VaultSandboxClient(api_key="test")

        # Methods from README API Reference table
        assert hasattr(client, "check_key")
        assert hasattr(client, "get_server_info")
        assert hasattr(client, "create_inbox")
        assert hasattr(client, "delete_all_inboxes")
        assert hasattr(client, "monitor_inboxes")
        assert hasattr(client, "export_inbox")
        assert hasattr(client, "import_inbox")
        assert hasattr(client, "close")


class TestAPIReferenceInboxMethods:
    """Tests verifying Inbox has documented API methods."""

    def test_inbox_has_all_documented_methods(self) -> None:
        """Test the actual Inbox class has documented methods."""
        # Methods from README API Reference table
        assert hasattr(Inbox, "list_emails")
        assert hasattr(Inbox, "get_email")
        assert hasattr(Inbox, "get_raw_email")
        assert hasattr(Inbox, "wait_for_email")
        assert hasattr(Inbox, "wait_for_email_count")
        assert hasattr(Inbox, "on_new_email")
        assert hasattr(Inbox, "mark_email_as_read")
        assert hasattr(Inbox, "delete_email")
        assert hasattr(Inbox, "delete")
        assert hasattr(Inbox, "get_sync_status")
        assert hasattr(Inbox, "export")


class TestAPIReferenceEmailProperties:
    """Tests verifying Email has documented properties."""

    def test_email_class_exists(self) -> None:
        """Test the Email class exists."""
        assert Email is not None

    @pytest.mark.asyncio
    async def test_email_has_documented_properties(
        self,
        api_config: dict[str, str],
        smtp_config: dict[str, str | int],
    ) -> None:
        """Test that email has all documented properties."""
        unique_id = str(uuid.uuid4())[:8]

        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            send_email(
                smtp_host=str(smtp_config["host"]),
                smtp_port=int(smtp_config["port"]),
                to_address=inbox.email_address,
                subject=f"Properties Test {unique_id}",
                body_text="Test body",
            )

            email = await inbox.wait_for_email()

            # Properties from README API Reference table
            assert hasattr(email, "id")
            assert hasattr(email, "from_address")
            assert hasattr(email, "to")
            assert hasattr(email, "subject")
            assert hasattr(email, "text")
            assert hasattr(email, "html")
            assert hasattr(email, "attachments")
            assert hasattr(email, "links")
            assert hasattr(email, "headers")
            assert hasattr(email, "auth_results")
            assert hasattr(email, "received_at")
            assert hasattr(email, "is_read")

            # Methods from README API Reference table
            assert hasattr(email, "mark_as_read")
            assert hasattr(email, "delete")
            assert hasattr(email, "get_raw")

            await inbox.delete()


class TestWaitForEmailOptionsTypes:
    """Tests for WaitForEmailOptions type combinations shown in README."""

    def test_wait_options_with_string_subject(self) -> None:
        """Test WaitForEmailOptions with string subject."""
        options = WaitForEmailOptions(subject="Welcome")
        assert options.subject == "Welcome"

    def test_wait_options_with_regex_subject(self) -> None:
        """Test WaitForEmailOptions with regex subject."""
        pattern = re.compile(r"Order #\d+")
        options = WaitForEmailOptions(subject=pattern)
        assert options.subject == pattern

    def test_wait_options_with_string_from_address(self) -> None:
        """Test WaitForEmailOptions with string from_address."""
        options = WaitForEmailOptions(from_address="sender@example.com")
        assert options.from_address == "sender@example.com"

    def test_wait_options_with_regex_from_address(self) -> None:
        """Test WaitForEmailOptions with regex from_address."""
        pattern = re.compile(r".*@company\.com")
        options = WaitForEmailOptions(from_address=pattern)
        assert options.from_address == pattern

    def test_wait_options_with_predicate(self) -> None:
        """Test WaitForEmailOptions with predicate function."""

        def has_attachments(email):
            return len(email.attachments) > 0

        options = WaitForEmailOptions(predicate=has_attachments)
        assert options.predicate is not None

    def test_wait_options_with_timeout(self) -> None:
        """Test WaitForEmailOptions with timeout."""
        options = WaitForEmailOptions(timeout=60000)
        assert options.timeout == 60000

    def test_wait_options_combined(self) -> None:
        """Test WaitForEmailOptions with multiple options."""
        options = WaitForEmailOptions(
            subject="Test",
            from_address=re.compile(r".*@example\.com"),
            timeout=30000,
        )
        assert options.subject == "Test"
        assert options.timeout == 30000
