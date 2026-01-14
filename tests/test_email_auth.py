"""Tests for email authentication using the Test Email API.

These tests use the Test Email API endpoint (POST /api/test/emails) to create
emails with controlled authentication results, enabling deterministic testing
of SPF, DKIM, DMARC, and Reverse DNS parsing.

Requirements:
- .env file with VAULTSANDBOX_URL, VAULTSANDBOX_API_KEY
- Server running with VSB_DEVELOPMENT=true (required for test endpoint)
"""

import os

import httpx
import pytest
from dotenv import load_dotenv

from vaultsandbox import VaultSandboxClient, WaitForEmailOptions
from vaultsandbox.types import (
    DKIMStatus,
    DMARCPolicy,
    DMARCStatus,
    ReverseDNSStatus,
    SPFStatus,
)

load_dotenv()


def get_env_or_skip(name: str) -> str:
    """Get environment variable or skip test if not set."""
    value = os.getenv(name)
    if not value:
        pytest.skip(f"{name} environment variable not set")
    return value


@pytest.fixture(scope="module")
def api_config() -> dict[str, str]:
    """Get API configuration from environment."""
    return {
        "api_key": get_env_or_skip("VAULTSANDBOX_API_KEY"),
        "base_url": get_env_or_skip("VAULTSANDBOX_URL"),
    }


async def create_test_email(
    base_url: str,
    api_key: str,
    to: str,
    *,
    from_address: str | None = None,
    subject: str | None = None,
    text: str | None = None,
    html: str | None = None,
    auth: dict | None = None,
) -> str:
    """Create a test email using the Test Email API.

    Args:
        base_url: VaultSandbox server base URL.
        api_key: API key for authentication.
        to: Inbox email address to deliver the test email to.
        from_address: Sender email address.
        subject: Email subject line.
        text: Plain text email body.
        html: HTML email body.
        auth: Authentication results object with spf, dkim, dmarc, reverseDns.

    Returns:
        The email ID of the created email.

    Raises:
        httpx.HTTPStatusError: If the request fails.
    """
    body: dict = {"to": to}
    if from_address:
        body["from"] = from_address
    if subject:
        body["subject"] = subject
    if text:
        body["text"] = text
    if html:
        body["html"] = html
    if auth:
        body["auth"] = auth

    async with httpx.AsyncClient() as http_client:
        response = await http_client.post(
            f"{base_url}/api/test/emails",
            json=body,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
            },
        )
        response.raise_for_status()
        return response.json()["emailId"]


class TestAllAuthPassing:
    """Tests for emails where all authentication checks pass."""

    @pytest.mark.asyncio
    async def test_all_auth_pass_default(self, api_config: dict[str, str]) -> None:
        """Test that default test email has all auth passing."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="All Auth Pass Default",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results is not None
            validation = email.auth_results.validate()

            assert validation.spf_passed is True
            assert validation.dkim_passed is True
            assert validation.dmarc_passed is True
            assert validation.reverse_dns_passed is True
            assert validation.passed is True
            assert len(validation.failures) == 0

    @pytest.mark.asyncio
    async def test_all_auth_pass_explicit(self, api_config: dict[str, str]) -> None:
        """Test explicitly setting all auth to pass."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="All Auth Pass Explicit",
                auth={
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                    "reverseDns": "pass",
                },
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            assert validation.passed is True
            assert validation.spf_passed is True
            assert validation.dkim_passed is True
            assert validation.dmarc_passed is True
            assert validation.reverse_dns_passed is True


class TestSPFResults:
    """Tests for SPF authentication results."""

    @pytest.mark.asyncio
    async def test_spf_pass(self, api_config: dict[str, str]) -> None:
        """Test SPF pass result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Pass",
                auth={"spf": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.result == SPFStatus.PASS
            assert email.auth_results.validate().spf_passed is True

    @pytest.mark.asyncio
    async def test_spf_fail(self, api_config: dict[str, str]) -> None:
        """Test SPF fail result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Fail",
                auth={"spf": "fail"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.result == SPFStatus.FAIL
            validation = email.auth_results.validate()
            assert validation.spf_passed is False
            assert validation.passed is False
            assert any("SPF" in f for f in validation.failures)

    @pytest.mark.asyncio
    async def test_spf_softfail(self, api_config: dict[str, str]) -> None:
        """Test SPF softfail result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Softfail",
                auth={"spf": "softfail"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.result == SPFStatus.SOFTFAIL
            assert email.auth_results.validate().spf_passed is False

    @pytest.mark.asyncio
    async def test_spf_neutral(self, api_config: dict[str, str]) -> None:
        """Test SPF neutral result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Neutral",
                auth={"spf": "neutral"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.result == SPFStatus.NEUTRAL
            assert email.auth_results.validate().spf_passed is False

    @pytest.mark.asyncio
    async def test_spf_none(self, api_config: dict[str, str]) -> None:
        """Test SPF none result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF None",
                auth={"spf": "none"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.result == SPFStatus.NONE
            assert email.auth_results.validate().spf_passed is False

    @pytest.mark.asyncio
    async def test_spf_temperror(self, api_config: dict[str, str]) -> None:
        """Test SPF temperror result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Temperror",
                auth={"spf": "temperror"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.result == SPFStatus.TEMPERROR
            assert email.auth_results.validate().spf_passed is False

    @pytest.mark.asyncio
    async def test_spf_permerror(self, api_config: dict[str, str]) -> None:
        """Test SPF permerror result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Permerror",
                auth={"spf": "permerror"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.result == SPFStatus.PERMERROR
            assert email.auth_results.validate().spf_passed is False

    @pytest.mark.asyncio
    async def test_spf_domain_extracted_from_sender(self, api_config: dict[str, str]) -> None:
        """Test that SPF domain is extracted from the sender address."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                from_address="sender@customdomain.com",
                subject="SPF Domain Test",
                auth={"spf": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.spf is not None
            assert email.auth_results.spf.domain == "customdomain.com"


class TestDKIMResults:
    """Tests for DKIM authentication results."""

    @pytest.mark.asyncio
    async def test_dkim_pass(self, api_config: dict[str, str]) -> None:
        """Test DKIM pass result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DKIM Pass",
                auth={"dkim": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert len(email.auth_results.dkim) > 0
            assert email.auth_results.dkim[0].result == DKIMStatus.PASS
            assert email.auth_results.validate().dkim_passed is True

    @pytest.mark.asyncio
    async def test_dkim_fail(self, api_config: dict[str, str]) -> None:
        """Test DKIM fail result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DKIM Fail",
                auth={"dkim": "fail"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert len(email.auth_results.dkim) > 0
            assert email.auth_results.dkim[0].result == DKIMStatus.FAIL
            validation = email.auth_results.validate()
            assert validation.dkim_passed is False
            assert validation.passed is False
            assert any("DKIM" in f for f in validation.failures)

    @pytest.mark.asyncio
    async def test_dkim_none(self, api_config: dict[str, str]) -> None:
        """Test DKIM none result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DKIM None",
                auth={"dkim": "none"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert len(email.auth_results.dkim) > 0
            assert email.auth_results.dkim[0].result == DKIMStatus.NONE
            assert email.auth_results.validate().dkim_passed is False

    @pytest.mark.asyncio
    async def test_dkim_selector_and_signature_present(self, api_config: dict[str, str]) -> None:
        """Test that DKIM result includes selector and signature info."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DKIM Details",
                auth={"dkim": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert len(email.auth_results.dkim) > 0
            dkim_result = email.auth_results.dkim[0]
            assert dkim_result.selector is not None
            assert dkim_result.signature is not None


class TestDMARCResults:
    """Tests for DMARC authentication results."""

    @pytest.mark.asyncio
    async def test_dmarc_pass(self, api_config: dict[str, str]) -> None:
        """Test DMARC pass result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DMARC Pass",
                auth={"dmarc": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.dmarc is not None
            assert email.auth_results.dmarc.result == DMARCStatus.PASS
            assert email.auth_results.validate().dmarc_passed is True

    @pytest.mark.asyncio
    async def test_dmarc_fail(self, api_config: dict[str, str]) -> None:
        """Test DMARC fail result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DMARC Fail",
                auth={"dmarc": "fail"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.dmarc is not None
            assert email.auth_results.dmarc.result == DMARCStatus.FAIL
            validation = email.auth_results.validate()
            assert validation.dmarc_passed is False
            assert validation.passed is False
            assert any("DMARC" in f for f in validation.failures)

    @pytest.mark.asyncio
    async def test_dmarc_none(self, api_config: dict[str, str]) -> None:
        """Test DMARC none result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DMARC None",
                auth={"dmarc": "none"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.dmarc is not None
            assert email.auth_results.dmarc.result == DMARCStatus.NONE
            assert email.auth_results.validate().dmarc_passed is False

    @pytest.mark.asyncio
    async def test_dmarc_policy_present(self, api_config: dict[str, str]) -> None:
        """Test that DMARC result includes policy information."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DMARC Policy",
                auth={"dmarc": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.dmarc is not None
            assert email.auth_results.dmarc.policy == DMARCPolicy.NONE

    @pytest.mark.asyncio
    async def test_dmarc_aligned_true(self, api_config: dict[str, str]) -> None:
        """Test that DMARC result shows alignment when passing."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DMARC Aligned",
                auth={"dmarc": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.dmarc is not None
            assert email.auth_results.dmarc.aligned is True


class TestReverseDNS:
    """Tests for Reverse DNS authentication results."""

    @pytest.mark.asyncio
    async def test_reverse_dns_verified(self, api_config: dict[str, str]) -> None:
        """Test reverse DNS verified result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Reverse DNS Verified",
                auth={"reverseDns": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.reverse_dns is not None
            assert email.auth_results.reverse_dns.result == ReverseDNSStatus.PASS
            assert email.auth_results.validate().reverse_dns_passed is True

    @pytest.mark.asyncio
    async def test_reverse_dns_not_verified(self, api_config: dict[str, str]) -> None:
        """Test reverse DNS not verified result."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Reverse DNS Not Verified",
                auth={"reverseDns": "fail"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.reverse_dns is not None
            assert email.auth_results.reverse_dns.result == ReverseDNSStatus.FAIL
            validation = email.auth_results.validate()
            assert validation.reverse_dns_passed is False
            assert any("Reverse DNS" in f for f in validation.failures)

    @pytest.mark.asyncio
    async def test_reverse_dns_hostname_and_ip_present(self, api_config: dict[str, str]) -> None:
        """Test that reverse DNS result includes hostname and IP."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Reverse DNS Details",
                auth={"reverseDns": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.auth_results.reverse_dns is not None
            assert email.auth_results.reverse_dns.hostname is not None
            assert email.auth_results.reverse_dns.ip is not None


class TestAllAuthFailing:
    """Tests for emails where all authentication checks fail."""

    @pytest.mark.asyncio
    async def test_all_auth_fail(self, api_config: dict[str, str]) -> None:
        """Test that all auth failing is correctly reported."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="All Auth Fail",
                auth={
                    "spf": "fail",
                    "dkim": "fail",
                    "dmarc": "fail",
                    "reverseDns": "fail",
                },
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            assert validation.passed is False
            assert validation.spf_passed is False
            assert validation.dkim_passed is False
            assert validation.dmarc_passed is False
            assert validation.reverse_dns_passed is False
            assert len(validation.failures) >= 3


class TestMixedAuthResults:
    """Tests for emails with mixed authentication results."""

    @pytest.mark.asyncio
    async def test_spf_softfail_dkim_pass_dmarc_fail(self, api_config: dict[str, str]) -> None:
        """Test mixed results: SPF softfail, DKIM pass, DMARC fail."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Mixed Auth 1",
                auth={
                    "spf": "softfail",
                    "dkim": "pass",
                    "dmarc": "fail",
                    "reverseDns": "pass",
                },
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            assert validation.passed is False
            assert validation.spf_passed is False
            assert validation.dkim_passed is True
            assert validation.dmarc_passed is False
            assert validation.reverse_dns_passed is True

    @pytest.mark.asyncio
    async def test_spf_pass_dkim_fail_dmarc_pass(self, api_config: dict[str, str]) -> None:
        """Test mixed results: SPF pass, DKIM fail, DMARC pass."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Mixed Auth 2",
                auth={
                    "spf": "pass",
                    "dkim": "fail",
                    "dmarc": "pass",
                    "reverseDns": "pass",
                },
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            assert validation.passed is False  # DKIM failed
            assert validation.spf_passed is True
            assert validation.dkim_passed is False
            assert validation.dmarc_passed is True
            assert validation.reverse_dns_passed is True

    @pytest.mark.asyncio
    async def test_all_pass_except_reverse_dns(self, api_config: dict[str, str]) -> None:
        """Test all passing except reverse DNS (should still pass overall)."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Mixed Auth 3",
                auth={
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                    "reverseDns": "fail",
                },
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            # Overall passed only requires SPF, DKIM, DMARC - not reverse DNS
            assert validation.passed is True
            assert validation.spf_passed is True
            assert validation.dkim_passed is True
            assert validation.dmarc_passed is True
            assert validation.reverse_dns_passed is False

    @pytest.mark.asyncio
    async def test_spf_neutral_rest_pass(self, api_config: dict[str, str]) -> None:
        """Test SPF neutral with rest passing."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Neutral Rest Pass",
                auth={
                    "spf": "neutral",
                    "dkim": "pass",
                    "dmarc": "pass",
                    "reverseDns": "pass",
                },
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            assert validation.passed is False  # SPF neutral is not pass
            assert validation.spf_passed is False
            assert validation.dkim_passed is True
            assert validation.dmarc_passed is True


class TestEmailContent:
    """Tests for email content with auth results."""

    @pytest.mark.asyncio
    async def test_custom_email_content(self, api_config: dict[str, str]) -> None:
        """Test that custom email content is correctly set."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                from_address="custom@example.org",
                subject="Custom Content Test",
                text="This is the plain text body.",
                html="<p>This is the HTML body.</p>",
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            assert email.from_address == "custom@example.org"
            assert email.subject == "Custom Content Test"
            assert email.text == "This is the plain text body."
            assert email.html == "<p>This is the HTML body.</p>"

    @pytest.mark.asyncio
    async def test_auth_domain_from_sender(self, api_config: dict[str, str]) -> None:
        """Test that auth domains are extracted from sender address."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                from_address="user@mydomain.test",
                subject="Domain Extraction Test",
                auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # SPF domain should be extracted from sender
            assert email.auth_results.spf is not None
            assert email.auth_results.spf.domain == "mydomain.test"

            # DKIM domain should be extracted from sender
            assert len(email.auth_results.dkim) > 0
            assert email.auth_results.dkim[0].domain == "mydomain.test"

            # DMARC domain should be extracted from sender
            assert email.auth_results.dmarc is not None
            assert email.auth_results.dmarc.domain == "mydomain.test"


class TestValidationFailureMessages:
    """Tests for validation failure message content."""

    @pytest.mark.asyncio
    async def test_spf_failure_message_includes_status(self, api_config: dict[str, str]) -> None:
        """Test that SPF failure message includes the status."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="SPF Failure Message Test",
                auth={"spf": "softfail", "dkim": "pass", "dmarc": "pass"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            spf_failure = next((f for f in validation.failures if "SPF" in f), None)
            assert spf_failure is not None
            assert "softfail" in spf_failure

    @pytest.mark.asyncio
    async def test_dmarc_failure_message_includes_policy(self, api_config: dict[str, str]) -> None:
        """Test that DMARC failure message includes policy info."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="DMARC Failure Message Test",
                auth={"spf": "pass", "dkim": "pass", "dmarc": "fail"},
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            validation = email.auth_results.validate()
            dmarc_failure = next((f for f in validation.failures if "DMARC" in f), None)
            assert dmarc_failure is not None
            assert "fail" in dmarc_failure


class TestPartialAuthOverrides:
    """Tests for partial auth overrides (only specifying some fields)."""

    @pytest.mark.asyncio
    async def test_only_spf_override(self, api_config: dict[str, str]) -> None:
        """Test that only overriding SPF leaves others at default (pass)."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Only SPF Override",
                auth={"spf": "fail"},  # Only override SPF
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # SPF should be fail (overridden)
            assert email.auth_results.spf.result == SPFStatus.FAIL

            # Others should be pass (default)
            assert len(email.auth_results.dkim) > 0
            assert email.auth_results.dkim[0].result == DKIMStatus.PASS
            assert email.auth_results.dmarc.result == DMARCStatus.PASS
            assert email.auth_results.reverse_dns.result == ReverseDNSStatus.PASS

    @pytest.mark.asyncio
    async def test_only_dkim_override(self, api_config: dict[str, str]) -> None:
        """Test that only overriding DKIM leaves others at default (pass)."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Only DKIM Override",
                auth={"dkim": "fail"},  # Only override DKIM
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # DKIM should be fail (overridden)
            assert len(email.auth_results.dkim) > 0
            assert email.auth_results.dkim[0].result == DKIMStatus.FAIL

            # Others should be pass (default)
            assert email.auth_results.spf.result == SPFStatus.PASS
            assert email.auth_results.dmarc.result == DMARCStatus.PASS
            assert email.auth_results.reverse_dns.result == ReverseDNSStatus.PASS

    @pytest.mark.asyncio
    async def test_only_reverse_dns_override(self, api_config: dict[str, str]) -> None:
        """Test that only overriding reverseDns leaves others at default (pass)."""
        async with VaultSandboxClient(**api_config) as client:
            inbox = await client.create_inbox()

            await create_test_email(
                api_config["base_url"],
                api_config["api_key"],
                inbox.email_address,
                subject="Only ReverseDNS Override",
                auth={"reverseDns": "fail"},  # Only override reverseDns
            )

            email = await inbox.wait_for_email(WaitForEmailOptions(timeout=30000))

            # ReverseDNS should be false (overridden)
            assert email.auth_results.reverse_dns.result == ReverseDNSStatus.FAIL

            # Others should be pass (default)
            assert email.auth_results.spf.result == SPFStatus.PASS
            assert len(email.auth_results.dkim) > 0
            assert email.auth_results.dkim[0].result == DKIMStatus.PASS
            assert email.auth_results.dmarc.result == DMARCStatus.PASS
