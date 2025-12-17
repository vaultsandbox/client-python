"""Tests for type definitions."""

from vaultsandbox.types import (
    AuthResults,
    DKIMResult,
    DKIMStatus,
    DMARCPolicy,
    DMARCResult,
    DMARCStatus,
    ReverseDNSResult,
    ReverseDNSStatus,
    SPFResult,
    SPFStatus,
)


class TestAuthResults:
    """Tests for AuthResults validation."""

    def test_all_pass(self) -> None:
        """Test validation when all checks pass."""
        auth = AuthResults(
            spf=SPFResult(status=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(status=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(status=DMARCStatus.PASS, domain="example.com"),
            reverse_dns=ReverseDNSResult(status=ReverseDNSStatus.PASS),
        )
        validation = auth.validate()
        assert validation.passed is True
        assert validation.spf_passed is True
        assert validation.dkim_passed is True
        assert validation.dmarc_passed is True
        assert validation.reverse_dns_passed is True
        assert len(validation.failures) == 0

    def test_spf_fail(self) -> None:
        """Test validation when SPF fails."""
        auth = AuthResults(
            spf=SPFResult(status=SPFStatus.FAIL, domain="example.com"),
            dkim=[DKIMResult(status=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(status=DMARCStatus.PASS),
        )
        validation = auth.validate()
        assert validation.passed is False
        assert validation.spf_passed is False
        assert any("SPF check failed" in f for f in validation.failures)

    def test_dkim_fail(self) -> None:
        """Test validation when DKIM fails."""
        auth = AuthResults(
            spf=SPFResult(status=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(status=DKIMStatus.FAIL, selector="s1", domain="example.com")],
            dmarc=DMARCResult(status=DMARCStatus.PASS),
        )
        validation = auth.validate()
        assert validation.passed is False
        assert validation.dkim_passed is False
        assert any("DKIM signature failed" in f for f in validation.failures)

    def test_dmarc_fail(self) -> None:
        """Test validation when DMARC fails."""
        auth = AuthResults(
            spf=SPFResult(status=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(status=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(status=DMARCStatus.FAIL, policy=DMARCPolicy.REJECT),
        )
        validation = auth.validate()
        assert validation.passed is False
        assert validation.dmarc_passed is False
        assert any("DMARC policy" in f for f in validation.failures)

    def test_reverse_dns_fail_does_not_affect_passed(self) -> None:
        """Test that reverse DNS failure doesn't affect overall passed status."""
        auth = AuthResults(
            spf=SPFResult(status=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(status=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(status=DMARCStatus.PASS),
            reverse_dns=ReverseDNSResult(status=ReverseDNSStatus.FAIL, hostname="mail.example.com"),
        )
        validation = auth.validate()
        # passed only considers SPF, DKIM, DMARC (not reverse_dns per Node.js spec)
        assert validation.passed is True
        assert validation.reverse_dns_passed is False
        assert any("Reverse DNS check failed" in f for f in validation.failures)

    def test_none_status_fails(self) -> None:
        """Test that 'none' status counts as failing (requires explicit 'pass')."""
        auth = AuthResults(
            spf=SPFResult(status=SPFStatus.NONE),
            dkim=[DKIMResult(status=DKIMStatus.NONE)],
            dmarc=DMARCResult(status=DMARCStatus.NONE),
            reverse_dns=ReverseDNSResult(status=ReverseDNSStatus.NONE),
        )
        validation = auth.validate()
        assert validation.passed is False
        assert validation.spf_passed is False
        assert validation.dkim_passed is False
        assert validation.dmarc_passed is False
        assert validation.reverse_dns_passed is False

    def test_dkim_at_least_one_pass(self) -> None:
        """Test that DKIM passes if at least one signature passes."""
        auth = AuthResults(
            spf=SPFResult(status=SPFStatus.PASS, domain="example.com"),
            dkim=[
                DKIMResult(status=DKIMStatus.FAIL, domain="example.com"),
                DKIMResult(status=DKIMStatus.PASS, domain="example.org"),
            ],
            dmarc=DMARCResult(status=DMARCStatus.PASS),
        )
        validation = auth.validate()
        assert validation.passed is True
        assert validation.dkim_passed is True
        assert len(validation.failures) == 0

    def test_empty_results(self) -> None:
        """Test validation with no auth results."""
        auth = AuthResults()
        validation = auth.validate()
        assert validation.passed is False
        assert validation.spf_passed is False
        assert validation.dkim_passed is False
        assert validation.dmarc_passed is False
        assert validation.reverse_dns_passed is False
