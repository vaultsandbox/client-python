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
from vaultsandbox.utils.email_utils import (
    parse_auth_results,
    parse_dkim_results,
    parse_dmarc_result,
    parse_reverse_dns_result,
    parse_spf_result,
)


class TestAuthResults:
    """Tests for AuthResults validation."""

    def test_all_pass(self) -> None:
        """Test validation when all checks pass."""
        auth = AuthResults(
            spf=SPFResult(result=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(result=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(result=DMARCStatus.PASS, domain="example.com"),
            reverse_dns=ReverseDNSResult(result=ReverseDNSStatus.PASS),
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
            spf=SPFResult(result=SPFStatus.FAIL, domain="example.com"),
            dkim=[DKIMResult(result=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(result=DMARCStatus.PASS),
        )
        validation = auth.validate()
        assert validation.passed is False
        assert validation.spf_passed is False
        assert any("SPF check failed" in f for f in validation.failures)

    def test_dkim_fail(self) -> None:
        """Test validation when DKIM fails."""
        auth = AuthResults(
            spf=SPFResult(result=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(result=DKIMStatus.FAIL, selector="s1", domain="example.com")],
            dmarc=DMARCResult(result=DMARCStatus.PASS),
        )
        validation = auth.validate()
        assert validation.passed is False
        assert validation.dkim_passed is False
        assert any("DKIM signature failed" in f for f in validation.failures)

    def test_dmarc_fail(self) -> None:
        """Test validation when DMARC fails."""
        auth = AuthResults(
            spf=SPFResult(result=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(result=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(result=DMARCStatus.FAIL, policy=DMARCPolicy.REJECT),
        )
        validation = auth.validate()
        assert validation.passed is False
        assert validation.dmarc_passed is False
        assert any("DMARC policy" in f for f in validation.failures)

    def test_reverse_dns_fail_does_not_affect_passed(self) -> None:
        """Test that reverse DNS failure doesn't affect overall passed status."""
        auth = AuthResults(
            spf=SPFResult(result=SPFStatus.PASS, domain="example.com"),
            dkim=[DKIMResult(result=DKIMStatus.PASS, domain="example.com")],
            dmarc=DMARCResult(result=DMARCStatus.PASS),
            reverse_dns=ReverseDNSResult(result=ReverseDNSStatus.FAIL, hostname="mail.example.com"),
        )
        validation = auth.validate()
        # passed only considers SPF, DKIM, DMARC (not reverse_dns per Node.js spec)
        assert validation.passed is True
        assert validation.reverse_dns_passed is False
        assert any("Reverse DNS check failed" in f for f in validation.failures)

    def test_none_status_fails(self) -> None:
        """Test that 'none' status counts as failing (requires explicit 'pass')."""
        auth = AuthResults(
            spf=SPFResult(result=SPFStatus.NONE),
            dkim=[DKIMResult(result=DKIMStatus.NONE)],
            dmarc=DMARCResult(result=DMARCStatus.NONE),
            reverse_dns=ReverseDNSResult(result=ReverseDNSStatus.FAIL),
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
            spf=SPFResult(result=SPFStatus.PASS, domain="example.com"),
            dkim=[
                DKIMResult(result=DKIMStatus.FAIL, domain="example.com"),
                DKIMResult(result=DKIMStatus.PASS, domain="example.org"),
            ],
            dmarc=DMARCResult(result=DMARCStatus.PASS),
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


class TestAuthResultsParsing:
    """Tests for parsing auth results from wire format."""

    def test_parse_spf_result(self) -> None:
        """Test parsing SPF result from wire format."""
        data = {
            "result": "pass",
            "domain": "example.com",
            "ip": "192.168.1.1",
            "details": "spf=pass (test email)",
        }
        spf = parse_spf_result(data)
        assert spf is not None
        assert spf.result == SPFStatus.PASS
        assert spf.domain == "example.com"
        assert spf.ip == "192.168.1.1"
        assert spf.details == "spf=pass (test email)"

    def test_parse_spf_result_minimal(self) -> None:
        """Test parsing SPF result with minimal data."""
        data = {"result": "fail"}
        spf = parse_spf_result(data)
        assert spf is not None
        assert spf.result == SPFStatus.FAIL
        assert spf.domain is None
        assert spf.ip is None
        assert spf.details is None

    def test_parse_spf_result_none(self) -> None:
        """Test parsing SPF result with None input."""
        assert parse_spf_result(None) is None
        assert parse_spf_result({}) is None

    def test_parse_dkim_results(self) -> None:
        """Test parsing DKIM results from wire format."""
        data = [
            {
                "result": "pass",
                "domain": "example.com",
                "selector": "default",
                "signature": "dkim=pass (test email)",
            },
            {
                "result": "fail",
                "domain": "other.com",
                "selector": "s1",
            },
        ]
        dkim = parse_dkim_results(data)
        assert len(dkim) == 2
        assert dkim[0].result == DKIMStatus.PASS
        assert dkim[0].domain == "example.com"
        assert dkim[0].selector == "default"
        assert dkim[0].signature == "dkim=pass (test email)"
        assert dkim[1].result == DKIMStatus.FAIL
        assert dkim[1].domain == "other.com"

    def test_parse_dkim_results_empty(self) -> None:
        """Test parsing DKIM results with empty/None input."""
        assert parse_dkim_results(None) == []
        assert parse_dkim_results([]) == []

    def test_parse_dmarc_result(self) -> None:
        """Test parsing DMARC result from wire format."""
        data = {
            "result": "pass",
            "policy": "reject",
            "domain": "example.com",
            "aligned": True,
        }
        dmarc = parse_dmarc_result(data)
        assert dmarc is not None
        assert dmarc.result == DMARCStatus.PASS
        assert dmarc.policy == DMARCPolicy.REJECT
        assert dmarc.domain == "example.com"
        assert dmarc.aligned is True

    def test_parse_dmarc_result_none_policy(self) -> None:
        """Test parsing DMARC result without policy."""
        data = {"result": "none"}
        dmarc = parse_dmarc_result(data)
        assert dmarc is not None
        assert dmarc.result == DMARCStatus.NONE
        assert dmarc.policy is None

    def test_parse_dmarc_result_none(self) -> None:
        """Test parsing DMARC result with None input."""
        assert parse_dmarc_result(None) is None
        assert parse_dmarc_result({}) is None

    def test_parse_reverse_dns_result(self) -> None:
        """Test parsing reverse DNS result from wire format."""
        data = {
            "result": "pass",
            "ip": "192.168.1.1",
            "hostname": "mail.example.com",
        }
        rdns = parse_reverse_dns_result(data)
        assert rdns is not None
        assert rdns.result == ReverseDNSStatus.PASS
        assert rdns.ip == "192.168.1.1"
        assert rdns.hostname == "mail.example.com"

    def test_parse_reverse_dns_result_fail(self) -> None:
        """Test parsing reverse DNS result when failed."""
        data = {"result": "fail", "ip": "192.168.1.1"}
        rdns = parse_reverse_dns_result(data)
        assert rdns is not None
        assert rdns.result == ReverseDNSStatus.FAIL
        assert rdns.hostname is None

    def test_parse_reverse_dns_result_none(self) -> None:
        """Test parsing reverse DNS result with None input."""
        assert parse_reverse_dns_result(None) is None
        assert parse_reverse_dns_result({}) is None

    def test_parse_auth_results_full(self) -> None:
        """Test parsing complete auth results matching wire format."""
        # Wire format as documented in test-email-api.md
        data = {
            "spf": {
                "result": "pass",
                "domain": "example.com",
                "details": "spf=pass (test email)",
            },
            "dkim": [
                {
                    "result": "pass",
                    "domain": "example.com",
                    "selector": "test",
                    "signature": "dkim=pass (test email)",
                }
            ],
            "dmarc": {
                "result": "pass",
                "policy": "none",
                "domain": "example.com",
                "aligned": True,
            },
            "reverseDns": {
                "result": "pass",
                "ip": "127.0.0.1",
                "hostname": "test.vaultsandbox.local",
            },
        }
        auth = parse_auth_results(data)

        # Verify SPF
        assert auth.spf is not None
        assert auth.spf.result == SPFStatus.PASS
        assert auth.spf.domain == "example.com"

        # Verify DKIM
        assert len(auth.dkim) == 1
        assert auth.dkim[0].result == DKIMStatus.PASS
        assert auth.dkim[0].selector == "test"

        # Verify DMARC
        assert auth.dmarc is not None
        assert auth.dmarc.result == DMARCStatus.PASS
        assert auth.dmarc.aligned is True

        # Verify Reverse DNS
        assert auth.reverse_dns is not None
        assert auth.reverse_dns.result == ReverseDNSStatus.PASS
        assert auth.reverse_dns.hostname == "test.vaultsandbox.local"

        # Verify validation passes
        validation = auth.validate()
        assert validation.passed is True
        assert validation.spf_passed is True
        assert validation.dkim_passed is True
        assert validation.dmarc_passed is True
        assert validation.reverse_dns_passed is True

    def test_parse_auth_results_all_fail(self) -> None:
        """Test parsing auth results when all checks fail."""
        data = {
            "spf": {"result": "fail", "domain": "example.com"},
            "dkim": [{"result": "fail", "domain": "example.com"}],
            "dmarc": {"result": "fail", "policy": "reject"},
            "reverseDns": {"result": "fail", "ip": "127.0.0.1"},
        }
        auth = parse_auth_results(data)
        validation = auth.validate()

        assert validation.passed is False
        assert validation.spf_passed is False
        assert validation.dkim_passed is False
        assert validation.dmarc_passed is False
        assert validation.reverse_dns_passed is False
        assert len(validation.failures) == 4

    def test_parse_auth_results_empty(self) -> None:
        """Test parsing auth results with empty/None input."""
        auth = parse_auth_results(None)
        assert auth.spf is None
        assert auth.dkim == []
        assert auth.dmarc is None
        assert auth.reverse_dns is None

        auth = parse_auth_results({})
        assert auth.spf is None
        assert auth.dkim == []
        assert auth.dmarc is None
        assert auth.reverse_dns is None
