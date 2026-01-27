"""Email utility functions for VaultSandbox SDK."""

from __future__ import annotations

import base64
import binascii
import logging
from re import Pattern
from typing import TYPE_CHECKING, Any

from ..crypto import Keypair, decrypt_metadata, decrypt_parsed
from ..errors import InvalidPayloadError
from ..types import (
    Attachment,
    AuthResults,
    DKIMResult,
    DKIMStatus,
    DMARCPolicy,
    DMARCResult,
    DMARCStatus,
    EmailResponse,
    ReverseDNSResult,
    ReverseDNSStatus,
    SpamAction,
    SpamAnalysisResult,
    SpamAnalysisStatus,
    SpamSymbol,
    SPFResult,
    SPFStatus,
    WaitForEmailOptions,
)

if TYPE_CHECKING:
    from ..email import Email


def parse_spf_result(data: dict[str, Any] | None) -> SPFResult | None:
    """Parse SPF result from decrypted data.

    Args:
        data: The SPF result data.

    Returns:
        SPFResult or None if no data.
    """
    if not data:
        return None
    return SPFResult(
        result=SPFStatus(data.get("result", "none")),
        domain=data.get("domain"),
        ip=data.get("ip"),
        details=data.get("details"),
    )


def parse_dkim_results(data: list[dict[str, Any]] | None) -> list[DKIMResult]:
    """Parse DKIM results from decrypted data.

    Args:
        data: The DKIM results data.

    Returns:
        List of DKIMResult.
    """
    if not data:
        return []
    return [
        DKIMResult(
            result=DKIMStatus(item.get("result", "none")),
            domain=item.get("domain"),
            selector=item.get("selector"),
            signature=item.get("signature"),
        )
        for item in data
    ]


def parse_dmarc_result(data: dict[str, Any] | None) -> DMARCResult | None:
    """Parse DMARC result from decrypted data.

    Args:
        data: The DMARC result data.

    Returns:
        DMARCResult or None if no data.
    """
    if not data:
        return None
    policy = data.get("policy")
    return DMARCResult(
        result=DMARCStatus(data.get("result", "none")),
        policy=DMARCPolicy(policy) if policy else None,
        aligned=data.get("aligned"),
        domain=data.get("domain"),
    )


def parse_reverse_dns_result(data: dict[str, Any] | None) -> ReverseDNSResult | None:
    """Parse reverse DNS result from decrypted data.

    Args:
        data: The reverse DNS result data.

    Returns:
        ReverseDNSResult or None if no data.
    """
    if not data:
        return None
    return ReverseDNSResult(
        result=ReverseDNSStatus(data.get("result", "none")),
        ip=data.get("ip"),
        hostname=data.get("hostname"),
    )


def parse_auth_results(data: dict[str, Any] | None) -> AuthResults:
    """Parse authentication results from decrypted data.

    Args:
        data: The authentication results data.

    Returns:
        AuthResults instance.
    """
    if not data:
        return AuthResults()
    return AuthResults(
        spf=parse_spf_result(data.get("spf")),
        dkim=parse_dkim_results(data.get("dkim")),
        dmarc=parse_dmarc_result(data.get("dmarc")),
        reverse_dns=parse_reverse_dns_result(data.get("reverseDns")),
    )


def parse_spam_symbol(data: dict[str, Any]) -> SpamSymbol:
    """Parse a spam symbol from decrypted data.

    Args:
        data: The spam symbol data.

    Returns:
        SpamSymbol instance.
    """
    return SpamSymbol(
        name=data.get("name", ""),
        score=float(data.get("score", 0)),
        description=data.get("description"),
        options=data.get("options"),
    )


def parse_spam_analysis(data: dict[str, Any] | None) -> SpamAnalysisResult | None:
    """Parse spam analysis results from decrypted data.

    Args:
        data: The spam analysis data.

    Returns:
        SpamAnalysisResult or None if no data.
    """
    if not data:
        return None

    # Parse status
    status_str = data.get("status", "error")
    try:
        status = SpamAnalysisStatus(status_str)
    except ValueError:
        status = SpamAnalysisStatus.ERROR

    # Parse action if present
    action = None
    action_str = data.get("action")
    if action_str:
        try:
            action = SpamAction(action_str)
        except ValueError:
            action = None

    # Parse symbols
    symbols_data = data.get("symbols", [])
    symbols = [parse_spam_symbol(s) for s in symbols_data] if symbols_data else []

    return SpamAnalysisResult(
        status=status,
        score=data.get("score"),
        required_score=data.get("requiredScore"),
        action=action,
        is_spam=data.get("isSpam"),
        symbols=symbols,
        processing_time_ms=data.get("processingTimeMs"),
        info=data.get("info"),
    )


def parse_attachments(data: list[dict[str, Any]] | None) -> list[Attachment]:
    """Parse attachments from decrypted data.

    Args:
        data: The attachments data.

    Returns:
        List of Attachment instances.
    """
    if not data:
        return []

    logger = logging.getLogger(__name__)
    attachments = []
    for item in data:
        # Decode base64 content to bytes
        content_b64 = item.get("content", "")
        try:
            content = base64.b64decode(content_b64)
        except binascii.Error as e:
            logger.warning(f"Failed to decode attachment base64: {e}")
            content = b""

        attachments.append(
            Attachment(
                filename=item.get("filename", ""),
                content_type=item.get("contentType", "application/octet-stream"),
                size=item.get("size", 0),
                content=content,
                content_id=item.get("contentId"),
                content_disposition=item.get("contentDisposition"),
                checksum=item.get("checksum"),
            )
        )
    return attachments


def decode_plain_email_response(
    email_response: EmailResponse,
) -> dict[str, Any]:
    """Decode a plain (non-encrypted) email response into its components.

    Args:
        email_response: The plain email response from the server.

    Returns:
        Dictionary with decoded email data.

    Raises:
        InvalidPayloadError: If base64 decoding or JSON parsing fails.
    """
    import json

    # Decode base64 metadata
    metadata_b64 = email_response.get("metadata", "")
    try:
        metadata = (
            json.loads(base64.b64decode(metadata_b64).decode("utf-8")) if metadata_b64 else {}
        )
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InvalidPayloadError(f"Failed to decode email metadata: {e}") from e

    # Decode base64 parsed content
    parsed_b64 = email_response.get("parsed", "")
    try:
        parsed = json.loads(base64.b64decode(parsed_b64).decode("utf-8")) if parsed_b64 else {}
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InvalidPayloadError(f"Failed to decode email parsed content: {e}") from e

    return {
        "id": email_response["id"],
        "inbox_id": email_response.get("inboxId"),
        "received_at": email_response.get("receivedAt") or metadata.get("receivedAt"),
        "is_read": email_response.get("isRead", False),
        "from_address": metadata.get("from", ""),
        "to": metadata.get("to", []),
        "subject": metadata.get("subject", ""),
        "text": parsed.get("text"),
        "html": parsed.get("html"),
        "headers": parsed.get("headers", {}),
        "attachments": parse_attachments(parsed.get("attachments")),
        "links": parsed.get("links", []),
        "auth_results": parse_auth_results(parsed.get("authResults")),
        "spam_analysis": parse_spam_analysis(parsed.get("spamAnalysis")),
        "metadata": metadata,
        "parsed_metadata": parsed.get("metadata", {}),
    }


def decrypt_email_response(
    email_response: EmailResponse,
    keypair: Keypair | None,
    pinned_server_key: str | None = None,
) -> dict[str, Any]:
    """Decrypt or decode an email response into its components.

    Handles both encrypted and plain email formats based on field presence.

    Args:
        email_response: The email response from the server (encrypted or plain).
        keypair: The keypair to use for decryption (required for encrypted emails).
        pinned_server_key: The pinned server signature public key (base64url)
            from inbox creation. If provided, validates server key matches.

    Returns:
        Dictionary with decrypted/decoded email data.
    """
    # Check if this is an encrypted or plain email based on field presence
    if "encryptedMetadata" in email_response:
        # Encrypted email - decrypt
        if keypair is None:
            raise RuntimeError("Encrypted email received but no keypair provided")

        # Decrypt metadata (with server key validation per Section 8)
        metadata = decrypt_metadata(
            email_response["encryptedMetadata"],
            keypair,
            pinned_server_key=pinned_server_key,
        )

        # Decrypt parsed content (with server key validation per Section 8)
        parsed = decrypt_parsed(
            email_response["encryptedParsed"],
            keypair,
            pinned_server_key=pinned_server_key,
        )

        return {
            "id": email_response["id"],
            "inbox_id": email_response.get("inboxId"),
            "received_at": email_response.get("receivedAt") or metadata.get("receivedAt"),
            "is_read": email_response.get("isRead", False),
            "from_address": metadata.get("from", ""),
            "to": metadata.get("to", []),
            "subject": metadata.get("subject", ""),
            "text": parsed.get("text"),
            "html": parsed.get("html"),
            "headers": parsed.get("headers", {}),
            "attachments": parse_attachments(parsed.get("attachments")),
            "links": parsed.get("links", []),
            "auth_results": parse_auth_results(parsed.get("authResults")),
            "spam_analysis": parse_spam_analysis(parsed.get("spamAnalysis")),
            "metadata": metadata,
            "parsed_metadata": parsed.get("metadata", {}),
        }
    else:
        # Plain email - decode base64
        return decode_plain_email_response(email_response)


def matches_filter(
    email: Email,
    options: WaitForEmailOptions,
) -> bool:
    """Check if an email matches the filter options.

    Args:
        email: The email to check.
        options: The filter options.

    Returns:
        True if the email matches all filters.
    """
    # Check subject filter
    if options.subject is not None:
        if isinstance(options.subject, str):
            if options.subject not in (email.subject or ""):
                return False
        elif isinstance(options.subject, Pattern) and not options.subject.search(
            email.subject or ""
        ):
            return False

    # Check from filter
    if options.from_address is not None:
        if isinstance(options.from_address, str):
            if options.from_address not in (email.from_address or ""):
                return False
        elif isinstance(options.from_address, Pattern) and not options.from_address.search(
            email.from_address or ""
        ):
            return False

    # Check custom predicate
    return not (options.predicate is not None and not options.predicate(email))
