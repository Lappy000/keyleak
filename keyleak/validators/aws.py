"""AWS key validator — uses STS GetCallerIdentity to verify credentials.

This validator checks AWS Access Key IDs (AKIA...) by calling the
AWS STS GetCallerIdentity API. This is one of the few AWS API calls
that works with any valid credentials regardless of IAM permissions.
"""

from __future__ import annotations

import time
from typing import Optional

from keyleak.validators import KeyStatus, ValidationResult


def validate(key: str, secret_key: Optional[str] = None) -> ValidationResult:
    """Validate an AWS Access Key ID.

    Note: Full validation requires both the Access Key ID and Secret Access Key.
    If only the Access Key ID is provided, we can only validate its format.
    If a secret key is also provided, we attempt STS GetCallerIdentity.

    Args:
        key: The AWS Access Key ID (AKIA...).
        secret_key: Optional AWS Secret Access Key for full validation.

    Returns:
        ValidationResult with the outcome.
    """
    start_time = time.time()

    # Format validation
    if not key.startswith("AKIA") or len(key) != 20:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="aws",
            status=KeyStatus.INVALID,
            message="Invalid AWS Access Key ID format (must be AKIA + 16 chars)",
            response_time_ms=round(elapsed, 2),
        )

    if secret_key is None:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="aws",
            status=KeyStatus.UNKNOWN,
            message="Format valid. Secret key required for full verification via STS.",
            response_time_ms=round(elapsed, 2),
        )

    # Full validation with boto3
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError

        client = boto3.client(
            "sts",
            aws_access_key_id=key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",
        )
        response = client.get_caller_identity()
        elapsed = (time.time() - start_time) * 1000

        account_id = response.get("Account", "unknown")
        arn = response.get("Arn", "unknown")
        user_id = response.get("UserId", "unknown")

        return ValidationResult(
            key_value=key,
            service="aws",
            status=KeyStatus.VALID,
            message=f"Key is valid. Account: {account_id}",
            account_info=f"ARN: {arn}, UserId: {user_id}",
            http_status=200,
            response_time_ms=round(elapsed, 2),
        )

    except ClientError as exc:
        elapsed = (time.time() - start_time) * 1000
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "InvalidClientTokenId":
            return ValidationResult(
                key_value=key,
                service="aws",
                status=KeyStatus.INVALID,
                message="AWS rejected the key: InvalidClientTokenId",
                http_status=403,
                response_time_ms=round(elapsed, 2),
            )
        elif error_code == "ExpiredToken":
            return ValidationResult(
                key_value=key,
                service="aws",
                status=KeyStatus.EXPIRED,
                message="AWS key has expired",
                http_status=403,
                response_time_ms=round(elapsed, 2),
            )
        else:
            return ValidationResult(
                key_value=key,
                service="aws",
                status=KeyStatus.ERROR,
                message=f"AWS error: {error_code} — {exc}",
                response_time_ms=round(elapsed, 2),
            )
    except Exception as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="aws",
            status=KeyStatus.ERROR,
            message=f"Failed to call STS: {exc}",
            response_time_ms=round(elapsed, 2),
        )
