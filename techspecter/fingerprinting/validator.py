"""Fingerprint database validation utilities."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError as PydanticValidationError

from techspecter.exceptions import InvalidFingerprintError
from techspecter.fingerprinting.loader import resolve_signatures_directory
from techspecter.fingerprinting.models import Fingerprint, FingerprintPattern, VersionPattern

_VALID_MATCHERS = frozenset({"string", "regex", "filename", "sourcemap", "global"})
_REQUIRED_FIELDS = frozenset({"id", "name", "category", "patterns"})


@dataclass(slots=True)
class FingerprintValidationIssue:
    """Single validation issue for a fingerprint file."""

    file: str
    fingerprint_id: str | None
    message: str
    severity: str = "error"


@dataclass(slots=True)
class FingerprintValidationReport:
    """Aggregated validation results for a fingerprint database."""

    directory: Path
    valid_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    issues: list[FingerprintValidationIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Return whether the database passed validation without errors."""
        return self.error_count == 0


class FingerprintValidator:
    """Validate fingerprint JSON files for schema and quality issues."""

    def __init__(self, signatures_dir: Path | str | None = None) -> None:
        """Initialize the validator.

        Args:
            signatures_dir: Optional fingerprints directory path.
        """
        self._signatures_dir = resolve_signatures_directory(signatures_dir)

    @property
    def signatures_dir(self) -> Path:
        """Return the active fingerprints directory."""
        return self._signatures_dir

    def validate_all(self) -> FingerprintValidationReport:
        """Validate every JSON fingerprint in the database directory.

        Returns:
            Validation report with errors and warnings.
        """
        report = FingerprintValidationReport(directory=self._signatures_dir)
        seen_ids: dict[str, str] = {}
        seen_names: dict[str, str] = {}

        for json_file in sorted(self._signatures_dir.glob("*.json")):
            if json_file.name == "schema.json":
                continue
            fingerprint = self._load_fingerprint(json_file, report)
            if fingerprint is None:
                continue

            self._validate_fingerprint(json_file, fingerprint, report, seen_ids, seen_names)
            report.valid_count += 1

        return report

    def validate_file(self, json_file: Path) -> FingerprintValidationReport:
        """Validate a single fingerprint JSON file.

        Args:
            json_file: Path to the fingerprint JSON file.

        Returns:
            Validation report for the file.
        """
        report = FingerprintValidationReport(directory=json_file.parent)
        fingerprint = self._load_fingerprint(json_file, report)
        if fingerprint is not None:
            self._validate_fingerprint(json_file, fingerprint, report, {}, {})
            report.valid_count = 1
        return report

    def _load_fingerprint(
        self,
        json_file: Path,
        report: FingerprintValidationReport,
    ) -> Fingerprint | None:
        """Load and parse a fingerprint file, recording errors on failure."""
        try:
            raw = json_file.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except OSError as exc:
            self._add_issue(report, json_file.name, None, f"Unable to read file: {exc}")
            return None
        except json.JSONDecodeError as exc:
            self._add_issue(report, json_file.name, None, f"Broken JSON: {exc}")
            return None

        if not isinstance(payload, dict):
            self._add_issue(report, json_file.name, None, "Fingerprint root must be a JSON object.")
            return None

        missing = _REQUIRED_FIELDS - payload.keys()
        if missing:
            self._add_issue(
                report,
                json_file.name,
                payload.get("id"),
                f"Missing required fields: {', '.join(sorted(missing))}",
            )
            return None

        try:
            return Fingerprint.model_validate(payload)
        except PydanticValidationError as exc:
            self._add_issue(report, json_file.name, payload.get("id"), f"Invalid schema: {exc}")
            return None

    def _validate_fingerprint(
        self,
        json_file: Path,
        fingerprint: Fingerprint,
        report: FingerprintValidationReport,
        seen_ids: dict[str, str],
        seen_names: dict[str, str],
    ) -> None:
        """Run semantic validation checks on a loaded fingerprint."""
        file_name = json_file.name

        if fingerprint.id in seen_ids:
            self._add_issue(
                report,
                file_name,
                fingerprint.id,
                f"Duplicate ID '{fingerprint.id}' (also in {seen_ids[fingerprint.id]})",
            )
        else:
            seen_ids[fingerprint.id] = file_name

        normalized_name = fingerprint.name.strip().lower()
        if normalized_name in seen_names:
            self._add_warning(
                report,
                file_name,
                fingerprint.id,
                f"Duplicate name '{fingerprint.name}' (also in {seen_names[normalized_name]})",
            )
        else:
            seen_names[normalized_name] = file_name

        if json_file.stem != fingerprint.id and json_file.stem != "schema":
            self._add_warning(
                report,
                file_name,
                fingerprint.id,
                f"Filename stem '{json_file.stem}' differs from fingerprint id '{fingerprint.id}'",
            )

        if not fingerprint.patterns:
            self._add_issue(report, file_name, fingerprint.id, "Fingerprint has no patterns.")

        for index, pattern in enumerate(fingerprint.patterns):
            self._validate_pattern(report, file_name, fingerprint.id, pattern, index)

        for index, version_pattern in enumerate(fingerprint.version_patterns):
            self._validate_version_pattern(
                report,
                file_name,
                fingerprint.id,
                version_pattern,
                index,
            )

    def _validate_pattern(
        self,
        report: FingerprintValidationReport,
        file_name: str,
        fingerprint_id: str | None,
        pattern: FingerprintPattern,
        index: int,
    ) -> None:
        """Validate a single detection pattern."""
        if pattern.matcher not in _VALID_MATCHERS:
            self._add_issue(
                report,
                file_name,
                fingerprint_id,
                f"patterns[{index}]: unsupported matcher '{pattern.matcher}'",
            )
            return

        if not pattern.pattern.strip():
            self._add_issue(
                report,
                file_name,
                fingerprint_id,
                f"patterns[{index}]: pattern must not be empty",
            )

        if pattern.matcher == "regex":
            self._validate_regex(report, file_name, fingerprint_id, pattern.pattern, pattern.flags)

    def _validate_version_pattern(
        self,
        report: FingerprintValidationReport,
        file_name: str,
        fingerprint_id: str | None,
        version_pattern: VersionPattern,
        index: int,
    ) -> None:
        """Validate a version extraction pattern."""
        if not version_pattern.pattern.strip():
            self._add_issue(
                report,
                file_name,
                fingerprint_id,
                f"version_patterns[{index}]: pattern must not be empty",
            )
            return
        self._validate_regex(
            report,
            file_name,
            fingerprint_id,
            version_pattern.pattern,
            version_pattern.flags,
            label=f"version_patterns[{index}]",
        )

    def _validate_regex(
        self,
        report: FingerprintValidationReport,
        file_name: str,
        fingerprint_id: str | None,
        expression: str,
        flags: str | None,
        *,
        label: str = "pattern",
    ) -> None:
        """Validate that a regular expression compiles."""
        flag_value = _compile_flags(flags)
        try:
            re.compile(expression, flag_value)
        except re.error as exc:
            self._add_issue(
                report,
                file_name,
                fingerprint_id,
                f"{label}: invalid regex: {exc}",
            )

    def _add_issue(
        self,
        report: FingerprintValidationReport,
        file_name: str,
        fingerprint_id: str | None,
        message: str,
    ) -> None:
        """Record a validation error."""
        report.error_count += 1
        report.issues.append(
            FingerprintValidationIssue(
                file=file_name,
                fingerprint_id=fingerprint_id,
                message=message,
                severity="error",
            )
        )

    def _add_warning(
        self,
        report: FingerprintValidationReport,
        file_name: str,
        fingerprint_id: str | None,
        message: str,
    ) -> None:
        """Record a validation warning."""
        report.warning_count += 1
        report.issues.append(
            FingerprintValidationIssue(
                file=file_name,
                fingerprint_id=fingerprint_id,
                message=message,
                severity="warning",
            )
        )


def validate_fingerprints_or_raise(
    signatures_dir: Path | str | None = None,
) -> FingerprintValidationReport:
    """Validate the fingerprint database and raise when errors are found.

    Args:
        signatures_dir: Optional fingerprints directory path.

    Returns:
        Validation report when no errors are present.

    Raises:
        InvalidFingerprintError: When validation errors exist.
    """
    report = FingerprintValidator(signatures_dir).validate_all()
    if not report.is_valid:
        messages = "; ".join(issue.message for issue in report.issues if issue.severity == "error")
        raise InvalidFingerprintError(messages)
    return report


def _compile_flags(flags: str | None) -> int:
    """Convert flag string to ``re`` flag bitmask."""
    flag_value = 0
    if flags:
        for flag in flags:
            if flag == "i":
                flag_value |= re.IGNORECASE
            elif flag == "m":
                flag_value |= re.MULTILINE
            elif flag == "s":
                flag_value |= re.DOTALL
    return flag_value
