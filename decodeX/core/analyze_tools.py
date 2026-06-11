"""Malware-analysis style file analyzer."""

from __future__ import annotations

import argparse
import re
import string
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .entropy_tools import calculate_shannon_entropy, explain_entropy_level
from .magic_bytes import MagicDetection, analyze_magic_bytes
from .risk_engine import calculate_risk
from decodeX.utils import (
    print_error,
    print_info,
    print_key_value_table,
    print_table,
    run_with_status,
    style_entropy_level,
)
from decodeX.utils.console import RICH_AVAILABLE

COMMAND_NAME = "legacy-analyze"
DEFAULT_STRING_LIMIT = 25
DEFAULT_MIN_STRING_LENGTH = 4

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_PATTERN = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]{2,}\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz)\b",
    re.IGNORECASE,
)
REGISTRY_PATTERN = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s\"'<>]{3,}",
    re.IGNORECASE,
)
FILE_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\|%(?:APPDATA|TEMP|TMP|WINDIR|"
    r"USERPROFILE|PROGRAMFILES)%\\)[^\s\"'<>|]+",
    re.IGNORECASE,
)
TIMESTAMP_Z_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b"
)
GUID_PATTERN = re.compile(
    r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?"
)
PRIVATE_IP_PATTERN = re.compile(
    r"(?<![.\d])"
    r"(?:192\.168\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
    r"(?![\d.])"
)
SUSPICIOUS_EXTRACT_KEYWORDS = (
    "powershell",
    "cmd.exe",
    "downloadstring",
    "base64",
    "invoke-expression",
    "iex",
    "certutil",
    "bitsadmin",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "schtasks",
    "wmic",
    "virtualalloc",
    "writeprocessmemory",
    "createremotethread",
    "shellexecute",
    "createprocess",
    "urldownloadtofile",
    "winhttprequest",
    "ntqueryinformationprocess",
    "isdebuggerpresent",
)

COMMAND_KEYWORDS = (
    "powershell",
    "cmd.exe",
    "certutil",
    "bitsadmin",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "schtasks",
    "wmic",
)
NETWORK_KEYWORDS = (
    "urldownloadtofile",
    "internetopen",
    "internetreadfile",
    "winhttpopen",
    "winhttprequest",
    "socket",
    "connect",
    "recv",
    "send",
)
INJECTION_KEYWORDS = (
    "virtualalloc",
    "writeprocessmemory",
    "createremotethread",
    "openprocess",
    "loadlibrary",
    "getprocaddress",
    "ntunmapviewofsection",
)
PERSISTENCE_KEYWORDS = (
    "currentversion\\run",
    "currentversion\\runonce",
    "\\startup",
    "software\\microsoft\\windows\\currentversion\\run",
    "schtasks",
)
ANTI_ANALYSIS_KEYWORDS = (
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "vmware",
    "virtualbox",
    "sandbox",
    "wireshark",
    "procmon",
)
CERTIFICATE_KEYWORDS = (
    "certificate",
    "certification authority",
    "code signing",
    "digital signature",
    "root authority",
    "timestamp",
    "time-stamp",
    "microsoft corporation",
    "microsoft code signing",
    "microsoft root",
    "digicert",
    "globalsign",
    "sectigo",
    "verisign",
    "entrust",
    "thawte",
    "nshield",
    "tss esn",
)
SYSTEM_KEYWORDS = (
    "microsoft",
    "windows",
    "redmond",
    "system32",
    "syswow64",
    "appdata",
    "program files",
    "systemroot",
    "win32",
    "win64",
)
KNOWN_SYSTEM_DLLS = (
    "advapi32.dll",
    "crypt32.dll",
    "gdi32.dll",
    "kernel32.dll",
    "msvcrt.dll",
    "ntdll.dll",
    "ole32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "user32.dll",
    "winhttp.dll",
    "wininet.dll",
    "ws2_32.dll",
)
API_KEYWORDS = (
    *COMMAND_KEYWORDS,
    *NETWORK_KEYWORDS,
    *INJECTION_KEYWORDS,
    *PERSISTENCE_KEYWORDS,
    *ANTI_ANALYSIS_KEYWORDS,
    "createfile",
    "readfile",
    "writefile",
    "regopenkey",
    "regsetvalue",
    "createprocess",
    "shellexecute",
    "createservice",
    "startservice",
    "cryptdecrypt",
    "cryptencrypt",
)
COMPANY_KEYWORDS = (
    " corporation",
    " company",
    " technologies",
    " software",
    " inc.",
    " ltd",
    " llc",
    " gmbh",
)
INSTALLER_KEYWORDS = (
    "setup",
    "installer",
    "installshield",
    "nsis",
    "wix",
    "msiexec",
    ".msi",
)
COMMON_SHORT_TOKENS = {
    "http",
    "post",
    "user",
    "path",
    "temp",
    "null",
    "true",
    "file",
    "data",
    "text",
    "code",
    "main",
}
MANAGED_NAMESPACE_ROOTS = {
    "system",
    "microsoft",
    "windows",
    "storeinstaller",
    "newtonsoft",
    "xamlgeneratednamespace",
}


@dataclass(frozen=True)
class ExtractedString:
    """A printable string extracted from a file."""

    offset: int
    encoding: str
    value: str


@dataclass(frozen=True)
class SuspiciousIndicator:
    """A heuristic malware-analysis indicator."""

    severity: str
    category: str
    evidence: str


@dataclass(frozen=True)
class FileAnalysis:
    """Complete malware-analysis summary for a file."""

    path: Path
    size: int
    md5: str
    sha256: str
    entropy: float
    entropy_level: str
    magic: MagicDetection
    strings: list[ExtractedString]
    string_count: int
    indicators: list[SuspiciousIndicator]


def analyze_file(
    file_path: str | Path,
    *,
    string_limit: int | None = DEFAULT_STRING_LIMIT,
    min_string_length: int = DEFAULT_MIN_STRING_LENGTH,
) -> FileAnalysis:
    """Analyze a file and return hashes, entropy, strings, and indicators."""
    path = Path(file_path)
    if string_limit is not None and string_limit < 1:
        raise ValueError("string_limit must be at least 1.")
    if min_string_length < 3:
        raise ValueError("min_string_length must be at least 3.")

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise OSError(f"Could not read file '{path}': {exc.strerror}") from exc

    entropy = calculate_shannon_entropy(data) if data else 0.0
    entropy_level = explain_entropy_level(entropy)
    magic = analyze_magic_bytes(path)
    from decodeX.plugins.strings_plugin import StringsPlugin
    strings_plugin = StringsPlugin()
    strings_result = strings_plugin.analyze(data, min_length=min_string_length)
    
    extracted_strings = [
        ExtractedString(
            offset=item["offset"], 
            encoding=item["encoding"], 
            value=item["value"]
        )
        for item in strings_result["extracted"]
    ]
    indicators = find_suspicious_indicators(
        data=data,
        extracted_strings=extracted_strings,
        entropy=entropy,
        magic=magic,
    )

    from decodeX.plugins.hash_plugin import HashPlugin
    hash_plugin = HashPlugin()
    hashes = hash_plugin.analyze(data)

    return FileAnalysis(
        path=path,
        size=len(data),
        md5=hashes["md5"],
        sha256=hashes["sha256"],
        entropy=entropy,
        entropy_level=entropy_level,
        magic=magic,
        strings=extracted_strings if string_limit is None else extracted_strings[:string_limit],
        string_count=len(extracted_strings),
        indicators=indicators,
    )


def categorize_strings(
    extracted_strings: list[ExtractedString],
) -> dict[str, list[str]]:
    """Categorize extracted strings into labelled buckets in a single pass.

    Returns a dict with keys: urls, ips, paths, registry, suspicious_keywords.
    Each value is a deduplicated, sorted list of matched strings.
    Designed for performance on large files — all patterns are precompiled
    module-level constants and deduplication uses set() internally.
    """
    urls: set[str] = set()
    ips: set[str] = set()
    paths: set[str] = set()
    registry: set[str] = set()
    suspicious: set[str] = set()

    for item in extracted_strings:
        value = item.value
        lowered = value.lower()

        # URLs
        for m in URL_PATTERN.finditer(value):
            urls.add(m.group(0).rstrip(".,);]"))

        # IPs (public + RFC-1918 private ranges via dedicated pattern)
        for m in IP_PATTERN.finditer(value):
            ips.add(m.group(0))
        for m in PRIVATE_IP_PATTERN.finditer(value):
            ips.add(m.group(0))

        # File paths
        for m in FILE_PATH_PATTERN.finditer(value):
            paths.add(m.group(0))

        # Registry keys
        for m in REGISTRY_PATTERN.finditer(value):
            registry.add(m.group(0))

        # Suspicious keywords (case-insensitive substring search)
        for keyword in SUSPICIOUS_EXTRACT_KEYWORDS:
            if keyword in lowered:
                suspicious.add(keyword)

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "paths": sorted(paths),
        "registry": sorted(registry),
        "suspicious_keywords": sorted(suspicious),
    }


def build_analyst_report(
    file_path: str | Path,
    *,
    min_string_length: int = DEFAULT_MIN_STRING_LENGTH,
) -> dict[str, Any]:
    """Build the structured JSON report used for PE triage workflows."""
    analysis = analyze_file(
        file_path,
        string_limit=None,
        min_string_length=min_string_length,
    )
    return build_structured_report(analysis)


def build_structured_report(analysis: FileAnalysis) -> dict[str, Any]:
    """Group extracted data by analyst meaning and add an inference layer."""
    sections: dict[str, list[dict[str, Any]]] = {
        "certificate_metadata": [],
        "strings_of_interest": [],
        "paths_and_domains": [],
        "system_artifacts": [],
        "suspicious_indicators": [],
        "generic_strings": [],
    }

    for value, occurrences in _group_extracted_strings(analysis.strings):
        section_name, details = _classify_report_string(value, occurrences)
        sections[section_name].append(_make_report_entry(value, occurrences, details))

    # Legacy 0-10 score kept for backwards-compatible fields (e.g., type_guess priority).
    legacy_score, _ = _score_report(analysis, sections)
    type_guess = _guess_type(analysis, sections, legacy_score)

    # Inference Layer
    behavior_hints = _infer_malware_behavior(analysis, sections)
    file_purpose = _infer_file_purpose(analysis, sections, behavior_hints)
    ioc_candidates = _extract_ioc_candidates(sections)

    partial_report: dict[str, Any] = {
        "sections": sections,
        "analysis": {
            "possible_packers": _build_possible_packers(analysis, sections),
            "possible_functionality": behavior_hints,
            "possible_file_purpose": file_purpose,
        },
        "raw_metadata": {
            "entropy": analysis.entropy,
            "magic": analysis.magic.detected_type,
        },
    }
    risk = calculate_risk(partial_report)

    # Final CODEx compliant structure
    return {
        "file_summary": {
            "type_guess": type_guess,
            "risk_score": risk["risk_score"],
            "verdict": risk["verdict"],
            "risk_level": f"{risk['verdict']} ({risk['risk_score']//10}/10)",
            "confidence": _report_confidence(analysis, sections),
        },
        "sections": sections,
        "analysis": {
            "high_value_findings": _build_high_value_findings(
                analysis,
                sections,
                legacy_score,
                type_guess,
            ),
            "possible_packers": _build_possible_packers(analysis, sections),
            "possible_functionality": behavior_hints,
            "ioc_candidates": ioc_candidates,
            "file_purpose": file_purpose
        },
        "raw_data_reference": {
            "preserved": True,
            "note": "All entries keep original offset and encoding"
        }
    }


def _infer_malware_behavior(analysis: FileAnalysis, sections: dict) -> list[str]:
    """Infers potential malware behaviors based on findings."""
    behaviors = []
    
    # 1. Persistence
    has_persistence = False
    for entry in sections.get("paths_and_domains", []):
        if "PERSISTENCE" in entry.get("tags", []):
            has_persistence = True
            break
    if has_persistence:
        behaviors.append("persistence")

    # 2. Injection
    has_injection = False
    for entry in sections.get("strings_of_interest", []):
        val = str(entry.get("value", "")).lower()
        if any(kw in val for kw in ["virtualalloc", "createremotethread", "writeprocessmemory"]):
            has_injection = True
            break
    if has_injection:
        behaviors.append("injection")

    # 3. Networking
    has_net = False
    for entry in sections.get("paths_and_domains", []):
        if "NETWORK" in entry.get("tags", []):
            has_net = True
            break
    if has_net:
        behaviors.append("networking")

    # 4. Obfuscation
    if sections.get("suspicious_indicators"):
        behaviors.append("obfuscation")
        
    return sorted(list(set(behaviors)))


def _infer_file_purpose(analysis: FileAnalysis, sections: dict, behaviors: list[str]) -> str:
    """Infers the likely purpose of the file."""
    if "persistence" in behaviors and "networking" in behaviors:
        return "dropper / backdoor"
    if "injection" in behaviors:
        return "malicious agent / injector"
    
    # Check for installer indicators
    lowered_path = str(analysis.path).lower()
    if "setup" in lowered_path or "install" in lowered_path:
        return "installer"
        
    for entry in sections.get("system_artifacts", []):
        if "MANIFEST" in entry.get("tags", []):
            return "legit app (estimated)"
            
    return "unknown"


def _extract_ioc_candidates(sections: dict) -> list[str]:
    """Extracts deduplicated IOC candidates from analysis sections."""
    candidates = set()
    
    # Domains and IPs
    for entry in sections.get("paths_and_domains", []):
        for match in entry.get("matches", []):
            if match.get("type") in ["URL", "IP address", "domain"]:
                candidates.add(match["value"])
                
    # Unique/Suspicious strings
    for entry in sections.get("suspicious_indicators", []):
        val = entry.get("value", "")
        if len(val) > 10 and not val.isspace():
            candidates.add(val)
            
    return sorted(list(candidates))


def _group_extracted_strings(
    strings_found: list[ExtractedString],
) -> list[tuple[str, list[ExtractedString]]]:
    """Group duplicate strings while preserving every raw occurrence."""
    grouped: dict[str, list[ExtractedString]] = {}
    for item in strings_found:
        grouped.setdefault(item.value, []).append(item)

    return sorted(grouped.items(), key=lambda pair: pair[1][0].offset)


def _classify_report_string(
    value: str,
    occurrences: list[ExtractedString],
) -> tuple[str, dict[str, Any]]:
    """Classify one unique extracted string into one report section."""
    # 1. certificate_metadata
    cert_details = _certificate_details(value)
    if cert_details:
        return "certificate_metadata", cert_details

    # 4. system_artifacts
    system_details = _system_artifact_details(value)
    if system_details:
        return "system_artifacts", system_details

    # 3. paths_and_domains
    path_details = _path_or_domain_details(value)
    if path_details:
        return "paths_and_domains", path_details

    # 5. suspicious_indicators
    suspicious_details = _suspicious_details(value, occurrences)
    if suspicious_details:
        return "suspicious_indicators", {
            "value": value,
            "reason": suspicious_details.get("reason", "Suspicious pattern detected.")
        }

    # 2. strings_of_interest
    interest_details = _interest_details(value)
    if interest_details:
        return "strings_of_interest", interest_details

    # 6. generic_strings
    return "generic_strings", {
        "tags": ["GENERIC"],
        "reason": "No strong security-relevant meaning matched current triage rules.",
    }


def _path_or_domain_details(value: str) -> dict[str, Any] | None:
    """Return IOC-style path/domain classification details when present."""
    if _looks_like_regex_pattern(value) or _looks_like_dotnet_assembly_reference(value):
        return None

    match_specs = (
        ("URL", URL_PATTERN, "NETWORK"),
        ("IP address", IP_PATTERN, "NETWORK"),
        ("registry path", REGISTRY_PATTERN, "REGISTRY"),
        ("file path", FILE_PATH_PATTERN, "PATH"),
        ("domain", DOMAIN_PATTERN, "NETWORK"),
    )
    matches: list[dict[str, str]] = []
    tags = {"IOC"}

    for match_type, pattern, tag in match_specs:
        for match in pattern.finditer(value):
            matched_value = match.group(0).rstrip(".,);]")
            if match_type == "domain" and _looks_like_managed_namespace(matched_value):
                continue
            candidate = {"type": match_type, "value": matched_value}
            if candidate not in matches:
                matches.append(candidate)
                tags.add(tag)

    lowered = value.lower()
    if any(keyword.lower() in lowered for keyword in PERSISTENCE_KEYWORDS):
        tags.add("PERSISTENCE")

    if not matches:
        return None

    match_types = sorted({item["type"] for item in matches})
    indicator_type = match_types[0] if len(match_types) == 1 else "mixed path/domain"
    return {
        "indicator_type": indicator_type,
        "matches": matches,
        "reason": f"Contains {', '.join(match_types)} candidate(s).",
        "tags": sorted(tags),
    }


def _certificate_details(value: str) -> dict[str, Any] | None:
    """Return code-signing metadata details when the string looks trust-related."""
    lowered = value.lower()
    tags = {"CERT"}

    if TIMESTAMP_Z_PATTERN.search(value):
        tags.add("TIMESTAMP")
        return {
            "group": "code signing / trust metadata",
            "reason": "Z-format timestamp commonly appears in signing or trust metadata.",
            "tags": sorted(tags),
        }

    keyword_hits = [
        keyword for keyword in CERTIFICATE_KEYWORDS if keyword in lowered
    ]
    if keyword_hits:
        if "timestamp" in lowered or "time-stamp" in lowered:
            tags.add("TIMESTAMP")
        return {
            "group": "code signing / trust metadata",
            "reason": f"Code signing or certificate authority term: {_preview_items(keyword_hits)}.",
            "tags": sorted(tags),
        }

    if len(value) > 5 and re.search(r"\b(?:CA|PCA)\b", value):
        return {
            "group": "code signing / trust metadata",
            "reason": "CA/PCA naming pattern often appears in certificate chains.",
            "tags": sorted(tags),
        }

    return None


def _system_artifact_details(value: str) -> dict[str, Any] | None:
    """Return system-artifact details for Windows and platform references."""
    lowered = value.lower()
    tags = {"SYSTEM"}
    reasons: list[str] = []

    if _looks_like_dotnet_assembly_reference(value):
        tags.add("DOTNET")
        reasons.append(".NET assembly or runtime metadata reference")

    if _looks_like_manifest_metadata(value):
        tags.add("MANIFEST")
        reasons.append("Windows application manifest compatibility metadata")

    dll_hits = [dll for dll in KNOWN_SYSTEM_DLLS if dll in lowered]
    if dll_hits:
        tags.add("DLL")
        reasons.append(f"Windows system DLL reference: {_preview_items(dll_hits)}")

    keyword_hits = [keyword for keyword in SYSTEM_KEYWORDS if keyword in lowered]
    if keyword_hits:
        reasons.append(f"Windows/platform reference: {_preview_items(keyword_hits)}")

    if re.search(r"\b(?:windows\s*)?(?:nt\s*)?\d+\.\d+(?:\.\d+){1,2}\b", lowered):
        tags.add("OS_BUILD")
        reasons.append("Version/build-like Windows or NT string.")

    if not reasons:
        return None

    return {
        "reason": "; ".join(reasons) + ".",
        "tags": sorted(tags),
    }


def _suspicious_details(
    value: str,
    occurrences: list[ExtractedString],
) -> dict[str, Any] | None:
    """Return suspicious indicator details for obfuscated or odd strings."""
    normalized = value.strip()
    if (
        _looks_like_manifest_metadata(normalized)
        or _looks_like_managed_symbol(normalized)
        or _looks_like_code_identifier(normalized)
    ):
        return None

    entropy = _string_entropy(value)
    tags = {"OBFUSCATION"}
    reasons: list[str] = []

    if _looks_like_hex_blob(normalized):
        tags.add("ENCODED")
        reasons.append("Long hex-like blob may be encoded or encrypted data")

    if _looks_like_base64_blob(normalized, entropy):
        tags.add("ENCODED")
        reasons.append("Long Base64-like blob may hide embedded data")

    if _looks_like_random_token(normalized, entropy):
        reasons.append(f"High-entropy mixed token ({entropy:.2f}) has random-looking structure")

    if _looks_like_low_entropy_token(normalized, entropy):
        reasons.append(f"Low-entropy repeated token ({entropy:.2f}) looks like padding or filler")

    if _looks_like_weird_short_token(normalized, len(occurrences)):
        tags.add("SHORT_TOKEN")
        reasons.append("Very short uppercase/digit token has little semantic meaning")

    if not reasons:
        return None

    if len(occurrences) > 1:
        reasons.append(f"Repeated {len(occurrences)} times")

    return {
        "reason": "; ".join(reasons) + ".",
        "tags": sorted(tags),
    }


def _interest_details(value: str) -> dict[str, Any] | None:
    """Return details for analyst-relevant but not directly suspicious strings."""
    lowered = value.lower()
    tags: set[str] = {"INTEREST"}
    reasons: list[str] = []

    api_hits = _keyword_hits(lowered, API_KEYWORDS)
    if api_hits:
        tags.add("API")
        if _keyword_hits(lowered, COMMAND_KEYWORDS):
            tags.add("LOLBIN")
        if _keyword_hits(lowered, NETWORK_KEYWORDS):
            tags.add("NETWORK")
        if _keyword_hits(lowered, INJECTION_KEYWORDS):
            tags.add("INJECTION")
        if _keyword_hits(lowered, PERSISTENCE_KEYWORDS):
            tags.add("PERSISTENCE")
        if _keyword_hits(lowered, ANTI_ANALYSIS_KEYWORDS):
            tags.add("ANTI_ANALYSIS")
        reasons.append(f"API-like or behavior keyword: {_preview_items(api_hits)}")

    company_hits = [keyword.strip() for keyword in COMPANY_KEYWORDS if keyword in lowered]
    if company_hits:
        tags.add("COMPANY")
        reasons.append("Company or vendor-looking string")

    installer_hits = _keyword_hits(lowered, INSTALLER_KEYWORDS)
    if installer_hits:
        tags.add("INSTALLER")
        reasons.append(f"Installer/setup keyword: {_preview_items(installer_hits)}")

    if not reasons:
        return None

    return {
        "reason": "; ".join(reasons) + ".",
        "tags": sorted(tags),
    }


def _make_report_entry(
    value: str,
    occurrences: list[ExtractedString],
    details: dict[str, Any],
) -> dict[str, Any]:
    """Build one JSON-ready report entry with preserved raw references."""
    first_occurrence = occurrences[0]
    entry: dict[str, Any] = {
        "value": value,
        "offset": first_occurrence.offset,
        "offset_hex": _format_offset(first_occurrence.offset),
        "encoding": first_occurrence.encoding,
        "occurrence_count": len(occurrences),
        "occurrences": [_format_occurrence(item) for item in occurrences],
        "entropy_hint": round(_string_entropy(value), 3),
    }

    for key, detail_value in details.items():
        entry[key] = detail_value

    return entry


def _score_report(
    analysis: FileAnalysis,
    sections: dict[str, list[dict[str, Any]]],
) -> tuple[int, str]:
    """Calculate the 0-10 triage score and convert it to a risk label."""
    score = 0

    if analysis.magic.detected_type == "EXE":
        score += 1
    if analysis.entropy >= 7.2:
        score += 3
    elif analysis.entropy >= 6.5:
        score += 2

    if sections["suspicious_indicators"]:
        score += min(3, len(sections["suspicious_indicators"]))
    if _has_section_tag(sections, "NETWORK"):
        score += 2
    if _has_section_tag(sections, "REGISTRY"):
        score += 1
    if _has_section_tag(sections, "PERSISTENCE"):
        score += 2
    if _has_section_tag(sections, "INJECTION"):
        score += 2
    if _has_section_tag(sections, "LOLBIN"):
        score += 2
    if _has_section_tag(sections, "ANTI_ANALYSIS"):
        score += 1

    if sections["certificate_metadata"] and score <= 3 and not sections["suspicious_indicators"]:
        score -= 1

    if _looks_like_signed_installer_without_strong_malware_behavior(sections):
        score = min(score, 6)

    score = max(0, min(score, 10))
    if score <= 3:
        return score, "benign-like"
    if score <= 6:
        return score, "suspicious"
    return score, "likely malicious"


def _guess_type(
    analysis: FileAnalysis,
    sections: dict[str, list[dict[str, Any]]],
    risk_score: int,
) -> str:
    """Guess PE purpose using installer, trust, and threat-behavior signals."""
    purpose = "unknown"
    if _has_section_tag(sections, "INSTALLER"):
        purpose = "installer"
    elif risk_score >= 7 and (
        _has_section_tag(sections, "NETWORK")
        or _has_section_tag(sections, "OBFUSCATION")
        or _has_section_tag(sections, "PERSISTENCE")
    ):
        purpose = "dropper"
    elif sections["certificate_metadata"] and risk_score <= 3:
        purpose = "legit app"

    if analysis.magic.detected_type == "EXE":
        return f"Portable Executable / {purpose}"
    if analysis.magic.is_known:
        return f"{analysis.magic.detected_type} / {purpose}"
    return purpose


def _looks_like_signed_installer_without_strong_malware_behavior(
    sections: dict[str, list[dict[str, Any]]],
) -> bool:
    """Return whether context should dampen risk for signed installer-like files."""
    if not sections["certificate_metadata"]:
        return False
    if not _has_section_tag(sections, "INSTALLER"):
        return False
    if any(
        _has_section_tag(sections, tag)
        for tag in ("PERSISTENCE", "INJECTION", "LOLBIN")
    ):
        return False

    cert_text = "\n".join(entry["value"].lower() for entry in sections["certificate_metadata"])
    has_trust_anchor = any(
        marker in cert_text
        for marker in ("microsoft corporation", "code signing", "certificate", "timestamp")
    )
    return has_trust_anchor


def _report_confidence(
    analysis: FileAnalysis,
    sections: dict[str, list[dict[str, Any]]],
) -> float:
    """Estimate confidence from file type, extracted strings, and signal volume."""
    classified_count = sum(
        len(entries)
        for name, entries in sections.items()
        if name != "generic_strings"
    )
    confidence = 0.35
    if analysis.magic.is_known:
        confidence += 0.15
    if analysis.string_count >= 20:
        confidence += 0.15
    elif analysis.string_count > 0:
        confidence += 0.05
    if classified_count:
        confidence += min(0.25, classified_count * 0.03)
    if sections["suspicious_indicators"] or sections["paths_and_domains"]:
        confidence += 0.10

    return round(min(confidence, 0.95), 2)


def _build_high_value_findings(
    analysis: FileAnalysis,
    sections: dict[str, list[dict[str, Any]]],
    risk_score: int,
    type_guess: str,
) -> list[dict[str, Any]]:
    """Create short, prioritized findings for fast triage."""
    findings: list[dict[str, Any]] = [
        {
            "finding": "possible file purpose",
            "evidence": type_guess,
            "priority": "high" if risk_score >= 7 else "medium" if risk_score >= 4 else "low",
        }
    ]

    if analysis.entropy >= 6.5:
        findings.append(
            {
                "finding": "elevated file entropy",
                "evidence": f"{analysis.entropy:.4f} bits/byte ({analysis.entropy_level})",
                "priority": "high" if analysis.entropy >= 7.2 else "medium",
            }
        )

    if sections["paths_and_domains"]:
        findings.append(
            {
                "finding": "IOC-like path/domain material",
                "evidence": _entry_preview(sections["paths_and_domains"]),
                "priority": "high",
            }
        )

    if sections["suspicious_indicators"]:
        findings.append(
            {
                "finding": "obfuscation or odd token indicators",
                "evidence": _entry_preview(sections["suspicious_indicators"]),
                "priority": "high" if risk_score >= 7 else "medium",
            }
        )

    behavior_tags = [
        tag
        for tag in ("PERSISTENCE", "INJECTION", "LOLBIN", "ANTI_ANALYSIS", "NETWORK")
        if _has_section_tag(sections, tag)
    ]
    if behavior_tags:
        findings.append(
            {
                "finding": "behavior-relevant strings",
                "evidence": ", ".join(behavior_tags),
                "priority": "high",
            }
        )

    if sections["certificate_metadata"]:
        findings.append(
            {
                "finding": "code signing / trust metadata present",
                "evidence": _entry_preview(sections["certificate_metadata"]),
                "priority": "medium",
            }
        )

    return findings


def _build_possible_packers(
    analysis: FileAnalysis,
    sections: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Infer possible packing or encoding from entropy and packer strings."""
    packers: list[dict[str, Any]] = []
    all_entries = _all_section_entries(sections)
    known_packer_hits = [
        entry["value"]
        for entry in all_entries
        if any(
            marker in entry["value"].lower()
            for marker in ("upx", "aspack", "themida", "vmprotect", "mpress", "pecompact")
        )
    ]

    if analysis.entropy >= 6.5:
        packers.append(
            {
                "name": "packed/compressed payload",
                "confidence": "high" if analysis.entropy >= 7.2 else "medium",
                "evidence": f"File entropy {analysis.entropy:.4f} bits/byte.",
            }
        )

    if known_packer_hits:
        packers.append(
            {
                "name": "known packer marker",
                "confidence": "medium",
                "evidence": _preview_items(known_packer_hits),
            }
        )

    encoded_entries = _entries_with_tag(sections, "ENCODED")
    if encoded_entries:
        packers.append(
            {
                "name": "embedded encoded strings",
                "confidence": "low",
                "evidence": _entry_preview(encoded_entries),
            }
        )

    return packers


def _build_possible_functionality(
    sections: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Summarize possible malware or installer behavior hinted by strings."""
    functionality: list[dict[str, Any]] = []
    feature_specs = (
        ("networking", "NETWORK", "medium"),
        ("persistence", "PERSISTENCE", "high"),
        ("process injection / dynamic loading", "INJECTION", "high"),
        ("command execution / LOLBin usage", "LOLBIN", "high"),
        ("anti-analysis awareness", "ANTI_ANALYSIS", "medium"),
        ("obfuscation", "OBFUSCATION", "medium"),
        ("installer behavior", "INSTALLER", "medium"),
    )

    for name, tag, confidence in feature_specs:
        entries = _entries_with_tag(sections, tag)
        if entries:
            functionality.append(
                {
                    "name": name,
                    "confidence": confidence,
                    "evidence": _entry_preview(entries),
                }
            )

    if not functionality:
        functionality.append(
            {
                "name": "unknown",
                "confidence": "low",
                "evidence": "No behavior-specific strings matched current heuristics.",
            }
        )

    return functionality


def _build_ioc_candidates(
    sections: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Extract threat-intel candidates from grouped report sections."""
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for entry in sections["paths_and_domains"]:
        matches = entry.get("matches") or [{"type": entry.get("indicator_type", "string"), "value": entry["value"]}]
        for match in matches:
            candidate = _ioc_entry(
                str(match["type"]).lower(),
                str(match["value"]),
                entry,
                "paths_and_domains",
            )
            if (candidate["type"], candidate["value"]) not in seen:
                seen.add((candidate["type"], candidate["value"]))
                candidates.append(candidate)

    for entry in sections["certificate_metadata"]:
        candidate = _ioc_entry(
            "certificate_metadata",
            entry["value"],
            entry,
            "certificate_metadata",
        )
        if (candidate["type"], candidate["value"]) not in seen:
            seen.add((candidate["type"], candidate["value"]))
            candidates.append(candidate)

    for entry in sections["suspicious_indicators"]:
        candidate = _ioc_entry(
            "suspicious_string",
            entry["value"],
            entry,
            "suspicious_indicators",
        )
        if (candidate["type"], candidate["value"]) not in seen:
            seen.add((candidate["type"], candidate["value"]))
            candidates.append(candidate)

    return candidates


def _ioc_entry(
    indicator_type: str,
    value: str,
    source_entry: dict[str, Any],
    source_section: str,
) -> dict[str, Any]:
    """Build an IOC candidate while preserving the raw string reference."""
    return {
        "type": indicator_type,
        "value": value,
        "offset": source_entry["offset"],
        "offset_hex": source_entry["offset_hex"],
        "encoding": source_entry["encoding"],
        "source_section": source_section,
    }


def _keyword_hits(lowered_value: str, keywords: tuple[str, ...]) -> list[str]:
    """Return sorted keyword hits in a lower-cased string."""
    return sorted({keyword for keyword in keywords if keyword.lower() in lowered_value})


def _looks_like_hex_blob(value: str) -> bool:
    """Return whether a string resembles a long hex-encoded blob."""
    compact = "".join(value.split())
    return len(compact) >= 16 and len(compact) % 2 == 0 and all(
        character in string.hexdigits for character in compact
    )


def _looks_like_regex_pattern(value: str) -> bool:
    """Return whether a path-like value is a regex pattern rather than an artifact."""
    stripped = value.strip()
    if not stripped:
        return False
    if stripped.startswith("^") or stripped.endswith("$"):
        return True
    return bool(re.search(r"\\[dDsSwW]|\[[^\]]+\]|\([^)]*\|[^)]*\)", stripped))


def _looks_like_managed_namespace(value: str) -> bool:
    """Return whether a dotted value is likely a .NET namespace, not a domain."""
    if "://" in value or "/" in value or "\\" in value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        return False
    if parts[0].lower() in MANAGED_NAMESPACE_ROOTS:
        return True
    return all(_is_pascal_or_upper_identifier(part) for part in parts)


def _looks_like_managed_symbol(value: str) -> bool:
    """Return whether a string looks like a compiler/runtime symbol from managed code."""
    if not value:
        return False
    if re.search(r"<[^>]+>(?:d__|b__|g__|c__|k__BackingField)", value):
        return True
    if re.search(r"<[^>]+>\d+__\d+", value):
        return True
    if re.search(r"<[^>]+>[ij]__\w+", value):
        return True
    if re.search(r"<\d+>__\w+", value):
        return True
    if value.startswith("__StaticArrayInitTypeSize="):
        return True
    if re.search(r"`\d+", value):
        return True
    managed_fragments = (
        "AsyncTaskMethodBuilder",
        "ConfiguredTaskAwaitable",
        "ValueTaskAwaiter",
        "TaskAwaiter",
        "MoveNextRunner",
        "IAsyncStateMachine",
    )
    return any(fragment in value for fragment in managed_fragments)


def _looks_like_dotnet_assembly_reference(value: str) -> bool:
    """Return whether a string is a .NET assembly-qualified reference."""
    lowered = value.lower()
    if re.fullmatch(
        r'\s*publickeytoken\s*=\s*"?[0-9a-fA-F]{8,16}"?\s*',
        value,
        re.IGNORECASE,
    ):
        return True
    return (
        "version=" in lowered
        and ("culture=" in lowered or "publickeytoken=" in lowered)
    )


def _looks_like_manifest_metadata(value: str) -> bool:
    """Return whether a string is normal Windows app manifest metadata."""
    lowered = value.lower().strip()
    manifest_markers = (
        "<supportedos",
        "supportedos id=",
        "<compatibility",
        "<application",
        "<assemblyidentity",
        "<trustinfo",
        "<requestedexecutionlevel",
        "urn:schemas-microsoft-com:asm.v",
        "xmlns=\"urn:schemas-microsoft-com",
    )
    if any(marker in lowered for marker in manifest_markers):
        return True
    return bool(GUID_PATTERN.search(value) and "<" in value and ">" in value)


def _looks_like_code_identifier(value: str) -> bool:
    """Return whether a string is likely a source/runtime identifier."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        return False
    if "_" in value and not value.startswith("__"):
        return True
    has_upper = any(character.isupper() for character in value)
    has_lower = any(character.islower() for character in value)
    return has_upper and has_lower and len(value) >= 12


def _is_pascal_or_upper_identifier(value: str) -> bool:
    """Return whether text resembles a managed-code identifier segment."""
    if not value or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        return False
    return value.isupper() or value[0].isupper()


def _looks_like_base64_blob(value: str, entropy: float) -> bool:
    """Return whether a string resembles Base64 or a similar encoded blob."""
    compact = "".join(value.split())
    return (
        len(compact) >= 24
        and bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact))
        and bool(re.search(r"[0-9+/=]", compact))
        and (entropy >= 4.0 or compact.endswith("="))
    )


def _looks_like_random_token(value: str, entropy: float) -> bool:
    """Return whether a string has high-entropy mixed-token structure."""
    return (
        len(value) >= 16
        and entropy >= 4.0
        and bool(re.search(r"[A-Z]", value))
        and bool(re.search(r"[a-z]", value))
        and bool(re.search(r"\d", value))
    )


def _looks_like_low_entropy_token(value: str, entropy: float) -> bool:
    """Return whether a string looks like repeated filler or padding."""
    if len(value) < 8 or entropy > 1.5:
        return False
    most_common_count = Counter(value).most_common(1)[0][1]
    return most_common_count / len(value) >= 0.70


def _looks_like_weird_short_token(value: str, occurrence_count: int) -> bool:
    """Return whether a short token resembles an opaque marker."""
    lowered = value.lower()
    if lowered in COMMON_SHORT_TOKENS:
        return False
    if not re.fullmatch(r"[A-Z0-9]{3,5}", value):
        return False
    has_digit = any(character.isdigit() for character in value)
    has_vowel = any(character in "AEIOU" for character in value)
    return has_digit or occurrence_count > 1 or not has_vowel


def _string_entropy(value: str) -> float:
    """Calculate string entropy safely for report hints."""
    if not value:
        return 0.0
    try:
        return calculate_shannon_entropy(value)
    except ValueError:
        return 0.0


def _has_section_tag(sections: dict[str, list[dict[str, Any]]], tag: str) -> bool:
    """Return whether any report entry has a specific tag."""
    return any(tag in entry.get("tags", []) for entry in _all_section_entries(sections))


def _entries_with_tag(
    sections: dict[str, list[dict[str, Any]]],
    tag: str,
) -> list[dict[str, Any]]:
    """Return report entries carrying a specific tag."""
    return [
        entry
        for entry in _all_section_entries(sections)
        if tag in entry.get("tags", [])
    ]


def _all_section_entries(sections: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Flatten report section entries."""
    entries: list[dict[str, Any]] = []
    for section_entries in sections.values():
        entries.extend(section_entries)
    return entries


def _entry_preview(entries: list[dict[str, Any]], *, limit: int = 3) -> str:
    """Return compact evidence text from report entries."""
    return _preview_items([str(entry["value"]) for entry in entries], limit=limit)


def _format_occurrence(item: ExtractedString) -> dict[str, Any]:
    """Format one raw string occurrence."""
    return {
        "offset": item.offset,
        "offset_hex": _format_offset(item.offset),
        "encoding": item.encoding,
    }


def _format_offset(offset: int) -> str:
    """Format a numeric offset as PE-analysis style hex."""
    return f"0x{offset:08X}"





def find_suspicious_indicators(
    *,
    data: bytes,
    extracted_strings: list[ExtractedString],
    entropy: float,
    magic: MagicDetection,
) -> list[SuspiciousIndicator]:
    """Find heuristic suspicious indicators from file metadata and strings."""
    indicators: list[SuspiciousIndicator] = []
    combined_text = "\n".join(item.value for item in extracted_strings)
    lowered_text = combined_text.lower()

    if magic.detected_type == "EXE":
        indicators.append(
            SuspiciousIndicator("Medium", "Executable", "MZ/PE executable header found.")
        )

    if entropy >= 7.2:
        indicators.append(
            SuspiciousIndicator(
                "High",
                "Packing/Encryption",
                f"Very high entropy ({entropy:.4f}) may indicate packing or encryption.",
            )
        )
    elif entropy >= 6.5:
        indicators.append(
            SuspiciousIndicator(
                "Medium",
                "Packing/Encryption",
                f"High entropy ({entropy:.4f}) may indicate compressed or packed data.",
            )
        )

    urls = _unique_matches(URL_PATTERN, combined_text)
    if urls:
        indicators.append(
            SuspiciousIndicator(
                "High",
                "Network",
                f"Embedded URL(s): {_preview_items(urls)}",
            )
        )

    ips = _unique_matches(IP_PATTERN, combined_text)
    if ips:
        indicators.append(
            SuspiciousIndicator(
                "Medium",
                "Network",
                f"Embedded IP address(es): {_preview_items(ips)}",
            )
        )

    domains = _unique_matches(DOMAIN_PATTERN, combined_text)
    if domains:
        indicators.append(
            SuspiciousIndicator(
                "Medium",
                "Network",
                f"Embedded domain(s): {_preview_items(domains)}",
            )
        )

    _append_keyword_indicator(
        indicators,
        lowered_text,
        COMMAND_KEYWORDS,
        "High",
        "Shell/LOLBins",
        "Command execution or living-off-the-land binary reference(s)",
    )
    _append_keyword_indicator(
        indicators,
        lowered_text,
        NETWORK_KEYWORDS,
        "Medium",
        "Network APIs",
        "Network-related API reference(s)",
    )
    _append_keyword_indicator(
        indicators,
        lowered_text,
        INJECTION_KEYWORDS,
        "High",
        "Process Injection",
        "Process injection or dynamic loading API reference(s)",
    )
    _append_keyword_indicator(
        indicators,
        lowered_text,
        PERSISTENCE_KEYWORDS,
        "High",
        "Persistence",
        "Persistence-related registry or scheduled task reference(s)",
    )
    _append_keyword_indicator(
        indicators,
        lowered_text,
        ANTI_ANALYSIS_KEYWORDS,
        "Medium",
        "Anti-analysis",
        "Debugger, VM, sandbox, or analyst-tool reference(s)",
    )

    if data.startswith(b"MZ") and magic.detected_type != "EXE":
        indicators.append(
            SuspiciousIndicator("Medium", "Header", "Raw bytes start with MZ signature.")
        )

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    indicators.sort(key=lambda item: (severity_order.get(item.severity, 9), item.category))
    return indicators


def register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register malware-analysis CLI command."""
    parser = subparsers.add_parser(
        COMMAND_NAME,
        help="Run malware-analysis style file triage.",
        description=(
            "Analyze hashes, entropy, magic bytes, strings, and suspicious indicators."
        ),
    )
    parser.add_argument("path", help="Path to the file to analyze.")
    parser.add_argument(
        "-s",
        "--strings",
        type=int,
        default=DEFAULT_STRING_LIMIT,
        help=f"Maximum extracted strings to display (default: {DEFAULT_STRING_LIMIT}).",
    )
    parser.add_argument(
        "--min-string",
        type=int,
        default=DEFAULT_MIN_STRING_LENGTH,
        help=f"Minimum printable string length (default: {DEFAULT_MIN_STRING_LENGTH}).",
    )
    parser.set_defaults(handler=handle_analyze_command)


def handle_analyze_command(args: argparse.Namespace) -> int:
    """Handle malware-analysis file triage."""
    try:
        analysis = run_with_status(
            "Analyzing file metadata, strings, and indicators...",
            lambda: analyze_file(
                args.path,
                string_limit=args.strings,
                min_string_length=args.min_string,
            ),
        )
    except (OSError, ValueError) as exc:
        print_error(f"Analyze error: {exc}")
        return 2

    print_analysis(analysis)
    return 0








def _append_keyword_indicator(
    indicators: list[SuspiciousIndicator],
    lowered_text: str,
    keywords: tuple[str, ...],
    severity: str,
    category: str,
    description: str,
) -> None:
    """Append a keyword-based indicator when any keyword appears."""
    matches = sorted(
        {
            keyword
            for keyword in keywords
            if keyword.lower() in lowered_text
        }
    )
    if not matches:
        return

    indicators.append(
        SuspiciousIndicator(
            severity,
            category,
            f"{description}: {_preview_items(matches)}",
        )
    )


def _unique_matches(pattern: re.Pattern[str], text: str) -> list[str]:
    """Return sorted unique regex matches."""
    return sorted({match.group(0) for match in pattern.finditer(text)})


def _preview_items(items: list[str], *, limit: int = 3) -> str:
    """Return a compact preview of matched strings."""
    preview = items[:limit]
    suffix = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(preview) + suffix


def _format_size(size: int) -> str:
    """Format byte size with a compact human-readable value."""
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.2f} KiB ({size} bytes)"
    return f"{size / (1024 * 1024):.2f} MiB ({size} bytes)"


def _severity_label(severity: str) -> str:
    """Return a styled severity label."""
    if not RICH_AVAILABLE:
        return severity

    styles = {
        "High": "bold red",
        "Medium": "bold yellow",
        "Low": "bold green",
    }
    style = styles.get(severity, "white")
    return f"[{style}]{severity}[/]"


def _safe_table_text(value: str, *, max_length: int = 110) -> str:
    """Trim and escape extracted strings for clean table rendering."""
    cleaned = "".join(character if character in string.printable else "." for character in value)
    cleaned = cleaned.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if len(cleaned) > max_length:
        cleaned = f"{cleaned[: max_length - 3]}..."
    if RICH_AVAILABLE:
        cleaned = cleaned.replace("[", "\\[")
    return cleaned


def _style_verdict(verdict: str) -> str:
    """Return a styled verdict string when Rich is available."""
    if not RICH_AVAILABLE:
        return verdict
    styles = {
        "Clean": "bold green",
        "Unknown": "bold yellow",
        "Suspicious": "bold orange1",
        "Malicious": "bold red",
    }
    style = styles.get(verdict, "white")
    return f"[{style}]{verdict}[/]"


def print_analysis(
    analysis: FileAnalysis,
    *,
    risk_score: int | None = None,
    verdict: str | None = None,
    categorized_strings: dict[str, list[str]] | None = None,
    yara_results: list[dict[str, Any]] | None = None,
) -> None:
    """Print a complete file analysis report."""
    rows: list[tuple[str, str]] = [
        ("Path", str(analysis.path)),
        ("File size", _format_size(analysis.size)),
        ("Detected type", analysis.magic.detected_type),
        ("Matched signature", analysis.magic.signature_hex),
        ("MD5", analysis.md5),
        ("SHA256", analysis.sha256),
        ("Entropy", f"{analysis.entropy:.4f} bits/byte"),
        ("Entropy level", style_entropy_level(analysis.entropy_level)),
        ("Strings extracted", str(analysis.string_count)),
        ("Indicators", str(len(analysis.indicators))),
    ]
    if risk_score is not None and verdict is not None:
        rows.append(("Risk score", f"{risk_score}/100"))
        rows.append(("Verdict", _style_verdict(verdict)))
    print_key_value_table("File triage summary", rows)

    if categorized_strings is not None:
        cat_rows: list[tuple[str, str]] = []
        label_map = {
            "urls": "URLs",
            "ips": "IPs",
            "paths": "File paths",
            "registry": "Registry keys",
            "suspicious_keywords": "Suspicious keywords",
        }
        for key, label in label_map.items():
            items = categorized_strings.get(key, [])
            if items:
                cat_rows.append((label, f"{len(items)}  {_preview_items(items)}"))
            else:
                cat_rows.append((label, "none"))
        print_key_value_table("Categorized strings", cat_rows)

    if analysis.indicators:
        print_table(
            "Suspicious indicators",
            (
                ("Severity", "bold"),
                ("Category", "cyan"),
                ("Evidence", "white"),
            ),
            (
                (
                    _severity_label(indicator.severity),
                    indicator.category,
                    _safe_table_text(indicator.evidence),
                )
                for indicator in analysis.indicators
            ),
        )
    else:
        print_info("No suspicious indicators found by the current heuristic set.")

    if yara_results:
        print_table(
            "YARA signature matches",
            (
                ("Rule Name", "bold magenta"),
                ("Severity", "bold"),
                ("Description", "white"),
                ("Hits", "cyan"),
            ),
            (
                (
                    finding.get("rule", "Unknown"),
                    _severity_label(finding.get("metadata", {}).get("severity", finding.get("metadata", {}).get("priority", "Medium")).capitalize()),
                    finding.get("metadata", {}).get("description", "No description provided."),
                    str(finding.get("matches", 0)),
                )
                for finding in yara_results
            ),
        )

    if analysis.strings:
        print_table(
            f"Extracted strings (top {len(analysis.strings)})",
            (
                ("Offset", "magenta"),
                ("Encoding", "cyan"),
                ("String", "white"),
            ),
            (
                (
                    f"0x{item.offset:08X}",
                    item.encoding,
                    _safe_table_text(item.value),
                )
                for item in analysis.strings
            ),
        )
    else:
        print_info("No printable strings found with the current minimum length.")

