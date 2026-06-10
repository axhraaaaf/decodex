import re
from typing import Any, Dict, List, Set

# Standard IOC Regex Patterns
URL_PATTERN = r"https?://[^\s/$.?#].[^\s]*"
DOMAIN_PATTERN = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b"
IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
PATH_PATTERN = r"\b[a-zA-Z]:\\[^/:*?\"<>|\r\n]+"
REGISTRY_PATTERN = r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CLASSES_ROOT|CURRENT_CONFIG)\\[^/:*?\"<>|\r\n]+"
MUTEX_PATTERN = r"Mutex:?\s*([a-zA-Z0-9_-]{4,})" # Simple heuristic for Mutex labels

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract various IOCs from the given text using regex.
    Returns a dictionary of deduplicated IOC lists.
    """
    if not text:
        return {}

    iocs = {
        "urls": _deduplicate(re.findall(URL_PATTERN, text)),
        "domains": _deduplicate(re.findall(DOMAIN_PATTERN, text)),
        "ips": _deduplicate(re.findall(IP_PATTERN, text)),
        "emails": _deduplicate(re.findall(EMAIL_PATTERN, text)),
        "paths": _deduplicate(re.findall(PATH_PATTERN, text)),
        "registry_keys": _deduplicate(re.findall(REGISTRY_PATTERN, text, re.IGNORECASE)),
        "mutexes": _deduplicate(re.findall(MUTEX_PATTERN, text))
    }

    # Filter out domains that are already in URLs
    domains_in_urls = [d for d in iocs["domains"] if any(d in url for url in iocs["urls"])]
    iocs["domains"] = [d for d in iocs["domains"] if d not in domains_in_urls]

    return {k: v for k, v in iocs.items() if v}

def _deduplicate(items: List[str]) -> List[str]:
    """Deduplicate and sort a list of strings."""
    return sorted(list(set(items)))

def get_malware_score(text: str) -> Dict[str, Any]:
    """
    Calculate a malware confidence score based on keywords and indicators.
    """
    if not text:
        return {"malware_score": 0, "confidence": 0}

    keywords = {
        "powershell": 20,
        "encodedcommand": 15,
        "iex": 15,
        "invoke-expression": 15,
        "downloadstring": 20,
        "invoke-webrequest": 20,
        "cmd.exe": 10,
        "rundll32": 15,
        "regsvr32": 15,
        "schtasks": 10,
        "sc.exe": 10,
        "net.exe": 5,
        "whoami": 5,
        "shellcode": 25,
        "mz": 20, # PE Header
        "pe": 20,
    }

    score = 0
    matches = []
    text_lower = text.lower()

    for kw, weight in keywords.items():
        if kw in text_lower:
            score += weight
            matches.append(kw)

    # Bonus for IOCs
    iocs = extract_iocs(text)
    ioc_count = sum(len(v) for v in iocs.values())
    score += ioc_count * 10
    
    # Cap score at 100
    final_score = min(100, score)
    confidence = final_score / 100.0

    return {
        "malware_score": int(final_score),
        "confidence": round(confidence, 2),
        "indicators": matches,
        "ioc_count": ioc_count
    }
