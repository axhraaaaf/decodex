import re
from typing import Any, Dict, List, Optional
from decodeX.core.detection_engine import score_language
from decodeX.core.ioc_extractor import extract_iocs, get_malware_score

def score_xor_key(data: bytes, key: bytes) -> Dict[str, Any]:
    """
    Score a XOR key based on how well it deobfuscates the data.
    """
    # Apply key to data (simplified repeating-key XOR)
    decoded_bytes = _apply_xor(data, key)
    try:
        text = decoded_bytes.decode("latin-1", errors="ignore")
    except Exception:
        return {"confidence": 0, "reason": "Failed to decode"}

    # 1. Printable Ratio (0.0 to 1.0)
    import string
    printable_chars = set(string.printable.encode())
    match_count = sum(1 for b in decoded_bytes if b in printable_chars)
    printable_ratio = match_count / len(decoded_bytes) if decoded_bytes else 0

    # 2. English Language Score (0.0 to 1.0)
    lang_score = score_language(text)

    # 3. Malware Indicators & IOCs
    malware_info = get_malware_score(text)
    malware_confidence = malware_info["confidence"]

    # Weighted Confidence Calculation
    # We prioritize language and malware indicators
    weights = {
        "printable": 0.2,
        "language": 0.4,
        "malware": 0.4
    }

    final_confidence = (
        (printable_ratio * weights["printable"]) +
        (lang_score * weights["language"]) +
        (malware_confidence * weights["malware"])
    )

    return {
        "key": key.hex(),
        "confidence": round(final_confidence, 2),
        "printable_ratio": round(printable_ratio, 2),
        "language_score": round(lang_score, 2),
        "malware_indicators": malware_info["indicators"],
        "decoded_preview": text[:100]
    }

def _apply_xor(data: bytes, key: bytes) -> bytes:
    """Apply repeating-key XOR."""
    if not key: return data
    key_len = len(key)
    return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

def find_best_single_byte_key(data: bytes) -> Dict[str, Any]:
    """Brute force single-byte XOR and return best candidate."""
    best_key = 0
    max_confidence = 0
    best_result = {}

    # Limit sample for performance
    sample = data[:4096]
    
    for k in range(256):
        res = score_xor_key(sample, bytes([k]))
        if res["confidence"] > max_confidence:
            max_confidence = res["confidence"]
            best_key = k
            best_result = res

    best_result["key_val"] = best_key
    return best_result

def estimate_repeating_key_length(data: bytes, max_len: int = 32) -> List[tuple[int, float]]:
    """Estimate repeating key length using Hamming distance (Kasiski/IC variant)."""
    # Implementation simplified for Tier 2
    # We'll just return a list of likely lengths
    return [(i, 0.5) for i in range(2, 8)] # Placeholder
