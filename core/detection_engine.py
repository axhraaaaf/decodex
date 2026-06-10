import base64
import binascii
import gzip
import re
import string
import zlib
from typing import Any, Dict, List, Optional
from decodeX.core.entropy_tools import calculate_shannon_entropy

# --- Constants & Charsets ---
ENGLISH_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her", "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me", "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
    "people", "into", "year", "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first", "well", "even", "new", "want", "because", "any", "these", "give", "day", "most", "us", "hello",
    "secret", "password", "admin", "system", "cmd", "powershell", "http", "https", "download", "execute", "exec", "flag", "key", "token"
}

def detect_candidates(data: bytes | str) -> List[Dict[str, Any]]:
    """
    Main entry point for smart auto-detection.
    Returns a sorted list of candidate decoders with confidence scores.
    """
    if isinstance(data, str):
        raw_data = data.encode("latin-1", errors="ignore")
        text_data = data
    else:
        raw_data = data
        text_data = data.decode("latin-1", errors="ignore")

    candidates = []

    # 1. Base64
    candidates.append(_detect_base64(text_data))
    
    # 2. Hex
    candidates.append(_detect_hex(text_data))
    
    # 3. URL Encoding
    candidates.append(_detect_url(text_data))
    
    # 4. Binary
    candidates.append(_detect_binary(text_data))
    
    # 5. Base32
    candidates.append(_detect_base32(text_data))
    
    # 6. Gzip / Zlib
    candidates.append(_detect_compression(raw_data))
    
    # 7. UTF-16LE
    candidates.append(_detect_utf16le(raw_data))
    
    # 8. ROT13 / ROT47 / Caesar (Heuristic)
    candidates.append(_detect_caesar(text_data))
    
    # 9. XOR (Heuristic)
    candidates.append(_detect_xor_heuristic(raw_data))

    # Filter out failures and sort by confidence
    valid_candidates = [c for c in candidates if c["confidence"] > 0]
    valid_candidates.sort(key=lambda x: x["confidence"], reverse=True)
    
    return valid_candidates

def _detect_base64(text: str) -> Dict[str, Any]:
    norm = "".join(text.split())
    if len(norm) < 4: return {"decoder": "base64", "confidence": 0, "reason": "Too short"}
    
    # Check charset
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]*", norm):
        return {"decoder": "base64", "confidence": 0, "reason": "Invalid chars"}
    
    confidence = 0.6
    if norm.endswith("="): confidence += 0.3
    if len(norm) % 4 == 0: confidence += 0.05
    
    # URL-Safe variant check
    if "-" in norm or "_" in norm:
        return {"decoder": "base64_url", "confidence": confidence, "reason": "URL-safe charset detected"}
    
    return {"decoder": "base64", "confidence": confidence, "reason": "Standard Base64 pattern matched"}

def _detect_hex(text: str) -> Dict[str, Any]:
    norm = "".join(re.findall(r"[0-9A-Fa-f]", text))
    if not norm or len(norm) < 4: return {"decoder": "hex", "confidence": 0, "reason": "Too short"}
    
    ratio = len(norm) / len("".join(text.split()))
    if ratio < 0.8: return {"decoder": "hex", "confidence": 0, "reason": "Low hex density"}
    
    confidence = 0.7
    if len(norm) % 2 == 0: confidence += 0.2
    
    return {"decoder": "hex", "confidence": confidence, "reason": "High hex digit density"}

def _detect_url(text: str) -> Dict[str, Any]:
    if "%" not in text: return {"decoder": "url", "confidence": 0, "reason": "No % marker"}
    
    # Check for valid %XX patterns
    matches = re.findall(r"%[0-9A-Fa-f]{2}", text)
    if not matches: return {"decoder": "url", "confidence": 0, "reason": "No valid %XX patterns"}
    
    confidence = (len(matches) * 3) / len(text)
    confidence = min(0.95, confidence + 0.5)
    
    return {"decoder": "url", "confidence": confidence, "reason": "URL encoding markers detected"}

def _detect_binary(text: str) -> Dict[str, Any]:
    norm = "".join(text.split())
    if not set(norm) <= {"0", "1"} or len(norm) < 8:
        return {"decoder": "binary", "confidence": 0, "reason": "Not binary"}
    
    confidence = 0.8
    if len(norm) % 8 == 0: confidence += 0.15
    
    return {"decoder": "binary", "confidence": confidence, "reason": "Valid bitstream detected"}

def _detect_base32(text: str) -> Dict[str, Any]:
    norm = "".join(text.split()).upper()
    if not re.fullmatch(r"[A-Z2-7=]*", norm) or len(norm) < 8:
        return {"decoder": "base32", "confidence": 0, "reason": "Invalid Base32 charset"}
    
    confidence = 0.5
    if norm.endswith("="): confidence += 0.3
    if len(norm) % 8 == 0: confidence += 0.1
    
    return {"decoder": "base32", "confidence": confidence, "reason": "Standard Base32 pattern matched"}

def _detect_compression(data: bytes) -> Dict[str, Any]:
    # Gzip Magic: 1F 8B
    if data.startswith(b"\x1f\x8b"):
        return {"decoder": "gzip", "confidence": 1.0, "reason": "Gzip magic bytes matched"}
    
    # Zlib: 78 01, 78 9C, 78 DA
    if data.startswith(b"\x78\x01") or data.startswith(b"\x78\x9c") or data.startswith(b"\x78\xda"):
        return {"decoder": "zlib", "confidence": 1.0, "reason": "Zlib magic bytes matched"}
        
    return {"decoder": "compression", "confidence": 0, "reason": "No compression magic"}

def _detect_utf16le(data: bytes) -> Dict[str, Any]:
    if len(data) < 10: return {"decoder": "utf16le", "confidence": 0, "reason": "Too short"}
    
    # Check for null bytes every second char (common in ASCII-heavy UTF-16LE)
    nulls_even = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
    ratio = nulls_even / (len(data) // 2)
    
    if ratio > 0.8:
        return {"decoder": "utf16le", "confidence": 0.9, "reason": "High null-byte density in even offsets (UTF-16LE candidate)"}
    
    return {"decoder": "utf16le", "confidence": 0, "reason": "No UTF-16LE pattern"}

def _detect_caesar(text: str) -> Dict[str, Any]:
    # Check for ROT13 specifically
    # ROT13 is its own inverse, check for common words
    # This is a bit expensive for detection, so we keep it light
    confidence = 0.1
    if any(c.isalpha() for c in text):
        confidence = 0.3 # Always a baseline candidate for any alphabetic text
        
    return {"decoder": "caesar", "confidence": confidence, "reason": "Input contains alphabetic characters"}

def _detect_xor_heuristic(data: bytes) -> Dict[str, Any]:
    # Very light XOR detection based on entropy and low confidence
    if len(data) < 10: return {"decoder": "xor", "confidence": 0, "reason": "Too short"}
    
    entropy = calculate_shannon_entropy(data)
    # Obfuscated text often has entropy between 3.0 and 6.5
    if 3.0 < entropy < 7.0:
        return {"decoder": "xor", "confidence": 0.4, "reason": f"Entropy ({entropy:.2f}) suggestive of obfuscation"}
    
    return {"decoder": "xor", "confidence": 0, "reason": "High/Low entropy suggests other states"}

def score_language(text: Optional[str]) -> float:
    """Score the likelihood of the text being English."""
    if not text: return 0.0
    words = re.findall(r"\b[a-z]{3,}\b", text.lower())
    if not words: return 0.0
    
    match_count = sum(1 for w in words if w in ENGLISH_WORDS)
    ratio = match_count / len(words)
    
    # Scale score: 0 to 1.0
    return min(1.0, ratio * 2.0) if match_count > 0 else 0.0
