import base64
import binascii
import json
import re
import string
import logging
from typing import Any, Callable
from urllib.parse import unquote_plus

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("decodeX.encodings")

# --- Constants & Charsets ---
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# --- Interface helper ---
def build_result(success: bool, output: str | None, type_name: str, confidence: float) -> dict[str, Any]:
    return {
        "success": success,
        "output": output,
        "type": type_name,
        "confidence": round(confidence, 2)
    }

# --- Decoders ---

def decode_base64(input_data: str) -> dict[str, Any]:
    """Standard and URL-safe Base64 decoding."""
    norm = "".join(input_data.split())
    if not norm: return build_result(False, None, "base64", 0)
    
    # Check if uses base64 charset
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]*", norm):
        return build_result(False, None, "base64", 0)
        
    try:
        # Try URL-safe first as it's a subset
        alt_norm = norm.replace("-", "+").replace("_", "/")
        padded = alt_norm + ("=" * (-len(alt_norm) % 4))
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")
        
        confidence = 0.9 if input_data.endswith("=") else 0.7
        if any(c in string.printable for c in decoded): confidence += 0.05
        
        return build_result(True, decoded, "base64", confidence)
    except Exception:
        return build_result(False, None, "base64", 0)

def decode_base32(input_data: str) -> dict[str, Any]:
    norm = "".join(input_data.split()).upper()
    if not re.fullmatch(r"[A-Z2-7=]*", norm):
        return build_result(False, None, "base32", 0)
    try:
        padded = norm + ("=" * (-len(norm) % 8))
        decoded = base64.b32decode(padded).decode("utf-8", errors="ignore")
        return build_result(True, decoded, "base32", 0.8)
    except Exception:
        return build_result(False, None, "base32", 0)

def decode_base58(input_data: str) -> dict[str, Any]:
    norm = "".join(input_data.split())
    if not all(c in BASE58_ALPHABET for c in norm):
        return build_result(False, None, "base58", 0)
    try:
        n = 0
        for char in norm:
            n = n * 58 + BASE58_ALPHABET.index(char)
        
        # Convert to bytes
        res = []
        while n > 0:
            n, r = divmod(n, 256)
            res.append(r)
        
        # Handle leading '1's as zero bytes
        for char in norm:
            if char == '1': res.append(0)
            else: break
            
        decoded = bytes(reversed(res)).decode("utf-8", errors="ignore")
        return build_result(True, decoded, "base58", 0.7)
    except Exception:
        return build_result(False, None, "base58", 0)

def decode_hex(input_data: str) -> dict[str, Any]:
    norm = "".join(re.findall(r"[0-9A-Fa-f]", input_data))
    if not norm or len(norm) % 2 != 0:
        return build_result(False, None, "hex", 0)
    try:
        decoded = bytes.fromhex(norm).decode("utf-8", errors="ignore")
        confidence = 0.8 if len(input_data) == len(norm) else 0.6
        return build_result(True, decoded, "hex", confidence)
    except Exception:
        return build_result(False, None, "hex", 0)

def decode_binary(input_data: str) -> dict[str, Any]:
    norm = "".join(re.findall(r"[01]", input_data))
    if not norm or len(norm) % 8 != 0:
        return build_result(False, None, "binary", 0)
    try:
        decoded = bytes(int(norm[i:i+8], 2) for i in range(0, len(norm), 8)).decode("utf-8", errors="ignore")
        return build_result(True, decoded, "binary", 0.9)
    except Exception:
        return build_result(False, None, "binary", 0)

def decode_url(input_data: str) -> dict[str, Any]:
    if "%" not in input_data: return build_result(False, None, "url", 0)
    decoded = unquote_plus(input_data)
    if decoded == input_data: return build_result(False, None, "url", 0)
    return build_result(True, decoded, "url", 0.9)

def decode_ascii_decimal(input_data: str) -> dict[str, Any]:
    parts = re.split(r"[\s,;]+", input_data.strip())
    if not parts: return build_result(False, None, "ascii_decimal", 0)
    try:
        decoded = "".join(chr(int(p)) for p in parts if p)
        return build_result(True, decoded, "ascii_decimal", 0.7)
    except Exception:
        return build_result(False, None, "ascii_decimal", 0)

def decode_rot13(input_data: str) -> dict[str, Any]:
    result = []
    for c in input_data:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return build_result(True, "".join(result), "rot13", 0.4) # Low confidence as it's always possible

def decode_rot47(input_data: str) -> dict[str, Any]:
    result = []
    for c in input_data:
        if 33 <= ord(c) <= 126:
            result.append(chr(33 + (ord(c) + 14) % 94))
        else:
            result.append(c)
    return build_result(True, "".join(result), "rot47", 0.4)

def brute_caesar(input_data: str) -> dict[str, Any]:
    best_output = input_data
    max_confidence = 0
    for shift in range(1, 26):
        res = []
        for c in input_data:
            if 'a' <= c <= 'z':
                res.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                res.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
            else:
                res.append(c)
        candidate = "".join(res)
        # Simplified scoring: check for common English words
        score = sum(1 for w in ["the", "and", "that", "with", "from", "hello", "secret"] if w in candidate.lower())
        if score > max_confidence:
            max_confidence = score
            best_output = candidate
            
    if max_confidence > 0:
        return build_result(True, best_output, "caesar", 0.7)
    return build_result(False, None, "caesar", 0)

def reverse_string(input_data: str) -> dict[str, Any]:
    return build_result(True, input_data[::-1], "reverse", 0.3)

# --- Heuristic Helpers ---

def is_readable_text(text: str) -> bool:
    """Check if the string is likely already plain English text."""
    if not text: return False
    words = re.findall(r"\b[a-z]{3,}\b", text.lower())
    if not words: return False
    
    common = ["the", "and", "that", "with", "from", "this", "they", "have", "hello"]
    match_count = sum(1 for w in words if w in common)
    
    # If 10% of words are common English, or it's a very clear signal
    if match_count / len(words) > 0.1 or match_count >= 1:
        return True
    return False

# --- Auto-Detection & Pipeline ---

DECODERS: list[Callable[[str], dict[str, Any]]] = [
    decode_base64, decode_base32, decode_base58, decode_hex,
    decode_binary, decode_url, decode_ascii_decimal, decode_rot13,
    decode_rot47, brute_caesar, reverse_string
]

def auto_detect(input_data: str) -> list[dict[str, Any]]:
    """Rank decoding results by confidence."""
    # Guard: Do not attempt to detect empty or whitespace-only strings
    normalized = input_data.strip()
    if not normalized:
        return []

    candidates = []
    
    # If it's already readable, penalize everything else
    plaintext_likely = is_readable_text(input_data)
    
    for decoder in DECODERS:
        res = decoder(input_data)
        if res["success"] and res["output"] != input_data:
            # Penalty for decoding already readable text
            if plaintext_likely:
                res["confidence"] *= 0.5
            candidates.append(res)
            
    candidates.sort(key=lambda x: x["confidence"], reverse=True)
    return candidates

def decode_pipeline(input_data: str, depth: int = 0) -> dict[str, Any]:
    """Recursively decode layers of encoding."""
    # Safety Guards
    if not input_data or len(input_data.strip()) == 0:
        return {"output": input_data, "steps": [], "final_type": "none"}

    if depth >= 5:
        logger.warning(f"Pipeline reached max depth ({depth})")
        return {"output": input_data, "steps": [], "final_type": "none"}
    
    # If input is already very readable, stop the pipeline
    if is_readable_text(input_data) and depth > 0:
        logger.info(f"Pipeline terminated: readable text found at depth {depth}")
        return {"output": input_data, "steps": [], "final_type": "none"}

    candidates = auto_detect(input_data)
    if not candidates or candidates[0]["confidence"] < 0.5:
        return {"output": input_data, "steps": [], "final_type": "none"}
    
    best = candidates[0]
    logger.info(f"Depth {depth}: Detected {best['type']} (conf: {best['confidence']})")
    
    # Recurse
    inner = decode_pipeline(best["output"], depth + 1)
    
    return {
        "output": inner["output"],
        "steps": [{ "decoder": best["type"], "output": best["output"], "confidence": best["confidence"] }] + inner["steps"],
        "final_type": inner["final_type"] if inner["final_type"] != "none" else best["type"]
    }
