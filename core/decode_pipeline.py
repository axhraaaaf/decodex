import base64
import gzip
import re
import string
import zlib
import logging
import math
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from decodeX.core.detection_engine import detect_candidates, ENGLISH_WORDS
from decodeX.core.entropy_tools import calculate_shannon_entropy

# Configure logging
logger = logging.getLogger("decodeX.pipeline")

MAX_RECURSION_DEPTH = 5

class ReadabilityScorer:
    """
    Evaluates the readability of a decoded output based on:
    - ASCII printable ratio (40%)
    - Dictionary word match (30%)
    - Character randomness reduction (20%)
    - UTF-8 validity (10%)
    """
    
    @staticmethod
    def evaluate(data: bytes | str, original_entropy: float = 8.0) -> float:
        if not data:
            return 0.0
            
        try:
            if isinstance(data, bytes):
                text = data.decode("utf-8")
                utf8_score = 1.0
            else:
                text = data
                utf8_score = 1.0
        except UnicodeDecodeError:
            if isinstance(data, bytes):
                text = data.decode("latin-1", errors="ignore")
            else:
                text = data
            utf8_score = 0.0

        if not text:
            return 0.0

        # 1. ASCII printable ratio (40%)
        printable_chars = sum(1 for c in text if c in string.printable)
        ascii_ratio = printable_chars / len(text)
        
        # 2. Dictionary word match (30%)
        words = re.findall(r"\b[a-z]{3,}\b", text.lower())
        if words:
            match_count = sum(1 for w in words if w in ENGLISH_WORDS)
            dict_ratio = match_count / len(words)
            # Boost if multiple words matched
            if match_count >= 2:
                dict_ratio = min(1.0, dict_ratio + 0.2)
        else:
            dict_ratio = 0.0
            
        # 3. Character randomness reduction (20%)
        current_data = data if isinstance(data, bytes) else data.encode("latin-1", errors="ignore")
        current_entropy = calculate_shannon_entropy(current_data)
        
        # English text usually has entropy 3.5 - 5.0
        # High entropy (> 6.0) is likely encoded/encrypted
        if current_entropy < 5.0:
            entropy_score = 1.0
        elif current_entropy > 7.0:
            entropy_score = 0.0
        else:
            entropy_score = (7.0 - current_entropy) / 2.0
            
        # Penalize high entropy even if printable (like Base64/Hex often is)
        if current_entropy > 5.5 and ascii_ratio > 0.9:
            # Likely base64 or hex
            ascii_ratio *= 0.5 

        # 4. UTF-8 Validity (10%) - already calculated as utf8_score

        total_score = (
            (ascii_ratio * 0.4) +
            (dict_ratio * 0.3) +
            (entropy_score * 0.2) +
            (utf8_score * 0.1)
        )
        
        return round(total_score, 4)

class DecodingPath:
    """Represents a single branch in the decoding tree."""
    def __init__(self, data: bytes | str, chain: List[str] = None, parent_score: float = 0.0):
        self.data = data
        self.chain = chain or []
        self.readability_score = ReadabilityScorer.evaluate(data)
        self.entropy = calculate_shannon_entropy(data if isinstance(data, bytes) else data.encode("latin-1", errors="ignore"))
        self.confidence = 1.0 # Initial confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_text": self.data if isinstance(self.data, str) else self.data.decode("latin-1", errors="ignore"),
            "detected_chain": self.chain,
            "confidence": round(self.confidence * 100, 2),
            "readability_score": self.readability_score,
            "entropy": round(self.entropy, 4)
        }

def auto_decode(data: bytes | str) -> Dict[str, Any]:
    """
    Main entry point for the BRANCH + VALIDATE + SELECT model.
    """
    initial_path = DecodingPath(data)
    active_paths = [initial_path]
    best_path = initial_path
    failed_paths = []
    
    seen_states = set()
    initial_state = ("str", data) if isinstance(data, str) else ("bytes", data.hex())
    seen_states.add(initial_state)

    for depth in range(MAX_RECURSION_DEPTH):
        new_paths = []
        for path in active_paths:
            # 1. Detect
            candidates = detect_candidates(path.data)
            _inject_tier2_candidates(path.data, candidates)
            
            # Prune low probability branches early
            candidates = [c for c in candidates if c["confidence"] >= 0.4]
            
            for candidate in candidates:
                # 2. Decode
                success, decoded = _apply_decoder(path.data, candidate["decoder"])
                if not success or decoded is None:
                    continue
                
                # Loop Detection - distinguish between string input and byte output
                state = ("str", decoded) if isinstance(decoded, str) else ("bytes", decoded.hex())
                if state in seen_states:
                    continue
                seen_states.add(state)
                
                # 3. Validate
                new_path = DecodingPath(decoded, path.chain + [candidate["decoder"]])
                new_path.confidence = path.confidence * candidate["confidence"]
                
                # Acceptance Rule: 
                # 1. High readability
                # 2. Significant entropy reduction
                # 3. High confidence intermediate step (even if score didn't improve yet)
                is_valid = (
                    new_path.readability_score >= 0.75 or 
                    (new_path.entropy < path.entropy - 0.2) or
                    (candidate["confidence"] >= 0.5 and depth < 3) # Be very permissive in early layers
                )

                if is_valid:
                    new_paths.append(new_path)
                    # Update best path: prefer higher readability, then lower entropy, then longer chain if readability is high
                    if new_path.readability_score > best_path.readability_score:
                        best_path = new_path
                    elif new_path.readability_score == best_path.readability_score and new_path.readability_score > 0.6:
                        if len(new_path.chain) > len(best_path.chain):
                            best_path = new_path
                else:
                    failed_paths.append(new_path.to_dict())

        if not new_paths:
            break
            
        # Prune: keep top N most promising branches to avoid exponential explosion
        new_paths.sort(key=lambda p: (p.readability_score, -p.entropy), reverse=True)
        active_paths = new_paths[:5]

    # Final result construction
    result = best_path.to_dict()
    result["readability_score"] = float(best_path.readability_score)
    result["failed_paths"] = failed_paths[:5]
    
    # Confidence adjustment
    if best_path.readability_score >= 0.85:
        result["confidence"] = 100
    elif best_path.readability_score >= 0.75:
        result["confidence"] = max(75, result["confidence"])
    else:
        result["confidence"] = min(49, result["confidence"])
        result["final_text"] = "non-readable output: " + result["final_text"][:50] + "..."

    return result

def decode_chain(data: bytes | str) -> Dict[str, Any]:
    """Shim for backward compatibility, uses auto_decode under the hood."""
    res = auto_decode(data)
    
    # Map to the format expected by SmartDecodePlugin
    # Old format: { "final_output": str, "chain": [ { "decoder": str, "output": str, "confidence": float } ], "overall_confidence": float }
    
    chain_detail = []
    # Note: auto_decode currently returns the FULL chain only at the end.
    # To reconstruct the intermediate steps with their outputs, we'd need to re-run or store them.
    # For now, we'll return a simplified chain that satisfies the plugin.
    for step in res.get("detected_chain", []):
        chain_detail.append({
            "decoder": step,
            "output": "(intermediate output omitted in shim)",
            "confidence": 1.0
        })
    
    if chain_detail:
        chain_detail[-1]["output"] = res["final_text"]
        chain_detail[-1]["confidence"] = res["confidence"] / 100.0

    return {
        "final_output": res["final_text"],
        "chain": chain_detail,
        "overall_confidence": res["confidence"] / 100.0,
        "readability_score": res.get("readability_score", 0),
        # Include new fields too
        "detected_chain": res.get("detected_chain", []),
        "confidence": res.get("confidence", 0)
    }

def _inject_tier2_candidates(data: bytes | str, candidates: List[Dict[str, Any]]):
    """
    Inject Tier 2 specialized candidates based on signatures.
    """
    text = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
    
    # PowerShell Signature
    if re.search(r"(?:powershell|pwsh).*-e(?:nc)?", text, re.I):
        candidates.insert(0, {"decoder": "powershell_enc", "confidence": 1.0, "reason": "PowerShell -enc signature found"})
    
    # String Recovery Signatures (Hex escapes, Unicode escapes)
    if re.search(r"(?:\\x[0-9a-f]{2}){4,}", text, re.I):
        candidates.append({"decoder": "hex_escapes", "confidence": 0.9, "reason": "Hex escape sequence detected"})

def _apply_decoder(data: bytes | str, decoder_name: str) -> tuple[bool, Any]:
    try:
        # Convert to text for string-based decoders
        text_data = data if isinstance(data, str) else data.decode("latin-1", errors="ignore")
        # Convert to bytes for byte-based decoders
        raw_data = data if isinstance(data, bytes) else data.encode("latin-1", errors="ignore")

        if decoder_name == "base64":
            padded = text_data + ("=" * (-len(text_data) % 4))
            return True, base64.b64decode(padded)
        elif decoder_name == "base64_url":
            padded = text_data.replace("-", "+").replace("_", "/") + ("=" * (-len(text_data) % 4))
            return True, base64.b64decode(padded)
        elif decoder_name == "base32":
            padded = text_data.upper() + ("=" * (-len(text_data) % 8))
            return True, base64.b32decode(padded)
        elif decoder_name == "hex":
            norm = "".join(re.findall(r"[0-9A-Fa-f]", text_data))
            return True, bytes.fromhex(norm)
        elif decoder_name == "binary":
            norm = "".join(text_data.split())
            return True, bytes(int(norm[i:i+8], 2) for i in range(0, len(norm), 8))
        elif decoder_name == "url":
            from urllib.parse import unquote_plus
            return True, unquote_plus(text_data)
        elif decoder_name == "gzip":
            return True, gzip.decompress(raw_data)
        elif decoder_name == "zlib":
            return True, zlib.decompress(raw_data)
        elif decoder_name == "powershell_enc":
            from decodeX.plugins.powershell_decoder_plugin import PowerShellDecoderPlugin
            res = PowerShellDecoderPlugin().analyze(text_data)
            if res.get("results"):
                return True, res["results"][0]["decoded_script"]
            return False, None
        elif decoder_name == "hex_escapes":
            from decodeX.plugins.string_recovery_plugin import StringRecoveryPlugin
            res = StringRecoveryPlugin().analyze(text_data)
            recoveries = [r["recovered"] for r in res.get("results", []) if "hex" in r["type"]]
            if recoveries:
                return True, recoveries[0]
            return False, None
        elif decoder_name == "rot13":
            return True, _rot_n(text_data, 13)
        elif decoder_name == "rot47":
            return True, _rot47(text_data)
        elif decoder_name == "caesar":
            return True, _brute_caesar(text_data)
        elif decoder_name == "reverse":
            return True, text_data[::-1]
        elif decoder_name == "xor":
            # Very simple 1-byte XOR brute force if XOR detected
            # In Tier 1, we just pick the best key
            success, result = _brute_xor(raw_data)
            return success, result

        return False, None
    except Exception as e:
        logger.error(f"Error applying decoder {decoder_name}: {e}")
        return False, None

def _rot_n(text: str, n: int) -> str:
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)

def _rot47(text: str) -> str:
    res = []
    for c in text:
        if 33 <= ord(c) <= 126:
            res.append(chr(33 + (ord(c) + 14) % 94))
        else:
            res.append(c)
    return "".join(res)

def _brute_caesar(text: str) -> str:
    best_text = text
    max_readability = 0
    for shift in range(1, 26):
        candidate = _rot_n(text, shift)
        score = ReadabilityScorer.evaluate(candidate)
        if score > max_readability:
            max_readability = score
            best_text = candidate
    return best_text

def _brute_xor(data: bytes) -> tuple[bool, Any]:
    # XOR HANDLING (STRICT RULES): 
    # Only attempt if entropy is high OR we are directed to (no other paths worked)
    current_entropy = calculate_shannon_entropy(data)
    # We use 5.0 as a slightly more permissive floor for "high" text entropy
    if current_entropy < 5.0:
        return False, None

    best_data = data
    max_readability = 0
    
    # Only XOR first 1024 bytes for performance
    sample = data[:1024]
    for key in range(1, 256):
        xor_sample = bytes([b ^ key for b in sample])
        try:
            text = xor_sample.decode("latin-1", errors="ignore")
            score = ReadabilityScorer.evaluate(text, original_entropy=current_entropy)
            if score > max_readability:
                max_readability = score
                best_data = bytes([b ^ key for b in data])
        except Exception:
            continue
            
    if max_readability >= 0.75:
        return True, best_data.decode("latin-1", errors="ignore")
    return False, None
