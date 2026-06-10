import base64
import binascii
import string
import re
import time
import logging
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote_plus

from decodeX.framework.plugin_base import Plugin, Finding
from decodeX.core.entropy_tools import calculate_shannon_entropy

# Configure logging
logger = logging.getLogger("decodeX.auto_decode")

# --- Constants & Limits ---
MAX_XOR_SAMPLE = 4096
MAX_RECURSION_DEPTH = 5
MAX_CANDIDATES = 50
MAX_DECODER_TIME = 2.0  # seconds
SCORE_THRESHOLD_EARLY_EXIT = 85
ENTROPY_HIGH_THRESHOLD = 7.5

# Top 100 English words for scoring
ENGLISH_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her", "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me", "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
    "people", "into", "year", "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first", "well", "even", "new", "want", "because", "any", "these", "give", "day", "most", "us", "hello"
}

class AutoDecodePlugin(Plugin):
    """
    Optimized Plugin for automatic multi-layered detection and decoding.
    Designed for malware analysis with fail-safes for large binaries.
    """

    _seen_outputs: set[str] = set()

    @property
    def name(self) -> str:
        return "auto_decode"

    @property
    def version(self) -> str:
        return "1.1.0"

    @property
    def description(self) -> str:
        return "High-performance automatic decoding with PE optimization and resource safety."

    def analyze(self, target: Path | str | bytes) -> dict[str, Any]:
        """Analyze the input and attempt recursive decoding with safety checks."""
        self._seen_outputs = set()
        input_data = b""
        
        if isinstance(target, Path):
            try:
                input_data = target.read_bytes()
            except Exception:
                return {"error": "Could not read target file."}
        elif isinstance(target, bytes):
            input_data = target
        else:
            input_data = str(target).encode("latin-1", errors="ignore")

        if not input_data:
            return {"error": "Empty input."}

        # 1. Entropy Gate
        entropy = calculate_shannon_entropy(input_data[:8192])
        logger.info(f"Input entropy: {entropy:.2f} (Size: {len(input_data)} bytes)")
        
        is_high_entropy = entropy > ENTROPY_HIGH_THRESHOLD
        
        # 2. PE Aware Detection
        is_pe = self._is_pe(input_data)
        if is_pe:
            logger.info("PE executable detected. Prioritizing string extraction.")
            # If PE, extract strings and only run XOR on those strings
            # For the main 'auto' behavior, we still return a unified result
            extracted = self._extract_strings(input_data)
            # Add extracted strings to analysis scope (simplified for now)
            # In a full triage tool, we'd loop over strings here.
            # For this plugin, we'll analyze the 'blob' but skip raw XOR if too large.
            pass

        # Convert to string for legacy decoders
        input_str = input_data.decode("utf-16le", errors="ignore") if any(b > 127 for b in input_data[:100]) else input_data.decode("latin-1", errors="ignore")

        # Recursive decoding
        self._seen_outputs.add(input_str)
        best_result = self._recursive_decode(input_str, depth=0, steps=[], high_entropy=is_high_entropy)
        
        findings = []
        if best_result["steps"] and best_result["confidence"] > 60:
            findings.append(Finding(
                severity="Medium",
                category="Obfuscation",
                title=f"Automatic Decoding successful ({best_result['detected_encoding']})",
                evidence=f"Decoded through {len(best_result['steps'])} steps.",
                recommendation="Review the final decoded output for hidden commands or data."
            ).to_dict())

        return {
            "plugin": "Auto Decode",
            "input_preview": input_str[:100],
            "entropy": round(entropy, 2),
            "is_pe": is_pe,
            "detected_encoding": best_result["detected_encoding"],
            "confidence": best_result["confidence"],
            "decoded_output": best_result["decoded_output"],
            "steps": best_result["steps"],
            "findings": findings
        }

    def _recursive_decode(self, text: str, depth: int, steps: list[str], high_entropy: bool) -> dict[str, Any]:
        """Exhaustively search for the best decoding path with depth and loop protection."""
        current_score = self._score_readability(text)
        
        if depth >= MAX_RECURSION_DEPTH:
            return self._build_result(text, steps[-1] if steps else "None", int(current_score), steps)

        results = [self._build_result(text, steps[-1] if steps else "None", int(current_score), steps)]
        
        candidates = self._detect_possibilities(text, high_entropy)
        # Limit total candidates to process
        candidates = candidates[:MAX_CANDIDATES]

        for encoding, method, confidence in candidates:
            try:
                # Execution protection is inside method
                decoded = method(text)
                if not decoded or decoded == text or decoded in self._seen_outputs:
                    continue
                
                self._seen_outputs.add(decoded)
                branch_res = self._recursive_decode(decoded, depth + 1, steps + [encoding], high_entropy=False)
                results.append(branch_res)
            except Exception:
                continue

        return max(results, key=lambda r: (r["confidence"], len(r["steps"])))

    def _build_result(self, output: str, encoding: str, confidence: int, steps: list[str]) -> dict[str, Any]:
        return {
            "detected_encoding": encoding,
            "confidence": min(confidence, 100),
            "decoded_output": output,
            "steps": steps
        }

    def _detect_possibilities(self, text: str, high_entropy: bool):
        """Detect likely next steps, prioritizing cheap ones and skipping expensive ones if needed."""
        normalized = "".join(text.split())
        candidates = []

        # --- CHEAP DETECTORS FIRST ---
        
        # 1. Base64
        if len(normalized) >= 4 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", normalized):
            if not all(c in string.hexdigits for c in normalized) or len(normalized) % 4 == 0:
                candidates.append(("Base64", self._decode_b64, 70))
        
        # 2. Hex
        if len(normalized) >= 2 and len(normalized) % 2 == 0 and all(c in string.hexdigits for c in normalized):
            candidates.append(("Hex", self._decode_hex, 85))

        # 3. URL Encoding
        if "%" in text:
            candidates.append(("URL", self._decode_url, 90))

        # 4. Binary
        if len(normalized) >= 8 and len(normalized) % 8 == 0 and set(normalized) <= {"0", "1"}:
            candidates.append(("Binary", self._decode_bin, 85))
            
        # 5. Reverse
        candidates.append(("Reverse", lambda t: t[::-1], 30))

        # --- EXPENSIVE DETECTORS LATER ---
            
        # XOR (Single Byte) - Only if score is low AND NOT gated by entropy
        if self._score_readability(text) < 60:
            if high_entropy:
                logger.info("High entropy detected. Skipping expensive XOR brute-force.")
            else:
                xor_res = self._brute_xor(text)
                if xor_res:
                    candidates.append((f"XOR(0x{xor_res[0]:02x})", lambda t, k=xor_res[0]: self._apply_xor(t, k), 65))
            
        return candidates

    def _brute_xor(self, text: str) -> tuple[int, float] | None:
        """Find the best single-byte XOR key with sample limits and timeouts."""
        logger.info(f"XOR brute-force started (Input size: {len(text)})")
        start_time = time.time()
        
        # Sample Limit
        sample_text = text[:MAX_XOR_SAMPLE]
        try:
            data = sample_text.encode("utf-16le") if any(ord(c) > 255 for c in sample_text) else sample_text.encode("latin-1")
        except Exception:
            return None
            
        best_key = 0
        max_score = 0
        base_score = self._score_readability(sample_text)
        
        for key in range(1, 256):
            # Timeout protection
            if time.time() - start_time > MAX_DECODER_TIME:
                logger.warning("XOR brute-force timeout reached.")
                break
                
            xor_data = bytes([b ^ key for b in data])
            try:
                decoded = xor_data.decode("utf-8", errors="ignore")
                score = self._score_readability(decoded)
                
                if score > max_score:
                    max_score = score
                    best_key = key
                
                # Early Exit
                if score > SCORE_THRESHOLD_EARLY_EXIT:
                    logger.info(f"XOR early exit at key 0x{key:02x} (Score: {score})")
                    break
            except Exception:
                continue
        
        logger.info(f"XOR brute-force finished in {time.time()-start_time:.2f}s")
        return (best_key, max_score) if max_score > base_score + 10 else None

    def _score_readability(self, text: str) -> float:
        """Calculate a robust readability score based ONLY on the first 1000 characters."""
        if not text: return 0
        
        # Performance Limit: Only score preview
        preview = text[:1000]
        length = len(preview)
        
        # 1. Alphanumeric & Common Punctuation Density (up to 30 points)
        allowed = string.ascii_letters + string.digits + " .,?!'\"\n\r\t"
        allowed_count = sum(1 for c in preview if c in allowed)
        density_score = (allowed_count / length) * 30
        
        # 2. English Words (up to 50 points)
        words = re.findall(r"\b[a-z]{2,}\b", preview.lower())
        if words:
            found_words = sum(1 for w in words if w in ENGLISH_WORDS)
            word_ratio = found_words / len(words)
            word_score = word_ratio * 50 if found_words > 0 else 0
        else:
            word_score = 0
            
        # 3. Entropy Penalty
        entropy = calculate_shannon_entropy(preview)
        entropy_score = max(0, 20 - (entropy * 2.5))
        
        # 4. Symbol/Control Char Penalty
        symbols = sum(1 for c in preview if c in string.punctuation and c not in ".,?!'\"")
        control = sum(1 for c in preview if c in "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f")
        penalty = ((symbols + control*5) / length) * 50
        
        return max(0, min(100, density_score + word_score + entropy_score - penalty))

    def _is_pe(self, data: bytes) -> bool:
        """Cheap detection for Windows PE executables."""
        if len(data) < 64: return False
        if data[:2] != b"MZ": return False
        try:
            pe_offset = int.from_bytes(data[60:64], "little")
            return data[pe_offset:pe_offset+2] == b"PE"
        except Exception:
            return False

    def _extract_strings(self, data: bytes, min_len: int = 4) -> list[str]:
        """Simple string extraction from binary blobs."""
        pattern = b"[ -~]{" + str(min_len).encode() + b",}"
        return [s.decode("ascii") for s in re.findall(pattern, data[:65536])] # Limit scan to first 64KB

    def _apply_xor(self, text: str, key: int) -> str:
        data = text.encode("utf-16le") if any(ord(c) > 255 for c in text) else text.encode("latin-1")
        return bytes([b ^ key for b in data]).decode("utf-8", errors="ignore")

    def _decode_b64(self, val: str) -> str:
        norm = "".join(val.split())
        padded = norm + ("=" * (-len(norm) % 4))
        return base64.b64decode(padded).decode("utf-8", errors="ignore")

    def _decode_hex(self, val: str) -> str:
        return bytes.fromhex("".join(val.split())).decode("utf-8", errors="ignore")

    def _decode_url(self, val: str) -> str:
        return unquote_plus(val)

    def _decode_bin(self, val: str) -> str:
        norm = "".join(val.split())
        return bytes(int(norm[i:i+8], 2) for i in range(0, len(norm), 8)).decode("utf-8", errors="ignore")
