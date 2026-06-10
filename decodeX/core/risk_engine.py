"""Risk scoring engine."""

from typing import Any


def calculate_risk(analysis_dict: dict[str, Any]) -> dict[str, Any]:
    """Calculate risk score and verdict based on analysis dictionary."""
    score = 0
    breakdown = []
    sections = analysis_dict.get("sections", {})

    # entropy > 6.8 -> +25
    entropy = analysis_dict.get("raw_metadata", {}).get("entropy", 0.0)
    if entropy > 6.8:
        score += 25
        breakdown.append({
            "component": "High Entropy",
            "score": 25,
            "description": f"File entropy is high ({entropy:.2f}), suggesting packed or encrypted data."
        })

    # embedded IP/domain -> +15
    if sections.get("paths_and_domains"):
        score += 15
        breakdown.append({
            "component": "Network Indicators",
            "score": 15,
            "description": "Embedded IP addresses or domains found in the binary."
        })

    # suspicious API strings -> +20
    suspicious_api = False
    for entry in sections.get("suspicious_indicators", []) + sections.get("strings_of_interest", []):
        if "API" in entry.get("tags", []):
            suspicious_api = True
            break
    
    # Check plugin results for suspicious imports
    pe_plugins = analysis_dict.get("decodeX.plugins", {}).get("pe", {})
    susp_imports = pe_plugins.get("suspicious_imports", [])
    if susp_imports:
        suspicious_api = True

    if suspicious_api:
        score += 20
        breakdown.append({
            "component": "Suspicious APIs",
            "score": 20,
            "description": "References to sensitive or suspicious system APIs detected."
        })

    # High risk for specific injection/execution imports -> +15 more
    high_risk_imports = False
    for api in susp_imports:
        if api.lower() in ["virtualalloc", "createremotethread", "writeprocessmemory", "winexec", "shellexecute"]:
            high_risk_imports = True
            break
    if high_risk_imports:
        score += 15
        breakdown.append({
            "component": "High-Risk Imports",
            "score": 15,
            "description": "Imports associated with process injection or direct execution detected."
        })

    # PE executable -> +10
    if analysis_dict.get("raw_metadata", {}).get("magic") == "EXE":
        score += 10
        breakdown.append({
            "component": "PE Header",
            "score": 10,
            "description": "File is a Windows executable (Portable Executable)."
        })

    # packing indicators -> +20
    packing = False
    for entry in sections.get("suspicious_indicators", []):
        if "ENCODED" in entry.get("tags", []):
            packing = True
            break
    if not packing and analysis_dict.get("analysis", {}).get("possible_packers"):
        packing = True
    if packing:
        score += 20
        breakdown.append({
            "component": "Packing/Obfuscation",
            "score": 20,
            "description": "Signatures of known packers or obfuscation techniques detected."
        })

    # known system binary -> -10
    system_binary = False
    for entry in sections.get("certificate_metadata", []):
        if "microsoft" in entry.get("value", "").lower() or "windows" in entry.get("value", "").lower():
            system_binary = True
            break
    if not system_binary:
        for entry in sections.get("system_artifacts", []):
            if "SYSTEM" in entry.get("tags", []):
                system_binary = True
                break
    if system_binary:
        score -= 10
        breakdown.append({
            "component": "System Binary",
            "score": -10,
            "description": "File matches signatures of known Microsoft/Windows system binaries."
        })

    # Clamp the score between 0 and 100
    score = max(0, min(100, score))
    
    # 0-10 score for CODEx
    score_10 = score // 10
    
    if score_10 >= 7:
        verdict = "Malicious"
    elif score_10 >= 4:
        verdict = "Suspicious"
    else:
        verdict = "Benign-like"

    return {
        "risk_score": score,
        "risk_score_10": score_10,
        "verdict": verdict,
        "breakdown": breakdown
    }
