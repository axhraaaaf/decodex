"""PE Analysis Foundation plugin for decodeX."""

import struct
from pathlib import Path
from typing import Any

import pefile

from decodeX.framework.plugin_base import Plugin


class PEPlugin(Plugin):
    """Plugin to perform foundational PE analysis on Windows executables."""

    @property
    def name(self) -> str:
        return "pe"

    @property
    def version(self) -> str:
        return "1.1.0"

    @property
    def description(self) -> str:
        return "Performs foundational PE header and architecture analysis."

    def analyze(self, target: Path | str | bytes) -> dict[str, Any]:
        """
        Analyze the target file for PE characteristics using the pefile library.
        """
        if isinstance(target, bytes):
            data = target
            file_size = len(data)
        else:
            target_path = Path(target)
            if not target_path.exists():
                return {"error": f"File not found: {target_path}"}
            data = target_path.read_bytes()
            file_size = target_path.stat().st_size

        results = {
            "plugin": "PE Analysis",
            "is_pe": False,
            "architecture": "Unknown",
            "file_size": file_size,
            "findings": [],
            "sections": [],
            "suspicious_imports": [],
            "imphash": None,
            "overlay_size": 0
        }

        try:
            pe = pefile.PE(data=data, fast_load=False)
            results["is_pe"] = True
            
            # Architecture
            machine = pe.FILE_HEADER.Machine
            if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                results["architecture"] = "x86 (32-bit)"
            elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                results["architecture"] = "x64 (64-bit)"
            else:
                results["architecture"] = f"Unknown ({hex(machine)})"

            results["findings"].append(f"PE structure identified ({results['architecture']}).")

            # Imphash
            results["imphash"] = pe.get_imphash()
            
            # Section Analysis
            for section in pe.sections:
                name = section.Name.decode('ascii', errors='ignore').strip('\x00')
                entropy = section.get_entropy()
                
                s_info = {
                    "name": name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(entropy, 2),
                    "characteristics": hex(section.Characteristics)
                }
                
                # Suspicious Section Permissions
                if section.Characteristics & 0x20000000 and section.Characteristics & 0x80000000:
                    results["findings"].append(f"Suspicious section permissions: '{name}' is both Executable and Writable.")
                
                if entropy > 7.1:
                    results["findings"].append(f"High entropy in section '{name}' ({entropy:.2f}), likely packed.")
                    
                results["sections"].append(s_info)

            # Import Analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('ascii', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('ascii', errors='ignore')
                            # Map to suspicious API list
                            SUSPICIOUS_APIS = {
                                "Injection": ["VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory"],
                                "Execution": ["WinExec", "ShellExecute", "CreateProcess", "CreateService"],
                                "Persistence": ["RegSetValue", "SetWindowsHook"],
                                "Anti-Debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                                "Networking": ["InternetOpen", "URLDownloadToFile", "WinHttpOpen"]
                            }
                            for cat, apis in SUSPICIOUS_APIS.items():
                                if any(api.lower() in func_name.lower() for api in apis):
                                    if f"{cat}: {func_name}" not in results["suspicious_imports"]:
                                        results["suspicious_imports"].append(f"{cat}: {func_name}")

            # Overlay Detection
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None and overlay_offset < file_size:
                results["overlay_size"] = file_size - overlay_offset
                if results["overlay_size"] > 1024: # ignore tiny overlays
                    results["findings"].append(f"Detected {results['overlay_size']} bytes of overlay data.")

            # Summary Findings
            if results["suspicious_imports"]:
                results["findings"].append(f"Detected {len(results['suspicious_imports'])} high-risk API imports.")

        except pefile.PEFormatError:
            results["findings"].append("Not a valid PE format.")
        except Exception as e:
            results["findings"].append(f"Error during deep PE parsing: {str(e)}")

        return results
