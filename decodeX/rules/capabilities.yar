rule Suspect_PE_Behaviors {
    meta:
        description = "Detects common suspicious PE patterns often found in malware"
        author = "Achraaf / decodeX"
        severity = "medium"

    strings:
        // Antivirus/Sandbox evasion strings
        $evasion1 = "IsDebuggerPresent"
        $evasion2 = "CheckRemoteDebuggerPresent"
        $evasion3 = "SbieDll.dll"  // Sandboxie
        $evasion4 = "VBoxGuest.sys" // VirtualBox

        // Generic persistence mechanisms
        $persist1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $persist2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase

        // Cryptography/Hashing common in ransomware/droppers
        $crypto1 = "CryptAcquireContext"
        $crypto2 = "BCryptOpenAlgorithmProvider"
        
        // Potential Process Injection
        $inj1 = "CreateRemoteThread"
        $inj2 = "WriteProcessMemory"
        $inj3 = "VirtualAllocEx"

    condition:
        2 of ($evasion*) or 1 of ($persist*) or 1 of ($inj*) or all of ($crypto*)
}

rule High_Entropy_Section {
    meta:
        description = "Potential packed or encrypted section detected via signature"
        priority = "high"
    
    strings:
        // Placeholder for future specific packer signatures (UPX, etc.)
        $upx1 = "UPX0"
        $upx2 = "UPX1"
    
    condition:
        any of them
}
