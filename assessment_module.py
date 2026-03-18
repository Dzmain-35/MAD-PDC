"""
Assessment Module for MAD - Malware Analysis Dashboard
Guided, CTF-style malware assessment mode for analyst training.
"""

import json
import os
from datetime import datetime
from pathlib import Path


QUESTION_BANK = {
    "ransomware": [
        {
            "id": 1,
            "phase": "Identification",
            "question": "Based on the file hashes and YARA matches, what type of malware family does this sample belong to? What indicators led you to this conclusion?",
            "hint": "Check the thq_family and yara_matches fields for family name keywords like 'Ransom', 'Crypt', or 'Lock'.",
            "reveal": "Ransomware families are typically identified by YARA signatures matching known encryption routines, ransom note templates, or specific mutex names. The ThreatHQ family classification and VirusTotal detections often contain keywords like 'Ransom', 'Crypt', 'Locker', or specific family names (e.g., LockBit, Conti, REvil).",
            "evidence_fields": ["yara_matches", "thq_family", "vt_family"],
            "free_text": True,
        },
        {
            "id": 2,
            "phase": "Static Analysis",
            "question": "Examine the import hash (imphash) and file type. What do these static indicators tell you about the sample's compilation and capabilities?",
            "hint": "The imphash groups binaries that import the same libraries in the same order — shared imphashes often indicate shared tooling or builders.",
            "reveal": "A PE32 executable with a known ransomware imphash suggests it was built with the same compiler/packer toolchain as other samples in the family. Common imports for ransomware include cryptographic APIs (CryptEncrypt, BCryptEncrypt), file enumeration APIs (FindFirstFile), and network APIs for C2 communication or key exchange.",
            "evidence_fields": ["imphash", "file_type", "file_size"],
            "free_text": True,
        },
        {
            "id": 3,
            "phase": "Behavior Analysis",
            "question": "What encryption-related behaviors would you expect from this ransomware sample during dynamic analysis? What file system artifacts should you look for?",
            "hint": "Ransomware typically enumerates drives, targets specific file extensions, and drops ransom notes.",
            "reveal": "Expected behaviors include: mass file enumeration across drives, creation of ransom note files (e.g., README.txt, DECRYPT_FILES.html), deletion of shadow copies (vssadmin delete shadows), modification of many files in rapid succession, and potential network callbacks to a C2 for key exchange. Look for new file extensions appended to encrypted files.",
            "evidence_fields": ["yara_matches", "vt_hits"],
            "free_text": True,
        },
        {
            "id": 4,
            "phase": "YARA / Signature Context",
            "question": "Review the YARA rule matches for this sample. What specific strings or byte patterns triggered the detection? How confident are you in the classification?",
            "hint": "Look at the matched strings within each YARA rule — they often reveal encryption constants, ransom note text, or unique mutex names.",
            "reveal": "YARA rules for ransomware often match on: encryption algorithm constants (AES S-box values, RSA key headers), ransom note template strings, specific API call patterns for file encryption, unique mutexes or registry keys, and sometimes Bitcoin wallet address patterns. High VT detection rates combined with specific YARA matches increase classification confidence.",
            "evidence_fields": ["yara_matches", "vt_hits", "vt_family"],
            "free_text": True,
        },
        {
            "id": 5,
            "phase": "Mitigation",
            "question": "What immediate containment and remediation steps would you recommend for a host infected with this ransomware family?",
            "hint": "Think about network isolation, backup verification, and IOC extraction for enterprise-wide hunting.",
            "reveal": "Immediate actions: (1) Isolate the host from the network to prevent lateral movement and further encryption. (2) Preserve forensic evidence — do NOT reboot. (3) Check for shadow copy availability. (4) Extract IOCs (hashes, C2 domains/IPs, mutex names) and hunt across the enterprise. (5) Identify the encryption type — some families have known decryptors. (6) Notify incident response team and assess backup integrity. (7) Block C2 infrastructure at the perimeter.",
            "evidence_fields": ["md5", "sha256", "iocs"],
            "free_text": True,
        },
    ],
    "rat": [
        {
            "id": 1,
            "phase": "Identification",
            "question": "What Remote Access Trojan (RAT) family does this sample appear to belong to? What detection signatures support this classification?",
            "hint": "Look for RAT-specific keywords in YARA matches and VT family names such as 'Agent', 'Remote', 'RAT', 'Backdoor'.",
            "reveal": "RAT families are identified through YARA rules matching C2 protocol structures, configuration extraction patterns, or known builder artifacts. Common families include AsyncRAT, NjRAT, DarkComet, Quasar, and Remcos. VT family labels and ThreatHQ classifications often directly name the RAT family.",
            "evidence_fields": ["yara_matches", "thq_family", "vt_family", "vt_hits"],
            "free_text": True,
        },
        {
            "id": 2,
            "phase": "Static Analysis",
            "question": "Examine the static properties of this sample. What do the file type, size, and import hash suggest about the RAT's capabilities and origin?",
            "hint": "RATs built with popular builders often share imphashes. Small file sizes may indicate a stub/loader rather than the full payload.",
            "reveal": "RATs are often .NET assemblies (indicated by file type) or packed PE executables. Shared imphashes across samples suggest the same RAT builder was used. Very small files may be droppers/stagers that download the full RAT payload. Look for imports related to: socket/network communication, screen capture, keylogging, file management, and registry manipulation.",
            "evidence_fields": ["imphash", "file_type", "file_size", "ssdeep"],
            "free_text": True,
        },
        {
            "id": 3,
            "phase": "Behavior Analysis",
            "question": "What network-based indicators would you monitor for during dynamic analysis of this RAT? What persistence mechanisms are commonly used?",
            "hint": "RATs need persistent C2 communication — look for beaconing patterns, DNS queries, and common persistence locations.",
            "reveal": "Network indicators: regular beaconing intervals to C2 servers, DNS queries to dynamic DNS providers (no-ip, duckdns), use of common ports (443, 8080, 1604). Persistence mechanisms: Run/RunOnce registry keys, scheduled tasks, startup folder shortcuts, WMI event subscriptions. Some RATs also install as services or use DLL side-loading.",
            "evidence_fields": ["yara_matches", "vt_hits", "iocs"],
            "free_text": True,
        },
        {
            "id": 4,
            "phase": "YARA / Signature Context",
            "question": "Analyze the YARA matches for this RAT sample. What configuration artifacts or protocol signatures did the rules detect?",
            "hint": "RAT YARA rules often match on embedded C2 configurations, encryption keys, or unique protocol headers.",
            "reveal": "RAT-specific YARA rules commonly detect: hardcoded C2 server addresses/ports, encryption keys used for C2 communication, unique protocol magic bytes or headers, mutex naming patterns, and builder-specific artifacts (version strings, default configurations). Configuration data extraction from matches can reveal the operator's infrastructure.",
            "evidence_fields": ["yara_matches", "vt_family"],
            "free_text": True,
        },
        {
            "id": 5,
            "phase": "Mitigation",
            "question": "What steps would you take to contain and eradicate this RAT from an infected environment? How would you assess the scope of compromise?",
            "hint": "Consider that RATs provide full remote access — the attacker may have moved laterally, exfiltrated data, or deployed additional tools.",
            "reveal": "Containment: (1) Isolate affected hosts. (2) Block C2 infrastructure (IPs, domains) at firewall/proxy. (3) Extract and distribute IOCs for enterprise hunting. Eradication: (4) Identify all persistence mechanisms and remove them. (5) Check for additional tools/malware dropped by the RAT operator. (6) Audit for lateral movement (credential theft, RDP sessions). (7) Review data access logs for potential exfiltration. (8) Reset credentials for any accounts accessible from compromised hosts.",
            "evidence_fields": ["md5", "sha256", "iocs"],
            "free_text": True,
        },
    ],
    "loader": [
        {
            "id": 1,
            "phase": "Identification",
            "question": "What type of loader/dropper does this sample represent? What detection signatures indicate its role in the delivery chain?",
            "hint": "Loaders are first-stage malware that download and execute the real payload. Look for family names with 'Loader', 'Dropper', 'Downloader' keywords.",
            "reveal": "Loaders are identified by YARA rules matching: download/execution patterns, embedded URLs or encoded payload locations, known loader framework signatures (e.g., BazarLoader, IcedID loader, Emotet). They often have lower VT detection rates than their payloads since they're frequently repacked. ThreatHQ may classify them by the payload they typically deliver.",
            "evidence_fields": ["yara_matches", "thq_family", "vt_family", "vt_hits"],
            "free_text": True,
        },
        {
            "id": 2,
            "phase": "Static Analysis",
            "question": "What do the static properties reveal about this loader's delivery mechanism? Is it packed or obfuscated?",
            "hint": "Loaders are frequently packed to evade detection. A high entropy or unusual file size relative to functionality may indicate packing.",
            "reveal": "Loaders commonly exhibit: packing/compression (UPX, custom packers) indicated by high entropy sections, small code sections with large data sections (embedded payloads), imports for network functions (URLDownloadToFile, WinHTTP) and process injection (VirtualAllocEx, WriteProcessMemory). The ssdeep hash can cluster related loader builds from the same campaign.",
            "evidence_fields": ["file_type", "file_size", "imphash", "ssdeep"],
            "free_text": True,
        },
        {
            "id": 3,
            "phase": "Behavior Analysis",
            "question": "What second-stage payload delivery behaviors should you look for during dynamic analysis?",
            "hint": "Loaders must retrieve their payload somehow — watch for HTTP/HTTPS requests, DNS lookups, and process creation events.",
            "reveal": "Expected behaviors: HTTP/HTTPS requests to payload hosting infrastructure, DNS queries to staging domains, creation of child processes (payload execution), process injection into legitimate processes, file writes to temp directories or AppData, and potential anti-analysis checks (sleep timers, VM detection, sandbox evasion) before payload retrieval.",
            "evidence_fields": ["yara_matches", "vt_hits", "iocs"],
            "free_text": True,
        },
        {
            "id": 4,
            "phase": "YARA / Signature Context",
            "question": "What do the YARA matches reveal about this loader's techniques? Can you identify the payload type it delivers?",
            "hint": "Some YARA rules detect the loader framework itself, while others may match on embedded payload artifacts or staging URLs.",
            "reveal": "Loader YARA rules may detect: specific decryption/deobfuscation routines, known loader framework code patterns, embedded or encoded URLs/IPs for payload retrieval, process injection shellcode templates, and anti-analysis technique signatures. Cross-referencing with threat intelligence can reveal the typical payload chain (e.g., BazarLoader → Cobalt Strike → Ryuk).",
            "evidence_fields": ["yara_matches", "vt_family"],
            "free_text": True,
        },
        {
            "id": 5,
            "phase": "Mitigation",
            "question": "How would you prevent the loader from delivering its payload and contain the threat? What infrastructure should you block?",
            "hint": "Focus on disrupting the delivery chain — if the loader can't reach its staging server, the payload never executes.",
            "reveal": "Prevention: (1) Block payload staging URLs/IPs/domains immediately. (2) Isolate hosts where the loader executed. (3) Check if the payload was already downloaded and executed. (4) Hunt for the loader across the environment using file hashes and YARA rules. (5) Review email/web gateway logs for the initial delivery vector. (6) Update email filters and web proxies to block the delivery mechanism. (7) If payload was delivered, pivot to payload-specific containment procedures.",
            "evidence_fields": ["md5", "sha256", "iocs"],
            "free_text": True,
        },
    ],
    "stealer": [
        {
            "id": 1,
            "phase": "Identification",
            "question": "What information stealer family does this sample belong to? What credentials or data types does it target?",
            "hint": "Look for stealer-related keywords in detections: 'Stealer', 'Spy', 'InfoStealer', 'PWS' (password stealer), 'Kredential'.",
            "reveal": "Info stealers are classified by YARA rules and VT/THQ detections matching known families (RedLine, Raccoon, Vidar, FormBook, AgentTesla). These target: browser saved passwords and cookies, cryptocurrency wallets, FTP/email client credentials, system information, screenshots, and clipboard data. The specific family determines the exfiltration method (HTTP POST, Telegram bot, email).",
            "evidence_fields": ["yara_matches", "thq_family", "vt_family", "vt_hits"],
            "free_text": True,
        },
        {
            "id": 2,
            "phase": "Static Analysis",
            "question": "What do the static indicators tell you about this stealer's targeting and capabilities?",
            "hint": "Stealers often import specific APIs for credential access and include strings referencing browser data paths or wallet files.",
            "reveal": "Stealer static indicators include: imports for cryptographic APIs (to decrypt stored credentials), file path strings targeting browser profiles (Chrome, Firefox, Edge), cryptocurrency wallet path references, registry access for installed software enumeration, and network APIs for data exfiltration. The imphash can link to known stealer builder versions.",
            "evidence_fields": ["imphash", "file_type", "file_size"],
            "free_text": True,
        },
        {
            "id": 3,
            "phase": "Behavior Analysis",
            "question": "What data collection and exfiltration behaviors should you monitor during analysis? Where does the stolen data go?",
            "hint": "Stealers typically collect data quickly and exfiltrate in a single burst — they're often 'smash and grab' rather than persistent.",
            "reveal": "Expected behaviors: rapid access to browser profile directories, reading of credential databases (Login Data, cookies.sqlite), enumeration of cryptocurrency wallet files, screenshot capture, system information gathering (OS version, hardware ID, installed software), creation of a temporary archive/zip of collected data, and a single exfiltration HTTP POST to C2 or a Telegram API call. Many stealers self-delete after exfiltration.",
            "evidence_fields": ["yara_matches", "vt_hits", "iocs"],
            "free_text": True,
        },
        {
            "id": 4,
            "phase": "YARA / Signature Context",
            "question": "What specific stealer artifacts did the YARA rules detect? Can you determine the exfiltration channel?",
            "hint": "YARA rules for stealers often match on browser path strings, credential decryption routines, or C2 communication patterns.",
            "reveal": "Stealer YARA rules commonly detect: hardcoded browser data paths and SQLite query strings, credential decryption function patterns, Telegram Bot API tokens or URLs, specific HTTP POST formats for data exfiltration, panel/gate URLs embedded in the binary, and anti-analysis checks specific to the family. Extracted C2 or Telegram tokens can be used for takedown or monitoring.",
            "evidence_fields": ["yara_matches", "vt_family"],
            "free_text": True,
        },
        {
            "id": 5,
            "phase": "Mitigation",
            "question": "What immediate response actions are critical after confirming an info stealer infection? What credentials need to be rotated?",
            "hint": "Assume all credentials accessible from the infected host are compromised — the stealer likely already exfiltrated them.",
            "reveal": "Critical actions: (1) Assume ALL stored credentials on the host are compromised. (2) Force password reset for all accounts (browser-saved passwords, email, VPN, SSO). (3) Revoke active sessions and tokens. (4) Enable MFA on all accounts if not already active. (5) Check for unauthorized access using stolen credentials. (6) Monitor cryptocurrency wallets for unauthorized transfers. (7) Block exfiltration C2/Telegram infrastructure. (8) Scan enterprise-wide for the same stealer. (9) Review initial infection vector to prevent reinfection.",
            "evidence_fields": ["md5", "sha256", "iocs"],
            "free_text": True,
        },
    ],
    "generic": [
        {
            "id": 1,
            "phase": "Initial Triage",
            "question": "Examine the case overview. How many files are present, and what are the initial threat scores? Which file(s) should you prioritize for deeper analysis?",
            "hint": "Start with the file that has the highest threat score or the most YARA/VT detections.",
            "reveal": "Initial triage should prioritize files by: (1) Threat score — higher scores indicate more detections. (2) VT hit count — more detections mean higher confidence. (3) YARA matches — specific rule matches can immediately classify the threat. (4) File type — executables (PE, ELF, Mach-O) are highest priority, followed by scripts, then documents. Files flagged as whitelisted can typically be deprioritized.",
            "evidence_fields": ["threat_score", "vt_hits", "yara_matches", "file_type"],
            "free_text": True,
        },
        {
            "id": 2,
            "phase": "Initial Triage",
            "question": "Review the file hashes (MD5, SHA256). Have you checked these against threat intelligence platforms? What did you find?",
            "hint": "The SHA256 hash is the primary pivot point for threat intelligence lookups across platforms.",
            "reveal": "Hash lookups are the fastest way to determine if a sample is known malicious. Check: VirusTotal (VT hits already in case data), ThreatHQ family classification, and any other threat intel platforms available. Known hashes with high detection rates confirm malicious classification. Unknown hashes (0 VT hits) may indicate novel/targeted malware requiring deeper analysis.",
            "evidence_fields": ["md5", "sha256", "vt_hits", "vt_link"],
            "free_text": True,
        },
        {
            "id": 3,
            "phase": "Static Analysis",
            "question": "What does the file type and size tell you about this sample? Is it a native executable, script, document, or something else?",
            "hint": "The file type detection uses magic bytes — the actual type may differ from the file extension.",
            "reveal": "File type analysis helps determine analysis approach: PE executables need disassembly/decompilation, scripts can be directly read, documents may contain macros. Unusually large files might contain embedded payloads. Very small executables are often packers/stubs. The file type also determines which sandbox or analysis tool is most appropriate.",
            "evidence_fields": ["file_type", "file_size"],
            "free_text": True,
        },
        {
            "id": 4,
            "phase": "Static Analysis",
            "question": "Examine the import hash (imphash) and ssdeep fuzzy hash. Can these link this sample to known malware families or campaigns?",
            "hint": "Imphash groups samples that import the same libraries — ssdeep finds files with similar binary content.",
            "reveal": "The imphash is a hash of the import table — samples from the same builder/family often share imphashes. Search the imphash in threat intel to find related samples. The ssdeep fuzzy hash can identify modified versions of the same file (repacked, slightly modified). Together, these help cluster related samples and identify campaigns even when exact hashes differ.",
            "evidence_fields": ["imphash", "ssdeep"],
            "free_text": True,
        },
        {
            "id": 5,
            "phase": "Behavioral Classification",
            "question": "Based on the YARA matches and threat intelligence, what is your classification of this malware's primary capability? (e.g., ransomware, RAT, stealer, loader, wiper, etc.)",
            "hint": "Cross-reference the YARA rule names, VT family labels, and ThreatHQ classification for consensus.",
            "reveal": "Classification uses multiple signals: YARA rule names often contain the category (e.g., 'Trojan_Downloader', 'Ransomware_Lockbit'), VT family labels aggregate vendor classifications, and ThreatHQ provides curated family identification. When signals disagree, weight specific YARA rule matches highest, then VT consensus, then generic labels. Document your confidence level.",
            "evidence_fields": ["yara_matches", "vt_family", "thq_family"],
            "free_text": True,
        },
        {
            "id": 6,
            "phase": "YARA / Signature Context",
            "question": "Review each YARA rule match in detail. What specific strings or patterns triggered the detection? What do these patterns tell you about the malware's functionality?",
            "hint": "Expand the matched strings — they often contain API names, C2 URLs, encryption constants, or unique markers.",
            "reveal": "YARA matched strings reveal: specific API calls the malware uses (indicating capabilities), embedded C2 infrastructure (URLs, IPs, domains), encryption or encoding routines, unique identifiers (mutexes, registry keys, file names), and sometimes attribution markers. Each matched string is a potential IOC that can be used for further hunting.",
            "evidence_fields": ["yara_matches"],
            "free_text": True,
        },
        {
            "id": 7,
            "phase": "IOC Extraction",
            "question": "What indicators of compromise (IOCs) can you extract from this case? List network indicators, file indicators, and any behavioral indicators.",
            "hint": "Check the IOCs section of the case data for URLs, IPs, and domains already identified.",
            "reveal": "IOC categories to extract: File indicators (MD5, SHA256, imphash, ssdeep, file names), Network indicators (C2 IPs, domains, URLs from case IOCs and YARA strings), Host indicators (mutex names, registry keys, file paths from YARA matches), and Behavioral indicators (process names, scheduled task patterns). All IOCs should be documented with confidence levels and shared via your threat intel platform.",
            "evidence_fields": ["md5", "sha256", "imphash", "iocs", "yara_matches"],
            "free_text": True,
        },
        {
            "id": 8,
            "phase": "Mitigation",
            "question": "Based on your complete analysis, write a brief incident summary and list your recommended containment and remediation actions.",
            "hint": "Structure your response as: Summary → Immediate Actions → Short-term Remediation → Long-term Prevention.",
            "reveal": "A complete response should include: (1) Executive summary: what the malware is, how it was delivered, what it does. (2) Immediate containment: isolate hosts, block IOCs at perimeter, disable compromised accounts. (3) Remediation: remove persistence mechanisms, clean infected systems, rotate credentials. (4) Prevention: update detection signatures, patch exploited vulnerabilities, improve email/web filtering, conduct user awareness training. (5) Documentation: update case notes, share IOCs with threat intel community.",
            "evidence_fields": ["threat_score", "yara_matches", "iocs", "vt_hits"],
            "free_text": True,
        },
    ],
}


class AssessmentEngine:
    """Engine for guided, CTF-style malware assessment walkthroughs."""

    def load_cases_from_disk(self, case_storage_path: str) -> list:
        """Enumerate case subdirectories and return a list of case summaries."""
        cases = []
        if not os.path.isdir(case_storage_path):
            return cases

        for entry in os.listdir(case_storage_path):
            case_dir = os.path.join(case_storage_path, entry)
            metadata_path = os.path.join(case_dir, "case_metadata.json")
            if not os.path.isdir(case_dir) or not os.path.isfile(metadata_path):
                continue
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                cases.append({
                    "id": meta.get("id", entry),
                    "created": meta.get("created", ""),
                    "total_threats": meta.get("total_threats", 0),
                    "file_count": len(meta.get("files", [])),
                    "status": meta.get("status", "UNKNOWN"),
                    "case_dir": case_dir,
                })
            except (json.JSONDecodeError, OSError):
                continue

        cases.sort(key=lambda c: c.get("created", ""), reverse=True)
        return cases

    def load_case_for_assessment(self, case_dir: str) -> dict:
        """Load the full case_metadata.json for a selected case."""
        metadata_path = os.path.join(case_dir, "case_metadata.json")
        with open(metadata_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def infer_category(self, case_data: dict) -> str:
        """Inspect case data to determine the malware category."""
        signals = []

        # Collect text signals from all files
        for file_info in case_data.get("files", []):
            thq = str(file_info.get("thq_family", "")).lower()
            vt_fam = str(file_info.get("vt_family", "")).lower()
            signals.append(thq)
            signals.append(vt_fam)
            for match in file_info.get("yara_matches", []):
                signals.append(str(match.get("rule", "")).lower())

        combined = " ".join(signals)

        # Category keyword matching (order matters — more specific first)
        if any(kw in combined for kw in ["ransom", "crypt", "lock", "wanna", "ryuk", "conti"]):
            return "ransomware"
        if any(kw in combined for kw in ["rat", "remote", "agent", "backdoor", "njrat",
                                          "asyncrat", "quasar", "darkcomet", "remcos"]):
            return "rat"
        if any(kw in combined for kw in ["stealer", "infostealer", "pws", "redline",
                                          "raccoon", "vidar", "formbook", "kredential", "spy"]):
            return "stealer"
        if any(kw in combined for kw in ["loader", "dropper", "downloader", "emotet",
                                          "bazar", "iceloader", "qakbot"]):
            return "loader"

        return "generic"

    def _prioritize_steps(self, steps: list, case_data: dict) -> list:
        """Sort steps so those whose evidence_fields intersect non-empty case fields come first."""
        # Gather which evidence field names have non-empty data in the case
        available_fields = set()
        for file_info in case_data.get("files", []):
            for key, val in file_info.items():
                if val and val != 0 and val != [] and val != "":
                    available_fields.add(key)
        # Also check top-level fields
        for key in ("iocs",):
            val = case_data.get(key)
            if val and val != {} and val != {"urls": [], "ips": [], "domains": []}:
                available_fields.add(key)
        # Also add aggregate fields
        if case_data.get("total_threats", 0) > 0:
            available_fields.add("threat_score")

        def sort_key(step):
            overlap = len(set(step.get("evidence_fields", [])) & available_fields)
            return -overlap  # More overlap = sort first

        return sorted(steps, key=sort_key)

    def load_assessment_questions(self, case_dir: str):
        """Load assessment_questions.json from a case directory.

        Returns the questions list, or None if the file doesn't exist.
        """
        qpath = os.path.join(case_dir, "assessment_questions.json")
        if not os.path.isfile(qpath):
            return None
        try:
            with open(qpath, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return None
            data = json.loads(content)
            return data.get("questions", [])
        except (json.JSONDecodeError, OSError):
            return None

    def generate_assessment_template(self, case_data: dict, dest_dir: str):
        """Write an assessment_questions.json template into *dest_dir*.

        Uses the QUESTION_BANK category for the case, adds empty
        ``required_keywords`` so the overseer knows what to fill in.
        """
        category = self.infer_category(case_data)
        steps = QUESTION_BANK.get(category, QUESTION_BANK["generic"])
        questions = []
        for s in steps:
            q = dict(s)
            q.setdefault("required_keywords", [])
            questions.append(q)

        payload = {"questions": questions}
        qpath = os.path.join(dest_dir, "assessment_questions.json")
        with open(qpath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)

    @staticmethod
    def validate_answer(step: dict, answer: str) -> bool:
        """Check that *answer* contains every required keyword (case-insensitive).

        Returns True when ``required_keywords`` is empty or missing (free-pass).
        """
        keywords = step.get("required_keywords", [])
        if not keywords:
            return True
        answer_lower = answer.lower()
        return all(kw.lower() in answer_lower for kw in keywords)

    def start_session(self, case_data: dict, custom_steps: list = None) -> dict:
        """Create and return a new assessment session dict.

        If *custom_steps* is provided (from assessment_questions.json) they
        are used instead of QUESTION_BANK.
        """
        category = self.infer_category(case_data)

        if custom_steps:
            steps = [s.copy() for s in custom_steps]
            # Ensure defaults for optional fields
            for s in steps:
                s.setdefault("free_text", True)
                s.setdefault("required_keywords", [])
                s.setdefault("evidence_fields", [])
        else:
            steps = [s.copy() for s in QUESTION_BANK.get(category, QUESTION_BANK["generic"])]

        steps = self._prioritize_steps(steps, case_data)

        return {
            "case_id": case_data.get("id", "UNKNOWN"),
            "category": category,
            "steps": steps,
            "current_step_index": 0,
            "analyst_answers": [],
            "started_at": datetime.now().isoformat(),
        }

    def get_current_step(self, session: dict):
        """Return the current step dict, or None if complete."""
        idx = session.get("current_step_index", 0)
        steps = session.get("steps", [])
        if idx < len(steps):
            return steps[idx]
        return None

    def submit_step(self, session: dict, answer: str) -> dict:
        """Record the answer, advance the index, return the reveal text."""
        idx = session["current_step_index"]
        step = session["steps"][idx]
        session["analyst_answers"].append({
            "step_id": step["id"],
            "phase": step["phase"],
            "question": step["question"],
            "answer": answer,
            "reveal": step["reveal"],
            "timestamp": datetime.now().isoformat(),
        })
        session["current_step_index"] = idx + 1
        return {"reveal": step["reveal"]}

    def is_complete(self, session: dict) -> bool:
        """Check if all steps have been completed."""
        return session["current_step_index"] >= len(session["steps"])

    def export_session_report(self, session: dict, output_path: str):
        """Write a plain-text assessment report."""
        lines = []
        lines.append("=" * 70)
        lines.append("MAD ASSESSMENT REPORT")
        lines.append("=" * 70)
        lines.append(f"Case ID:    {session['case_id']}")
        lines.append(f"Category:   {session['category']}")
        lines.append(f"Started:    {session['started_at']}")
        lines.append(f"Completed:  {datetime.now().isoformat()}")
        lines.append(f"Steps:      {len(session['analyst_answers'])} / {len(session['steps'])}")
        lines.append("")

        for i, entry in enumerate(session["analyst_answers"], 1):
            lines.append("-" * 70)
            lines.append(f"Step {i}: [{entry['phase']}]")
            lines.append(f"Q: {entry['question']}")
            lines.append(f"A: {entry['answer']}")
            lines.append(f"Reveal: {entry['reveal']}")
            lines.append("")

        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
