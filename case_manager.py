"""
Case Manager Module
Handles case creation, file management, and metadata collection

Requirements:
pip install requests yara-python ssdeep
"""

import os
import json
import hashlib
import shutil
import zipfile
import tarfile
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import requests
import yara
import tempfile
import re
from urllib.parse import urlparse

# Import from other modules (to be created)
# from utils.file_handler import FileHandler
# from thq import get_thq_family


class CaseManager:
    def __init__(self, yara_rules_path=None, case_storage_path=None, whitelist_path=None,
                 vt_api_key=None, threathq_user=None, threathq_pass=None, settings_manager=None):
        """
        Initialize Case Manager

        Args:
            yara_rules_path: Path to YARA rules directory (if None, will look in common locations)
            case_storage_path: Path where cases will be stored (if None, uses Desktop/MAD_Cases)
            whitelist_path: Path to whitelist.txt file with SHA256 hashes
            vt_api_key: VirusTotal API key (if None, uses default)
            threathq_user: ThreatHQ username (if None, uses default)
            threathq_pass: ThreatHQ password (if None, uses default)
        """
        # Auto-detect YARA rules path if not provided
        if yara_rules_path is None:
            possible_paths = [
                # Absolute path (most reliable)
                r"C:\Users\REM\Desktop\MAD\YDAMN",
                # Desktop relative
                os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "YDAMN"),
                # Current directory + YDAMN (if running from MAD folder)
                os.path.join(os.getcwd(), "YDAMN"),
                # Parent directory + MAD/YDAMN
                os.path.join(os.path.dirname(os.getcwd()), "MAD", "YDAMN"),
                # Current directory + MAD/YDAMN
                os.path.join(os.getcwd(), "MAD", "YDAMN"),
                # Relative paths
                "YDAMN",
                "MAD/YDAMN",
                "./YDAMN",
                "../MAD/YDAMN"
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    yara_rules_path = os.path.abspath(path)
                    print(f"Found YARA rules at: {yara_rules_path}")
                    break
            
            if yara_rules_path is None:
                print("WARNING: YARA rules directory not found! Checked:")
                for path in possible_paths:
                    abs_path = os.path.abspath(path) if not os.path.isabs(path) else path
                    print(f"  - {abs_path} {'(exists)' if os.path.exists(path) else '(not found)'}")
                yara_rules_path = "YDAMN"  # fallback
        
        # Set case storage path to Desktop/MAD_Cases if not provided
        if case_storage_path is None:
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            case_storage_path = os.path.join(desktop_path, "MAD_Cases")
            print(f"Desktop path detected: {desktop_path}")
            print(f"Cases will be saved to: {case_storage_path}")
            
            # Verify the path exists or can be created
            if not os.path.exists(desktop_path):
                print(f"WARNING: Desktop path does not exist: {desktop_path}")
        
        # Auto-detect whitelist path
        if whitelist_path is None:
            whitelist_paths = [
                "whitelist.txt",
                os.path.join(os.getcwd(), "whitelist.txt"),
                os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "whitelist.txt"),
                r"C:\Users\REM\Desktop\MAD\whitelist.txt"
            ]
            for path in whitelist_paths:
                if os.path.exists(path):
                    whitelist_path = path
                    print(f"Found whitelist at: {whitelist_path}")
                    break
            
            if whitelist_path is None:
                print("INFO: No whitelist.txt found - all files will be analyzed")
                # Create empty whitelist file as template
                default_path = os.path.join(os.getcwd(), "whitelist.txt")
                try:
                    with open(default_path, 'w') as f:
                        f.write("# Whitelisted SHA256 hashes - one per line\n")
                        f.write("# Files matching these hashes will be marked as Benign\n")
                    print(f"Created template whitelist at: {default_path}")
                    whitelist_path = default_path
                except:
                    pass
            
        self.yara_rules_path = yara_rules_path
        self.case_storage_path = case_storage_path
        self.whitelist_path = whitelist_path
        self.settings_manager = settings_manager

        # API keys - use provided values or fall back to defaults
        self.vt_api_key = vt_api_key or "93aa3b4a6ba88ba96734df3e73147f89ecfd63164f3eacd240c1ff6e592d9d49"
        self.threathq_user = threathq_user or "088611ff43c14dcbb8ce10af714872b4"
        self.threathq_pass = threathq_pass or "5ea7fba6ebff4158a0469b47a49c2895"

        self.current_case = None
        self.yara_rules = None
        self.whitelisted_hashes = set()
        
        # Ensure storage directory exists
        os.makedirs(self.case_storage_path, exist_ok=True)
        
        # Load YARA rules
        self.load_yara_rules()
        
        # Load whitelist
        self.load_whitelist()
    
    def load_yara_rules(self):
        """Load all YARA rules from the specified directory"""
        try:
            if not os.path.exists(self.yara_rules_path):
                print(f"ERROR: YARA rules directory does not exist: {self.yara_rules_path}")
                return
            
            yara_files = list(Path(self.yara_rules_path).glob("*.yara")) + \
                        list(Path(self.yara_rules_path).glob("*.yar"))
            
            if not yara_files:
                print(f"WARNING: No YARA rules found in {self.yara_rules_path}")
                print(f"Looking for files: {list(Path(self.yara_rules_path).glob('*'))}")
                return
            
            print(f"Found {len(yara_files)} YARA rule files:")
            for yf in yara_files:
                print(f"  - {yf.name}")
            
            # Create a dictionary of rules for compilation
            rules_dict = {}
            for idx, yara_file in enumerate(yara_files):
                namespace = f"rule_{idx}_{yara_file.stem}"
                rules_dict[namespace] = str(yara_file)
            
            # Compile all rules
            print("Compiling YARA rules...")
            self.yara_rules = yara.compile(filepaths=rules_dict)
            print(f"Successfully loaded {len(yara_files)} YARA rule files")
            
        except Exception as e:
            print(f"ERROR loading YARA rules: {e}")
            import traceback
            traceback.print_exc()
            self.yara_rules = None
    
    def load_whitelist(self):
        """Load whitelisted SHA256 hashes from whitelist.txt"""
        if not self.whitelist_path or not os.path.exists(self.whitelist_path):
            print("No whitelist loaded")
            return
        
        try:
            with open(self.whitelist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        # Validate it's a SHA256 (64 hex characters)
                        if len(line) == 64 and all(c in '0123456789abcdefABCDEF' for c in line):
                            self.whitelisted_hashes.add(line.lower())
            
            print(f"Loaded {len(self.whitelisted_hashes)} whitelisted hashes")

        except Exception as e:
            print(f"Error loading whitelist: {e}")

    def _create_network_case_folder(self, report_url: str) -> Optional[str]:
        """
        Create a network case folder based on report URL

        Args:
            report_url: Report URL (e.g., https://xpo-mpdr.managedphishme.com/reports/306892)

        Returns:
            Path to created network folder, or None if creation failed or disabled
        """
        if not self.settings_manager:
            return None

        try:
            network_path = self.settings_manager.get_network_case_folder_path(report_url)
            if not network_path:
                return None

            # Create the network folder
            os.makedirs(network_path, exist_ok=True)

            # Create a files subdirectory in the network folder too
            network_files_dir = os.path.join(network_path, "files")
            os.makedirs(network_files_dir, exist_ok=True)

            print(f"Created network case folder: {network_path}")
            return network_path

        except Exception as e:
            print(f"Error creating network case folder: {e}")
            return None

    def sync_case_to_network(self, case_dir: str, network_path: str) -> bool:
        """
        Sync case files to network folder

        Args:
            case_dir: Local case directory
            network_path: Network folder path

        Returns:
            True if sync successful, False otherwise
        """
        try:
            if not network_path or not os.path.exists(case_dir):
                return False

            # Copy case metadata
            local_metadata = os.path.join(case_dir, "case_metadata.json")
            if os.path.exists(local_metadata):
                shutil.copy2(local_metadata, os.path.join(network_path, "case_metadata.json"))

            # Copy case notes if exists
            local_notes = os.path.join(case_dir, "case_notes.txt")
            if os.path.exists(local_notes):
                shutil.copy2(local_notes, os.path.join(network_path, "case_notes.txt"))

            # Copy files directory
            local_files_dir = os.path.join(case_dir, "files")
            network_files_dir = os.path.join(network_path, "files")

            if os.path.exists(local_files_dir):
                for filename in os.listdir(local_files_dir):
                    src = os.path.join(local_files_dir, filename)
                    dst = os.path.join(network_files_dir, filename)
                    if os.path.isfile(src):
                        shutil.copy2(src, dst)

            print(f"Synced case to network: {network_path}")
            return True

        except Exception as e:
            print(f"Error syncing case to network: {e}")
            return False

    def create_case(self, file_paths: List[str], report_url: str = None) -> Dict:
        """
        Create a new case with initial file uploads

        Args:
            file_paths: List of file paths to analyze
            report_url: Optional report URL for network folder naming (e.g., https://xpo-mpdr.managedphishme.com/reports/306892)

        Returns:
            Case information dictionary
        """
        # Generate case ID
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        case_dir = os.path.join(self.case_storage_path, case_id)
        files_dir = os.path.join(case_dir, "files")

        # Create case directories
        os.makedirs(files_dir, exist_ok=True)

        # Create network folder if enabled and report URL provided
        network_case_path = None
        if report_url and self.settings_manager:
            network_case_path = self._create_network_case_folder(report_url)

        # Initialize case data
        case_data = {
            "id": case_id,
            "created": datetime.now().isoformat(),
            "status": "ACTIVE",
            "report_url": report_url or "",
            "network_case_path": network_case_path or "",
            "files": [],
            "total_threats": 0,
            "total_vt_hits": 0,
            "iocs": {
                "urls": [],
                "ips": [],
                "domains": []
            }
        }
        
        # Process each file
        for file_path in file_paths:
            file_info = self.process_file(file_path, files_dir, case_id)
            case_data["files"].append(file_info)
            
            # Update case statistics - count as threat if YARA match OR THQ match OR VT hits
            # BUT NOT if whitelisted
            if not file_info.get("whitelisted", False):
                has_yara = len(file_info["yara_matches"]) > 0
                has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                has_vt = file_info["vt_hits"] > 0
                
                if has_yara or has_thq or has_vt:
                    case_data["total_threats"] += 1
                case_data["total_vt_hits"] += file_info["vt_hits"]
        
        # Save case metadata
        self.save_case_metadata(case_dir, case_data)
        
        self.current_case = case_data
        return case_data
    
    def add_files_to_case(self, file_paths: List[str]) -> Dict:
        """
        Add files to existing case
        
        Args:
            file_paths: List of file paths to add
            
        Returns:
            Updated case information
        """
        if not self.current_case:
            raise ValueError("No active case. Create a case first.")
        
        case_id = self.current_case["id"]
        case_dir = os.path.join(self.case_storage_path, case_id)
        files_dir = os.path.join(case_dir, "files")
        
        # Process each new file
        for file_path in file_paths:
            file_info = self.process_file(file_path, files_dir, case_id)
            self.current_case["files"].append(file_info)
            
            # Update case statistics - count as threat if YARA match OR THQ match OR VT hits
            # BUT NOT if whitelisted
            if not file_info.get("whitelisted", False):
                has_yara = len(file_info["yara_matches"]) > 0
                has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                has_vt = file_info["vt_hits"] > 0
                
                if has_yara or has_thq or has_vt:
                    self.current_case["total_threats"] += 1
                self.current_case["total_vt_hits"] += file_info["vt_hits"]
        
        # Update case metadata
        self.save_case_metadata(case_dir, self.current_case)
        
        return self.current_case
    
    def process_file(self, file_path: str, storage_dir: str, case_id: str) -> Dict:
        """
        Process a single file: copy, hash, scan, and collect metadata
        
        Args:
            file_path: Original file path
            storage_dir: Directory to store the file
            case_id: Current case ID
            
        Returns:
            File information dictionary
        """
        filename = os.path.basename(file_path)
        print(f"\n{'='*60}")
        print(f"Processing file: {filename}")
        print(f"{'='*60}")
        
        # Copy file to case storage
        dest_path = os.path.join(storage_dir, filename)
        shutil.copy2(file_path, dest_path)
        print(f"Copied to: {dest_path}")
        
        # Calculate hashes
        print("Calculating hashes...")
        md5, sha256, imphash, ssdeep = self.calculate_hashes(dest_path)
        print(f"  MD5: {md5}")
        print(f"  SHA256: {sha256}")
        print(f"  IMPHASH: {imphash}")
        print(f"  SSDEEP: {ssdeep}")

        # Get file size
        file_size = os.path.getsize(dest_path)
        print(f"File size: {file_size} bytes")

        # Detect file type
        print("Detecting file type...")
        file_type = self.detect_file_type(dest_path)
        print(f"  File Type: {file_type}")

        # Scan with YARA
        yara_matches = self.scan_with_yara(dest_path)

        # Query VirusTotal
        print("Querying VirusTotal...")
        vt_hits, vt_total, vt_family, vt_link = self.query_virustotal(sha256)
        print(f"  VT Hits: {vt_hits}/{vt_total}")
        print(f"  VT Family: {vt_family}")
        print(f"  VT Link: {vt_link}")

        # Get THQ Family using MD5
        print("Querying ThreatHQ...")
        thq_family = self.get_thq_family(md5)
        print(f"  THQ Family: {thq_family}")

        # Check if file is whitelisted
        is_whitelisted = sha256.lower() in self.whitelisted_hashes
        if is_whitelisted:
            print(f"✓ File is WHITELISTED")

        # Calculate threat score
        threat_score = self.calculate_threat_score(yara_matches, vt_hits)
        threat_level = self.get_threat_level(threat_score)
        print(f"Threat Score: {threat_score} ({threat_level})")

        # Compile file information
        file_info = {
            "filename": filename,
            "original_path": file_path,
            "storage_path": dest_path,
            "md5": md5,
            "sha256": sha256,
            "imphash": imphash,
            "ssdeep": ssdeep,
            "file_size": file_size,
            "file_type": file_type,
            "whitelisted": is_whitelisted,
            "yara_matches": yara_matches,
            "vt_hits": vt_hits,
            "vt_total": vt_total,
            "vt_family": vt_family,
            "vt_link": vt_link,
            "thq_family": thq_family,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "timestamp": datetime.now().isoformat(),
            "case_id": case_id
        }
        
        # Save individual file details
        self.save_file_details(storage_dir, filename, file_info)
        print(f"{'='*60}\n")
        
        return file_info
    
    def detect_file_type(self, file_path: str) -> str:
        """
        Detect the actual file type using magic bytes

        Args:
            file_path: Path to the file

        Returns:
            String describing the file type
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)  # Read first 32 bytes for magic number detection

            if len(header) < 2:
                return "Empty or invalid file"

            # PE/EXE/DLL detection
            if header[:2] == b'MZ':
                # Read PE header to determine if it's EXE or DLL
                try:
                    import pefile
                    pe = pefile.PE(file_path)
                    if pe.is_dll():
                        return "PE32 DLL (Windows)"
                    elif pe.is_exe():
                        return "PE32 EXE (Windows)"
                    else:
                        return "PE32 (Windows)"
                except:
                    return "PE/DOS executable"

            # Image formats
            if header[:8] == b'\x89PNG\r\n\x1a\n':
                return "PNG image"
            if header[:2] == b'\xff\xd8' and header[6:10] in (b'JFIF', b'Exif'):
                return "JPEG image"
            if header[:6] in (b'GIF87a', b'GIF89a'):
                return "GIF image"
            if header[:2] in (b'BM', b'BA', b'CI', b'CP', b'IC', b'PT'):
                return "BMP image"

            # Archive formats
            if header[:4] == b'PK\x03\x04' or header[:4] == b'PK\x05\x06' or header[:4] == b'PK\x07\x08':
                return "ZIP archive"
            if header[:2] == b'\x1f\x8b':
                return "GZIP archive"
            if header[:7] == b'Rar!\x1a\x07\x00' or header[:7] == b'Rar!\x1a\x07\x01':
                return "RAR archive"
            if header[:6] == b'7z\xbc\xaf\x27\x1c':
                return "7-Zip archive"

            # Document formats
            if header[:4] == b'%PDF':
                return "PDF document"
            if header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                return "Microsoft Office document (OLE2)"
            if header[:4] == b'PK\x03\x04':
                # Could be Office Open XML format
                return "ZIP/Office Open XML"

            # Script/text formats
            if header[:2] == b'#!':
                return "Shell script"
            if header[:5] == b'<?xml':
                return "XML document"
            if header[:5] == b'<html' or header[:6] == b'<!DOCT':
                return "HTML document"

            # ELF binary (Linux)
            if header[:4] == b'\x7fELF':
                return "ELF executable (Linux)"

            # Mach-O binary (macOS)
            if header[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
                return "Mach-O executable (macOS)"

            # Check if it's likely a text file
            try:
                header.decode('utf-8')
                # If we can decode it, it's likely text
                return "Text file"
            except UnicodeDecodeError:
                pass

            # Unknown binary
            return "Unknown binary data"

        except Exception as e:
            return f"Error detecting type: {str(e)}"

    def calculate_hashes(self, file_path: str) -> tuple:
        """
        Calculate MD5, SHA256, IMPHASH, and SSDEEP for a file

        Args:
            file_path: Path to the file

        Returns:
            Tuple of (md5, sha256, imphash, ssdeep)
        """
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        # Read file and calculate hashes
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        # IMPHASH calculation (requires pefile for PE files)
        imphash = "N/A"
        try:
            import pefile
            pe = pefile.PE(file_path)
            imphash = pe.get_imphash()
        except:
            pass  # Not a PE file or pefile not installed

        # SSDEEP calculation (fuzzy hash)
        ssdeep_hash = "N/A"
        try:
            import ssdeep
            ssdeep_hash = ssdeep.hash_from_file(file_path)
        except ImportError:
            pass  # ssdeep not installed
        except Exception:
            pass  # Error calculating ssdeep

        return md5_hash.hexdigest(), sha256_hash.hexdigest(), imphash, ssdeep_hash
    
    def scan_with_yara(self, file_path: str) -> List[Dict]:
        """
        Scan file with YARA rules

        Args:
            file_path: Path to file to scan

        Returns:
            List of dictionaries containing rule name and matched strings
            Format: [{"rule": "RuleName", "strings": [(offset, identifier, data), ...]}, ...]
        """
        if not self.yara_rules:
            print(f"WARNING: No YARA rules loaded, skipping scan for {file_path}")
            return []

        try:
            print(f"Scanning {os.path.basename(file_path)} with YARA...")
            matches = self.yara_rules.match(file_path)

            match_details = []
            if matches:
                print(f"  ✓ YARA MATCHES FOUND: {[m.rule for m in matches]}")
                for match in matches:
                    # Extract matched strings with their details
                    matched_strings = []
                    for string_match in match.strings:
                        # string_match is a yara.StringMatch object with attributes
                        identifier = string_match.identifier

                        # Each StringMatch can have multiple instances (locations where it matched)
                        for instance in string_match.instances:
                            offset = instance.offset
                            data = instance.matched_data

                            # Convert bytes to string for display, handle binary data
                            try:
                                if isinstance(data, bytes):
                                    # Try to decode as UTF-8, fallback to repr for binary
                                    try:
                                        data_str = data.decode('utf-8', errors='ignore')
                                    except:
                                        data_str = repr(data)
                                else:
                                    data_str = str(data)
                            except:
                                data_str = repr(data)

                            matched_strings.append({
                                "offset": offset,
                                "identifier": identifier,
                                "data": data_str
                            })

                    match_details.append({
                        "rule": match.rule,
                        "strings": matched_strings
                    })
            else:
                print(f"  - No YARA matches")

            return match_details
        except Exception as e:
            print(f"YARA scan error for {file_path}: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def query_virustotal(self, sha256: str) -> tuple:
        """
        Query VirusTotal for file information

        Args:
            sha256: SHA256 hash of the file

        Returns:
            Tuple of (detection_count, total_scans, most_common_family, vt_link)
        """
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}"

        if not self.vt_api_key:
            return 0, 0, "Unknown", vt_link

        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": self.vt_api_key}

            print(f"  Querying VT for SHA256: {sha256[:16]}...")
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)

                # Calculate total scans (all engines that scanned the file)
                total_scans = sum([
                    stats.get("malicious", 0),
                    stats.get("suspicious", 0),
                    stats.get("undetected", 0),
                    stats.get("harmless", 0),
                    stats.get("timeout", 0),
                    stats.get("confirmed-timeout", 0),
                    stats.get("failure", 0),
                    stats.get("type-unsupported", 0)
                ])

                # Extract most common family name
                results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
                families = []
                for engine, result in results.items():
                    if result.get("category") == "malicious":
                        result_name = result.get("result", "")
                        if result_name:
                            # Clean up family name
                            family = result_name.split('.')[0].split(':')[0].split('/')[0]
                            if family and len(family) > 2:
                                families.append(family)

                # Get most common family
                if families:
                    from collections import Counter
                    most_common = Counter(families).most_common(1)[0][0]
                else:
                    most_common = "Unknown"

                print(f"    VT Response: {malicious}/{total_scans} detections, Family: {most_common}")
                return malicious, total_scans, most_common, vt_link

            elif response.status_code == 404:
                print(f"    VT Response: File not found in database")
                return 0, 0, "Unknown", vt_link

            elif response.status_code == 429:
                print(f"    VT Response: Rate limit exceeded, skipping VT check")
                return 0, 0, "RateLimited", vt_link

            else:
                print(f"    VT Response: Error {response.status_code}")
                return 0, 0, "Unknown", vt_link

        except Exception as e:
            print(f"    VirusTotal query error: {e}")

        return 0, 0, "Unknown", vt_link
    
    def get_thq_family(self, md5_hash: str) -> str:
        """
        Get THQ family classification using ThreatHQ API

        Args:
            md5_hash: MD5 hash of the file

        Returns:
            THQ family name
        """
        try:
            url = f"https://www.threathq.com/apiv1/threat/search/?malwareArtifactMD5={md5_hash}"

            response = requests.post(url, auth=(self.threathq_user, self.threathq_pass), timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                threats = data.get("data", {}).get("threats", [])
                for threat in threats:
                    block_set = threat.get("blockSet", [])
                    for block in block_set:
                        malware_family = block.get("malwareFamily", {})
                        family_name = malware_family.get("familyName")
                        if family_name:
                            return family_name
            
            return "Unknown"
            
        except Exception as e:
            print(f"ThreatHQ query error: {e}")
            return "Unknown"
    
    def calculate_threat_score(self, yara_matches: List[Dict], vt_hits: int) -> int:
        """
        Calculate threat score based on YARA matches and VT hits

        Args:
            yara_matches: List of YARA rule match dictionaries
            vt_hits: Number of VirusTotal detections

        Returns:
            Threat score (0-100)
        """
        score = 0

        # YARA matches contribute up to 40 points
        # yara_matches is now a list of dicts, so count the number of rules matched
        score += min(len(yara_matches) * 20, 40)
        
        # VT hits contribute up to 60 points
        if vt_hits > 0:
            # Scale VT hits: 1-10 hits = 20pts, 11-30 = 40pts, 31+ = 60pts
            if vt_hits >= 31:
                score += 60
            elif vt_hits >= 11:
                score += 40
            elif vt_hits >= 1:
                score += 20
        
        return min(score, 100)
    
    def get_threat_level(self, score: int) -> str:
        """
        Convert threat score to threat level

        Args:
            score: Threat score (0-100)

        Returns:
            Threat level string
        """
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 30:
            return "Medium"
        elif score > 0:
            return "Low"
        return "Clean"

    def _check_unsupported_url(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL is from a service that doesn't support direct downloads.

        Returns:
            Tuple of (is_unsupported, error_message)
        """
        parsed = urlparse(url)

        # Proton Drive - uses end-to-end encryption, requires JavaScript decryption
        if 'drive.proton.me' in parsed.netloc:
            return (True, "Proton Drive uses end-to-end encryption and cannot be downloaded directly. "
                         "Please download the file manually from your browser and upload it using the file picker.")

        return (False, "")

    def _convert_to_direct_download_url(self, url: str) -> str:
        """
        Convert sharing URLs to direct download URLs for various services.

        Supports:
        - Dropbox: www.dropbox.com -> dl.dropboxusercontent.com
        - Google Drive: Convert to direct download format
        """
        parsed = urlparse(url)

        # Dropbox conversion
        if 'dropbox.com' in parsed.netloc:
            # Convert www.dropbox.com to dl.dropboxusercontent.com for direct download
            # Remove query params except for the file path
            if 'www.dropbox.com' in parsed.netloc or 'dropbox.com' == parsed.netloc:
                new_url = url.replace('www.dropbox.com', 'dl.dropboxusercontent.com')
                new_url = new_url.replace('dropbox.com', 'dl.dropboxusercontent.com')
                # Remove dl parameter as it's not needed for dl.dropboxusercontent.com
                if '?' in new_url:
                    base, params = new_url.split('?', 1)
                    # Keep only essential params, remove dl=0/1
                    param_pairs = params.split('&')
                    filtered_params = [p for p in param_pairs if not p.startswith('dl=')]
                    if filtered_params:
                        new_url = base + '?' + '&'.join(filtered_params)
                    else:
                        new_url = base
                print(f"Converted Dropbox URL to direct download: {new_url}")
                return new_url

        # Google Drive conversion
        if 'drive.google.com' in parsed.netloc:
            # Convert /file/d/FILE_ID/view to direct download
            import re
            match = re.search(r'/file/d/([^/]+)', url)
            if match:
                file_id = match.group(1)
                new_url = f"https://drive.google.com/uc?export=download&id={file_id}"
                print(f"Converted Google Drive URL to direct download: {new_url}")
                return new_url

        return url

    def _extract_archive(self, archive_path: str) -> Tuple[bool, List[str], str]:
        """
        Extract files from an archive (zip, tar, tar.gz, etc.)

        Args:
            archive_path: Path to the archive file

        Returns:
            Tuple of (success, list of extracted file paths, error_message)
        """
        extracted_files = []
        extract_dir = os.path.join(tempfile.gettempdir(), f"extracted_{datetime.now().strftime('%Y%m%d%H%M%S')}")

        try:
            os.makedirs(extract_dir, exist_ok=True)
            lower_path = archive_path.lower()

            if lower_path.endswith('.zip'):
                print(f"Extracting ZIP archive: {archive_path}")
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    # Extract all files
                    zf.extractall(extract_dir)
                    for name in zf.namelist():
                        if not name.endswith('/'):  # Skip directories
                            extracted_files.append(os.path.join(extract_dir, name))

            elif lower_path.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2')):
                print(f"Extracting TAR archive: {archive_path}")
                with tarfile.open(archive_path, 'r:*') as tf:
                    tf.extractall(extract_dir)
                    for member in tf.getmembers():
                        if member.isfile():
                            extracted_files.append(os.path.join(extract_dir, member.name))

            elif lower_path.endswith('.7z'):
                # Try to use py7zr if available
                try:
                    import py7zr
                    print(f"Extracting 7Z archive: {archive_path}")
                    with py7zr.SevenZipFile(archive_path, mode='r') as z:
                        z.extractall(extract_dir)
                        for name in z.getnames():
                            full_path = os.path.join(extract_dir, name)
                            if os.path.isfile(full_path):
                                extracted_files.append(full_path)
                except ImportError:
                    return False, [], "7z extraction requires py7zr package (pip install py7zr)"

            elif lower_path.endswith('.rar'):
                # Try to use rarfile if available
                try:
                    import rarfile
                    print(f"Extracting RAR archive: {archive_path}")
                    with rarfile.RarFile(archive_path, 'r') as rf:
                        rf.extractall(extract_dir)
                        for name in rf.namelist():
                            if not name.endswith('/'):
                                extracted_files.append(os.path.join(extract_dir, name))
                except ImportError:
                    return False, [], "RAR extraction requires rarfile package (pip install rarfile)"

            else:
                return False, [], f"Unsupported archive format: {archive_path}"

            print(f"Extracted {len(extracted_files)} files from archive")
            return True, extracted_files, ""

        except zipfile.BadZipFile:
            return False, [], f"Invalid or corrupted ZIP file: {archive_path}"
        except tarfile.TarError as e:
            return False, [], f"Error extracting TAR archive: {str(e)}"
        except Exception as e:
            return False, [], f"Error extracting archive: {str(e)}"

    def _is_archive(self, filename: str) -> bool:
        """Check if a file is an archive based on extension"""
        archive_extensions = ('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.7z', '.rar')
        return filename.lower().endswith(archive_extensions)

    def download_file_from_url(self, url: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Download a file from a URL to a temporary location (browser-like behavior)

        Args:
            url: URL to download from
            timeout: Request timeout in seconds

        Returns:
            Tuple of (success, file_path, error_message)
        """
        try:
            # Check if URL is from an unsupported service
            is_unsupported, unsupported_msg = self._check_unsupported_url(url)
            if is_unsupported:
                print(f"Unsupported URL service: {url}")
                return False, "", unsupported_msg

            # Convert sharing URLs to direct download URLs
            original_url = url
            url = self._convert_to_direct_download_url(url)
            print(f"Downloading file from URL: {url}")

            # Parse URL to get filename
            parsed_url = urlparse(original_url)  # Use original URL for filename extraction
            filename = os.path.basename(parsed_url.path)

            # If no filename in URL, generate one
            if not filename or '.' not in filename:
                filename = f"downloaded_file_{datetime.now().strftime('%Y%m%d%H%M%S')}.bin"

            # Create temporary file
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, filename)

            # Browser-like headers to mimic real browser requests
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0',
            }

            # Create a session for cookie handling (like a browser)
            session = requests.Session()
            response = session.get(url, headers=headers, timeout=timeout, stream=True, allow_redirects=True)
            response.raise_for_status()

            # Try to get filename from Content-Disposition header (like browsers do)
            content_disp = response.headers.get('Content-Disposition', '')
            if 'filename=' in content_disp:
                # Extract filename from header
                import re
                fname_match = re.search(r'filename[*]?=["\']?([^"\';\n]+)', content_disp)
                if fname_match:
                    filename = fname_match.group(1).strip()
                    temp_path = os.path.join(temp_dir, filename)

            # Write to temporary file
            with open(temp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            file_size = os.path.getsize(temp_path)
            print(f"Successfully downloaded {file_size} bytes to {temp_path}")

            # Add URL to IOCs if we have a current case
            if self.current_case:
                self.add_ioc("urls", url)

            return True, temp_path, ""

        except requests.exceptions.Timeout:
            error_msg = f"Timeout downloading from {url}"
            print(f"ERROR: {error_msg}")
            return False, "", error_msg

        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to download from {url}: {str(e)}"
            print(f"ERROR: {error_msg}")
            return False, "", error_msg

        except Exception as e:
            error_msg = f"Unexpected error downloading from {url}: {str(e)}"
            print(f"ERROR: {error_msg}")
            return False, "", error_msg

    def create_case_from_urls(self, urls: List[str]) -> Tuple[Dict, List[str]]:
        """
        Create a new case by downloading files from URLs

        Args:
            urls: List of URLs to download

        Returns:
            Tuple of (case_data, list of error messages)
        """
        downloaded_files = []
        errors = []

        # Download all files first
        for url in urls:
            success, file_path, error = self.download_file_from_url(url)
            if success:
                downloaded_files.append(file_path)
            else:
                errors.append(f"{url}: {error}")

        # Create case with downloaded files if any succeeded
        if downloaded_files:
            case_data = self.create_case(downloaded_files)

            # Clean up temporary files
            for file_path in downloaded_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except:
                    pass

            return case_data, errors
        else:
            raise ValueError("Failed to download any files from provided URLs")

    def add_files_from_urls_to_case(self, urls: List[str]) -> Tuple[Dict, List[str]]:
        """
        Add files to existing case by downloading from URLs

        Args:
            urls: List of URLs to download

        Returns:
            Tuple of (updated case_data, list of error messages)
        """
        if not self.current_case:
            raise ValueError("No active case. Create a case first.")

        downloaded_files = []
        errors = []

        # Download all files first
        for url in urls:
            success, file_path, error = self.download_file_from_url(url)
            if success:
                downloaded_files.append(file_path)
            else:
                errors.append(f"{url}: {error}")

        # Add files to case if any succeeded
        if downloaded_files:
            case_data = self.add_files_to_case(downloaded_files)

            # Clean up temporary files
            for file_path in downloaded_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except:
                    pass

            return case_data, errors
        else:
            return self.current_case, errors

    def add_ioc(self, ioc_type: str, value: str):
        """
        Add an IOC (Indicator of Compromise) to the current case

        Args:
            ioc_type: Type of IOC ('urls', 'ips', 'domains')
            value: IOC value
        """
        if not self.current_case:
            return

        if ioc_type not in self.current_case.get("iocs", {}):
            if "iocs" not in self.current_case:
                self.current_case["iocs"] = {"urls": [], "ips": [], "domains": []}

        # Avoid duplicates
        if value not in self.current_case["iocs"][ioc_type]:
            self.current_case["iocs"][ioc_type].append(value)

            # Save updated metadata
            case_id = self.current_case["id"]
            case_dir = os.path.join(self.case_storage_path, case_id)
            self.save_case_metadata(case_dir, self.current_case)

    def extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs (URLs, IPs, domains) from text

        Args:
            text: Text to extract IOCs from

        Returns:
            Dictionary with lists of URLs, IPs, and domains
        """
        iocs = {"urls": [], "ips": [], "domains": []}

        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        iocs["urls"].extend(urls)

        # IP pattern (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        # Filter out invalid IPs
        valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
        iocs["ips"].extend(valid_ips)

        # Domain pattern (basic)
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(domain_pattern, text.lower())
        iocs["domains"].extend(domains)

        # Remove duplicates
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        return iocs
    
    def format_file_details(self, file_info: Dict) -> str:
        """
        Format file details for display

        Args:
            file_info: File information dictionary

        Returns:
            Formatted string for display
        """
        # Format YARA matches with detailed information
        yara_matches = file_info.get("yara_matches", [])
        if yara_matches:
            yara_details = []
            # Handle both old format (list of strings) and new format (list of dicts)
            for match in yara_matches:
                if isinstance(match, str):
                    # Old format: just rule names
                    yara_details.append(f"\n  Rule: {match}")
                elif isinstance(match, dict):
                    # New format: dict with rule name and matched strings
                    rule_name = match.get("rule", "Unknown")
                    matched_strings = match.get("strings", [])

                    yara_details.append(f"\n  Rule: {rule_name}")
                    if matched_strings:
                        yara_details.append(f"  Matched Strings ({len(matched_strings)}):")
                        # Show up to 5 matched strings to avoid overwhelming output
                        for i, string_info in enumerate(matched_strings[:5], 1):
                            offset = string_info.get("offset", "?")
                            identifier = string_info.get("identifier", "?")
                            data = string_info.get("data", "")
                            # Truncate long strings for display
                            if len(data) > 60:
                                data = data[:57] + "..."
                            yara_details.append(f"    {i}. [{identifier}] @ 0x{offset:X}: {data}")

                        if len(matched_strings) > 5:
                            yara_details.append(f"    ... and {len(matched_strings) - 5} more")
                    else:
                        yara_details.append("  No string matches captured")

            yara_display = "\n".join(yara_details)
        else:
            yara_display = "\n  None"

        # Format VT information
        vt_hits = file_info.get('vt_hits', 0)
        vt_total = file_info.get('vt_total', 0)
        vt_link = file_info.get('vt_link', 'N/A')

        if vt_total > 0:
            vt_ratio = f"{vt_hits}/{vt_total}"
            vt_link_line = f"\nVT Link: {vt_link}"
        else:
            vt_ratio = f"{vt_hits}"
            vt_link_line = ""  # Don't show link if file not found in VT

        details = f"""File Details:
==================================================================
File Name: {file_info['filename']}
MD5: {file_info['md5']}
SHA256: {file_info['sha256']}
File Size: {file_info['file_size']} bytes
==================================================================
File Type: {file_info.get('file_type', 'Unknown')}
IMPHASH: {file_info.get('imphash', 'N/A')}
SSDEEP: {file_info.get('ssdeep', 'N/A')}
==================================================================
YARA Matches:{yara_display}
==================================================================
VT Detection: {vt_ratio}
VT Family: {file_info.get('vt_family', 'Unknown')}{vt_link_line}
THQ Family: {file_info.get('thq_family', 'Unknown')}
Threat Score: {file_info.get('threat_score', 0)} ({file_info.get('threat_level', 'Unknown')})
=================================================================="""

        return details
    
    def get_yara_display_text(self, yara_matches: List) -> str:
        """
        Format YARA matches for GUI display (e.g., "RuleName +2")

        Args:
            yara_matches: List of YARA rule matches (strings or dictionaries)

        Returns:
            Formatted string for display
        """
        if not yara_matches:
            return "No Matches"

        # Handle both old format (list of strings) and new format (list of dicts)
        first_match = yara_matches[0]
        if isinstance(first_match, str):
            # Old format
            rule_name = first_match
        else:
            # New format
            rule_name = first_match.get("rule", "Unknown")

        if len(yara_matches) == 1:
            return rule_name

        return f"{rule_name} +{len(yara_matches) - 1}"
    
    def save_case_metadata(self, case_dir: str, case_data: Dict):
        """
        Save case metadata to JSON file and sync to network if enabled

        Args:
            case_dir: Case directory path
            case_data: Case data dictionary
        """
        metadata_path = os.path.join(case_dir, "case_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(case_data, f, indent=4)

        # Sync to network if path is configured
        network_path = case_data.get("network_case_path")
        if network_path:
            self.sync_case_to_network(case_dir, network_path)

    def save_case_notes(self, case_dir: str, notes: str):
        """
        Save case notes to text file

        Args:
            case_dir: Case directory path
            notes: Notes text content
        """
        notes_path = os.path.join(case_dir, "case_notes.txt")
        with open(notes_path, 'w', encoding='utf-8') as f:
            f.write(notes)

    def save_file_details(self, storage_dir: str, filename: str, file_info: Dict):
        """
        Save individual file details to JSON
        
        Args:
            storage_dir: Directory where file is stored
            filename: Name of the file
            file_info: File information dictionary
        """
        details_path = os.path.join(storage_dir, f"{filename}_details.json")
        with open(details_path, 'w') as f:
            json.dump(file_info, f, indent=4)
    
    def get_current_case(self) -> Optional[Dict]:
        """
        Get current active case
        
        Returns:
            Current case dictionary or None
        """
        return self.current_case
    
    def get_file_info(self, filename: str) -> Optional[Dict]:
        """
        Get information for a specific file in current case
        
        Args:
            filename: Name of the file
            
        Returns:
            File info dictionary or None
        """
        if not self.current_case:
            return None
        
        for file_info in self.current_case["files"]:
            if file_info["filename"] == filename:
                return file_info
        
        return None


# Example usage for testing
if __name__ == "__main__":
    # Initialize case manager
    manager = CaseManager()
    
    # Create a new case with files
    test_files = ["sample.exe"]  # Replace with actual test files
    
    if os.path.exists(test_files[0]):
        case = manager.create_case(test_files)
        print(f"Created case: {case['id']}")
        
        # Display file details
        for file_info in case["files"]:
            print("\n" + manager.format_file_details(file_info))
    else:
        print("Test file not found. Please provide a valid file path.")