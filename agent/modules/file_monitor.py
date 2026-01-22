"""
File Integrity Monitor Module for HIDS Agent
Detects unauthorized file modifications using SHA256 hashing
MITRE ATT&CK: T1565 (Data Manipulation)
"""

import os
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path


class FileIntegrityMonitor:
    def __init__(self, config):
        """
        Initialize File Integrity Monitor
        
        Args:
            config: Configuration dictionary containing monitored paths
        """
        self.config = config
        self.monitored_paths = config.get('monitored_paths', [])
        self.exclude_extensions = config.get('exclude_extensions', [])
        self.baseline_file = config.get('baseline_file', 'data/file_baseline.json')
        self.baseline = {}
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        
    def calculate_file_hash(self, filepath):
        """
        Calculate SHA256 hash of a file
        
        Args:
            filepath: Path to the file
            
        Returns:
            str: SHA256 hash of the file or None if error
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                # Read file in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as e:
            print(f"[ERROR] Cannot hash {filepath}: {e}")
            return None
    
    def get_file_metadata(self, filepath):
        """
        Get file metadata (permissions, owner, size, mtime)
        
        Args:
            filepath: Path to the file
            
        Returns:
            dict: File metadata
        """
        try:
            stat_info = os.stat(filepath)
            return {
                'size': stat_info.st_size,
                'permissions': oct(stat_info.st_mode)[-3:],
                'owner_uid': stat_info.st_uid,
                'owner_gid': stat_info.st_gid,
                'modified_time': stat_info.st_mtime
            }
        except Exception as e:
            print(f"[ERROR] Cannot get metadata for {filepath}: {e}")
            return {}
    
    def should_monitor_file(self, filepath):
        """
        Check if file should be monitored (based on extensions)
        
        Args:
            filepath: Path to check
            
        Returns:
            bool: True if should be monitored
        """
        # Skip if file has excluded extension
        for ext in self.exclude_extensions:
            if filepath.endswith(ext):
                return False
        return True
    
    def scan_path(self, path):
        """
        Recursively scan a path and collect file information
        
        Args:
            path: Directory or file path to scan
            
        Returns:
            dict: Dictionary of filepath -> file info
        """
        file_data = {}
        
        try:
            if os.path.isfile(path):
                # Single file
                if self.should_monitor_file(path):
                    file_hash = self.calculate_file_hash(path)
                    if file_hash:
                        file_data[path] = {
                            'hash': file_hash,
                            'metadata': self.get_file_metadata(path)
                        }
            
            elif os.path.isdir(path):
                # Directory - scan recursively
                for root, dirs, files in os.walk(path):
                    # Limit depth for /bin and /usr/bin to avoid too many files
                    if root.count(os.sep) - path.count(os.sep) > 1:
                        continue
                        
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        
                        if self.should_monitor_file(filepath):
                            file_hash = self.calculate_file_hash(filepath)
                            if file_hash:
                                file_data[filepath] = {
                                    'hash': file_hash,
                                    'metadata': self.get_file_metadata(filepath)
                                }
        
        except PermissionError:
            print(f"[WARNING] Permission denied for path: {path}")
        except Exception as e:
            print(f"[ERROR] Error scanning {path}: {e}")
        
        return file_data
    
    def create_baseline(self):
        """
        Create initial baseline of all monitored files
        """
        print("[INFO] Creating file integrity baseline...")
        baseline_data = {
            'created_at': datetime.now().isoformat(),
            'files': {}
        }
        
        for path in self.monitored_paths:
            print(f"[INFO] Scanning: {path}")
            if os.path.exists(path):
                file_data = self.scan_path(path)
                baseline_data['files'].update(file_data)
            else:
                print(f"[WARNING] Path does not exist: {path}")
        
        # Save baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        self.baseline = baseline_data['files']
        print(f"[SUCCESS] Baseline created with {len(self.baseline)} files")
        return baseline_data
    
    def load_baseline(self):
        """
        Load existing baseline from file
        
        Returns:
            bool: True if baseline loaded successfully
        """
        try:
            if not os.path.exists(self.baseline_file):
                print("[WARNING] No baseline file found. Creating new baseline...")
                self.create_baseline()
                return True
            
            with open(self.baseline_file, 'r') as f:
                baseline_data = json.load(f)
                self.baseline = baseline_data.get('files', {})
                print(f"[INFO] Baseline loaded: {len(self.baseline)} files")
                return True
        
        except Exception as e:
            print(f"[ERROR] Failed to load baseline: {e}")
            return False
    
    def check_integrity(self):
        """
        Check current file state against baseline
        
        Returns:
            list: List of detected changes (events)
        """
        events = []
        print("[INFO] Starting integrity check...")
        
        current_files = {}
        
        # Scan all monitored paths
        for path in self.monitored_paths:
            if os.path.exists(path):
                file_data = self.scan_path(path)
                current_files.update(file_data)
        
        # Check for modifications and deletions
        for filepath, baseline_info in self.baseline.items():
            if filepath in current_files:
                # File exists - check if modified
                current_hash = current_files[filepath]['hash']
                baseline_hash = baseline_info['hash']
                
                if current_hash != baseline_hash:
                    event = {
                        'event_type': 'file_modified',
                        'severity': 'high',
                        'timestamp': datetime.now().isoformat(),
                        'filepath': filepath,
                        'old_hash': baseline_hash,
                        'new_hash': current_hash,
                        'metadata': current_files[filepath]['metadata'],
                        'mitre_technique': 'T1565',
                        'description': f'File integrity violation detected: {filepath}'
                    }
                    events.append(event)
                    print(f"[ALERT] Modified: {filepath}")
            else:
                # File was deleted
                event = {
                    'event_type': 'file_deleted',
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat(),
                    'filepath': filepath,
                    'old_hash': baseline_info['hash'],
                    'mitre_technique': 'T1070.004',  # File Deletion
                    'description': f'Critical file deleted: {filepath}'
                }
                events.append(event)
                print(f"[ALERT] Deleted: {filepath}")
        
        # Check for new files
        for filepath in current_files:
            if filepath not in self.baseline:
                event = {
                    'event_type': 'file_created',
                    'severity': 'medium',
                    'timestamp': datetime.now().isoformat(),
                    'filepath': filepath,
                    'new_hash': current_files[filepath]['hash'],
                    'metadata': current_files[filepath]['metadata'],
                    'mitre_technique': 'T1105',  # Ingress Tool Transfer
                    'description': f'New file detected in monitored directory: {filepath}'
                }
                events.append(event)
                print(f"[ALERT] New file: {filepath}")
        
        if events:
            print(f"[WARNING] Detected {len(events)} integrity violations")
        else:
            print("[INFO] No integrity violations detected")
        
        return events
    
    def update_baseline(self):
        """
        Update baseline with current file state
        (Use cautiously - only after verifying changes are legitimate)
        """
        print("[INFO] Updating baseline...")
        self.create_baseline()


# Test function
if __name__ == "__main__":
    # Test configuration
    test_config = {
        'monitored_paths': [
            '/etc/passwd',
            '/etc/hosts'
        ],
        'exclude_extensions': ['.log', '.tmp'],
        'baseline_file': 'data/file_baseline.json'
    }
    
    # Initialize monitor
    fim = FileIntegrityMonitor(test_config)
    
    # Create or load baseline
    fim.load_baseline()
    
    # Perform integrity check
    print("\n" + "="*60)
    events = fim.check_integrity()
    
    # Display events
    if events:
        print(f"\n[DETECTED EVENTS]")
        for event in events:
            print(json.dumps(event, indent=2))