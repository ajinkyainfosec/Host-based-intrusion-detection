"""
Process Monitor Module for HIDS Agent
Detects suspicious processes, crypto miners, privilege escalation, and anomalies
MITRE ATT&CK: T1055 (Process Injection), T1496 (Resource Hijacking), 
              T1548 (Privilege Escalation), T1059 (Command Execution)
"""

import os
import json
import psutil
import time
import re
from datetime import datetime
from collections import defaultdict


class ProcessMonitor:
    def __init__(self, config):
        """
        Initialize Process Monitor
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.baseline_file = config.get('baseline_file', 'data/process_baseline.json')
        self.cpu_threshold = config.get('cpu_threshold', 80)
        self.memory_threshold = config.get('memory_threshold', 80)
        self.crypto_miner_detection_enabled = config.get('check_crypto_miners', True)
        self.reverse_shell_detection_enabled = config.get('check_reverse_shells', True)
        self.privilege_escalation_detection_enabled = config.get('check_privilege_escalation', True)
        self.whitelist_processes = config.get('whitelist_processes', [])
        self.suspicious_process_names = config.get('suspicious_process_names', [])
        self.suspicious_commands = config.get('suspicious_commands', [])
        self.suspicious_paths = config.get('suspicious_paths', [])
        self.monitor_network_connections = config.get('monitor_network_connections', True)
        self.suspicious_ports = config.get('suspicious_ports', [])
        
        # Baseline data
        self.baseline = {}
        
        # Track process history
        self.process_history = defaultdict(list)
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
    
    def get_process_info(self, proc):
        """
        Get detailed information about a process
        
        Args:
            proc: psutil.Process object
            
        Returns:
            dict: Process information
        """
        try:
            pinfo = proc.as_dict(attrs=[
                'pid', 'name', 'exe', 'cmdline', 'username', 
                'status', 'cpu_percent', 'memory_percent',
                'create_time', 'num_threads', 'nice'
            ])
            
            # Get network connections if monitoring enabled
            if self.monitor_network_connections:
                try:
                    connections = proc.connections(kind='inet')
                    pinfo['connections'] = [
                        {
                            'local_addr': f"{c.laddr.ip}:{c.laddr.port}",
                            'remote_addr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                            'status': c.status
                        }
                        for c in connections
                    ]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pinfo['connections'] = []
            
            return pinfo
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def is_whitelisted(self, process_name):
        """
        Check if process is in whitelist
        
        Args:
            process_name: Name of the process
            
        Returns:
            bool: True if whitelisted
        """
        return any(wl in process_name.lower() for wl in self.whitelist_processes)
    
    def check_suspicious_name(self, pinfo):
        """
        Check if process name is suspicious
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            dict or None: Event if suspicious
        """
        process_name = pinfo.get('name', '').lower()
        
        for suspicious_name in self.suspicious_process_names:
            if suspicious_name.lower() in process_name:
                return {
                    'event_type': 'suspicious_process_name',
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'pid': pinfo.get('pid'),
                    'process_name': pinfo.get('name'),
                    'exe': pinfo.get('exe'),
                    'cmdline': ' '.join(pinfo.get('cmdline', [])),
                    'username': pinfo.get('username'),
                    'matched_pattern': suspicious_name,
                    'mitre_technique': 'T1036',
                    'description': f'Suspicious process detected: {pinfo.get("name")} (matches pattern: {suspicious_name})'
                }
        
        return None
    
    def check_suspicious_command(self, pinfo):
        """
        Check if command line contains suspicious patterns
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            list: Events for suspicious commands
        """
        events = []
        cmdline = ' '.join(pinfo.get('cmdline', [])).lower()
        
        for suspicious_cmd in self.suspicious_commands:
            if suspicious_cmd.lower() in cmdline:
                events.append({
                    'event_type': 'suspicious_command_execution',
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat(),
                    'pid': pinfo.get('pid'),
                    'process_name': pinfo.get('name'),
                    'exe': pinfo.get('exe'),
                    'cmdline': ' '.join(pinfo.get('cmdline', [])),
                    'username': pinfo.get('username'),
                    'matched_pattern': suspicious_cmd,
                    'mitre_technique': 'T1059',
                    'description': f'Suspicious command execution detected: {suspicious_cmd}'
                })
        
        return events
    
    def check_suspicious_path(self, pinfo):
        """
        Check if process is running from suspicious path
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            dict or None: Event if suspicious
        """
        exe_path = pinfo.get('exe', '')
        
        if not exe_path:
            return None
        
        for suspicious_path in self.suspicious_paths:
            # Handle wildcards
            pattern = suspicious_path.replace('*', '.*')
            if re.match(pattern, exe_path):
                return {
                    'event_type': 'process_from_suspicious_path',
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'pid': pinfo.get('pid'),
                    'process_name': pinfo.get('name'),
                    'exe': exe_path,
                    'cmdline': ' '.join(pinfo.get('cmdline', [])),
                    'username': pinfo.get('username'),
                    'suspicious_path': suspicious_path,
                    'mitre_technique': 'T1036.005',
                    'description': f'Process running from suspicious path: {exe_path}'
                }
        
        return None
    
    def check_high_resource_usage(self, pinfo):
        """
        Check for abnormally high CPU/memory usage (potential crypto miner)
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            dict or None: Event if high resource usage
        """
        cpu = pinfo.get('cpu_percent', 0)
        memory = pinfo.get('memory_percent', 0)
        
        if cpu > self.cpu_threshold or memory > self.memory_threshold:
            severity = 'critical' if (cpu > 90 or memory > 90) else 'high'
            
            return {
                'event_type': 'high_resource_usage',
                'severity': severity,
                'timestamp': datetime.now().isoformat(),
                'pid': pinfo.get('pid'),
                'process_name': pinfo.get('name'),
                'exe': pinfo.get('exe'),
                'cmdline': ' '.join(pinfo.get('cmdline', [])),
                'username': pinfo.get('username'),
                'cpu_percent': cpu,
                'memory_percent': memory,
                'mitre_technique': 'T1496',
                'description': f'High resource usage detected: CPU={cpu:.1f}%, Memory={memory:.1f}%'
            }
        
        return None
    
    def check_crypto_miner(self, pinfo):
        """
        Check for cryptocurrency mining indicators
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            dict or None: Event if crypto miner detected
        """
        if not self.crypto_miner_detection_enabled:  # Changed
            return None
        
        # Miner indicators
        miner_indicators = [
            'xmrig', 'minerd', 'ccminer', 'claymore', 'ethminer',
            'phoenix', 'nbminer', 'cryptonight', 'monero', 'stratum'
        ]
        
        cmdline = ' '.join(pinfo.get('cmdline', [])).lower()
        process_name = pinfo.get('name', '').lower()
        
        # Check process name and command line
        for indicator in miner_indicators:
            if indicator in process_name or indicator in cmdline:
                return {
                    'event_type': 'cryptocurrency_miner_detected',
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat(),
                    'pid': pinfo.get('pid'),
                    'process_name': pinfo.get('name'),
                    'exe': pinfo.get('exe'),
                    'cmdline': ' '.join(pinfo.get('cmdline', [])),
                    'username': pinfo.get('username'),
                    'cpu_percent': pinfo.get('cpu_percent'),
                    'matched_indicator': indicator,
                    'mitre_technique': 'T1496',
                    'description': f'Cryptocurrency miner detected: {indicator}'
                }
        
        # Check for high CPU usage combined with network connections to mining pools
        if pinfo.get('cpu_percent', 0) > 70:
            connections = pinfo.get('connections', [])
            for conn in connections:
                remote = conn.get('remote_addr', '')
                # Common mining pool ports
                if any(port in str(remote) for port in ['3333', '4444', '5555', '7777', '8888', '9999']):
                    return {
                        'event_type': 'possible_cryptocurrency_miner',
                        'severity': 'high',
                        'timestamp': datetime.now().isoformat(),
                        'pid': pinfo.get('pid'),
                        'process_name': pinfo.get('name'),
                        'exe': pinfo.get('exe'),
                        'cmdline': ' '.join(pinfo.get('cmdline', [])),
                        'username': pinfo.get('username'),
                        'cpu_percent': pinfo.get('cpu_percent'),
                        'remote_connection': remote,
                        'mitre_technique': 'T1496',
                        'description': f'Possible crypto miner: High CPU usage with suspicious network connection'
                    }
        
        return None
    
    def check_reverse_shell(self, pinfo):
        """
        Check for reverse shell indicators
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            list: Events for reverse shell indicators
        """
        if not self.reverse_shell_detection_enabled:
            return []
        
        events = []
        cmdline = ' '.join(pinfo.get('cmdline', [])).lower()
        
        # Reverse shell patterns
        reverse_shell_patterns = [
            r'/dev/tcp/[\d\.]+/\d+',
            r'/dev/udp/[\d\.]+/\d+',
            r'nc.*-e.*/(bash|sh)',
            r'bash.*-i.*>.*&',
            r'python.*socket.*connect',
            r'perl.*socket.*connect',
            r'ruby.*socket.*connect'
        ]
        
        for pattern in reverse_shell_patterns:
            if re.search(pattern, cmdline):
                events.append({
                    'event_type': 'reverse_shell_detected',
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat(),
                    'pid': pinfo.get('pid'),
                    'process_name': pinfo.get('name'),
                    'exe': pinfo.get('exe'),
                    'cmdline': ' '.join(pinfo.get('cmdline', [])),
                    'username': pinfo.get('username'),
                    'matched_pattern': pattern,
                    'mitre_technique': 'T1059.004',
                    'description': f'Reverse shell detected: {pattern}'
                })
        
        return events
    
    def check_privilege_escalation(self, pinfo):
        """
        Check for privilege escalation indicators
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            dict or None: Event if privilege escalation detected
        """
        if not self.privilege_escalation_detection_enabled:
            return None
        
        username = pinfo.get('username', '')
        cmdline = ' '.join(pinfo.get('cmdline', [])).lower()
        process_name = pinfo.get('name', '').lower()
        
        # Check for SUID/SGID executables running from suspicious locations
        exe_path = pinfo.get('exe', '')
        
        if exe_path and os.path.exists(exe_path):
            try:
                stat_info = os.stat(exe_path)
                mode = stat_info.st_mode
                
                # Check for SUID (Set User ID) bit
                if mode & 0o4000:
                    # SUID binary running from suspicious location
                    if any(susp_path in exe_path for susp_path in ['/tmp', '/var/tmp', '/dev/shm']):
                        return {
                            'event_type': 'suspicious_suid_execution',
                            'severity': 'critical',
                            'timestamp': datetime.now().isoformat(),
                            'pid': pinfo.get('pid'),
                            'process_name': pinfo.get('name'),
                            'exe': exe_path,
                            'cmdline': ' '.join(pinfo.get('cmdline', [])),
                            'username': username,
                            'mitre_technique': 'T1548.001',
                            'description': f'SUID binary executing from suspicious location: {exe_path}'
                        }
            except (OSError, PermissionError):
                pass
        
        return None
    
    def check_suspicious_network_connections(self, pinfo):
        """
        Check for suspicious network connections
        
        Args:
            pinfo: Process information dictionary
            
        Returns:
            list: Events for suspicious connections
        """
        if not self.monitor_network_connections:
            return []
        
        events = []
        connections = pinfo.get('connections', [])
        
        for conn in connections:
            remote = conn.get('remote_addr', '')
            if not remote:
                continue
            
            # Extract port
            try:
                remote_port = int(remote.split(':')[1])
            except (IndexError, ValueError):
                continue
            
            # Check for suspicious ports
            if remote_port in self.suspicious_ports:
                events.append({
                    'event_type': 'suspicious_network_connection',
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'pid': pinfo.get('pid'),
                    'process_name': pinfo.get('name'),
                    'exe': pinfo.get('exe'),
                    'cmdline': ' '.join(pinfo.get('cmdline', [])),
                    'username': pinfo.get('username'),
                    'remote_address': remote,
                    'suspicious_port': remote_port,
                    'mitre_technique': 'T1071',
                    'description': f'Connection to suspicious port {remote_port}: {remote}'
                })
        
        return events
    
    def create_baseline(self):
        """
        Create baseline of running processes
        
        Returns:
            dict: Baseline data
        """
        print("[INFO] Creating process baseline...")
        
        baseline_data = {
            'created_at': datetime.now().isoformat(),
            'processes': {}
        }
        
        for proc in psutil.process_iter():
            try:
                pinfo = self.get_process_info(proc)
                if pinfo:
                    baseline_data['processes'][pinfo['name']] = {
                        'count': baseline_data['processes'].get(pinfo['name'], {}).get('count', 0) + 1,
                        'typical_user': pinfo.get('username')
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        self.baseline = baseline_data['processes']
        print(f"[SUCCESS] Process baseline created with {len(self.baseline)} process types")
        
        return baseline_data
    
    def load_baseline(self):
        """
        Load existing process baseline
        
        Returns:
            bool: True if loaded successfully
        """
        try:
            if not os.path.exists(self.baseline_file):
                print("[WARNING] No process baseline found. Creating new baseline...")
                self.create_baseline()
                return True
            
            with open(self.baseline_file, 'r') as f:
                baseline_data = json.load(f)
                self.baseline = baseline_data.get('processes', {})
                print(f"[INFO] Process baseline loaded: {len(self.baseline)} process types")
                return True
        
        except Exception as e:
            print(f"[ERROR] Failed to load process baseline: {e}")
            return False
    
    def monitor(self):
        """
        Monitor running processes and detect anomalies
        
        Returns:
            list: Detected security events
        """
        events = []
        
        print("[INFO] Starting process monitoring...")
        
        # Get all running processes
        process_count = 0
        
        for proc in psutil.process_iter():
            try:
                pinfo = self.get_process_info(proc)
                
                if not pinfo:
                    continue
                
                process_count += 1
                
                # Skip whitelisted processes
                if self.is_whitelisted(pinfo.get('name', '')):
                    continue
                
                # Run all checks
                
                # 1. Suspicious process name
                event = self.check_suspicious_name(pinfo)
                if event:
                    events.append(event)
                
                # 2. Suspicious command
                cmd_events = self.check_suspicious_command(pinfo)
                events.extend(cmd_events)
                
                # 3. Suspicious path
                event = self.check_suspicious_path(pinfo)
                if event:
                    events.append(event)
                
                # 4. High resource usage
                event = self.check_high_resource_usage(pinfo)
                if event:
                    events.append(event)
                
                # 5. Crypto miner detection
                event = self.check_crypto_miner(pinfo)
                if event:
                    events.append(event)
                
                # 6. Reverse shell detection
                shell_events = self.check_reverse_shell(pinfo)
                events.extend(shell_events)
                
                # 7. Privilege escalation
                event = self.check_privilege_escalation(pinfo)
                if event:
                    events.append(event)
                
                # 8. Suspicious network connections
                net_events = self.check_suspicious_network_connections(pinfo)
                events.extend(net_events)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                print(f"[ERROR] Error processing process: {e}")
                continue
        
        print(f"[INFO] Scanned {process_count} processes")
        
        if events:
            print(f"[ALERT] Detected {len(events)} suspicious process events")
        else:
            print("[INFO] No suspicious processes detected")
        
        return events


# Test function
if __name__ == "__main__":
    test_config = {
        'baseline_file': 'data/process_baseline.json',
        'cpu_threshold': 80,
        'memory_threshold': 80,
        'check_crypto_miners': True,
        'check_reverse_shells': True,
        'check_privilege_escalation': True,
        'whitelist_processes': ['systemd', 'sshd'],
        'suspicious_process_names': ['nc', 'netcat', 'xmrig'],
        'suspicious_commands': ['bash -i', '/dev/tcp', 'nc -e'],
        'suspicious_paths': ['/tmp', '/var/tmp'],
        'monitor_network_connections': True,
        'suspicious_ports': [4444, 5555, 31337]
    }
    
    monitor = ProcessMonitor(test_config)
    monitor.load_baseline()
    
    print("\n" + "="*60)
    events = monitor.monitor()
    
    print("\n" + "="*60)
    print("DETECTED EVENTS:")
    print("="*60)
    
    for event in events:
        print(json.dumps(event, indent=2))