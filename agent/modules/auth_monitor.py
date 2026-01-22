"""
Authentication Monitor Module for HIDS Agent
Detects brute force attacks, failed logins, and suspicious authentication activities
MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts), T1021.004 (SSH)
"""

import re
import os
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict


class AuthenticationMonitor:
    def __init__(self, config):
        """
        Initialize Authentication Monitor
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.log_files = config.get('log_files', ['/var/log/auth.log'])
        self.position_file = config.get('position_file', 'data/auth_log_position.json')
        self.brute_force_threshold = config.get('brute_force_threshold', 5)
        self.brute_force_window = config.get('brute_force_window', 300)  # 5 minutes
        self.monitor_sudo = config.get('monitor_sudo', True)
        self.monitor_ssh = config.get('monitor_ssh', True)
        self.monitor_user_changes = config.get('monitor_user_changes', True)
        self.suspicious_usernames = config.get('suspicious_usernames', [])
        
        # Track failed login attempts
        self.failed_attempts = defaultdict(list)
        
        # Track log file positions
        self.log_positions = {}
        self.load_positions()
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.position_file), exist_ok=True)
        
        # Regex patterns for log parsing
        self.patterns = self._compile_patterns()
    
    def _compile_patterns(self):
        """
        Compile regex patterns for log parsing
        
        Returns:
            dict: Compiled regex patterns
        """
        return {
            # SSH Failed Password
            'ssh_failed_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[(\d+)\]:\s+Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)'
            ),
            
            # SSH Accepted Password
            'ssh_accepted': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[(\d+)\]:\s+Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port (\d+)'
            ),
            
            # SSH Connection Closed
            'ssh_connection_closed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[(\d+)\]:\s+Connection closed by (?:authenticating user )?(\S+)?\s*([\d\.]+)'
            ),
            
            # Sudo Command
            'sudo_command': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)'
            ),
            
            # Sudo Authentication Failure
            'sudo_auth_failure': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo:\s+(\S+)\s+:\s+(\d+) incorrect password attempt'
            ),
            
            # User Added
            'user_added': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*useradd\[(\d+)\]:\s+new user:\s+name=(\S+)'
            ),
            
            # User Deleted
            'user_deleted': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*userdel\[(\d+)\]:\s+delete user\s+\'(\S+)\''
            ),
            
            # Password Changed
            'password_changed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*passwd\[(\d+)\]:\s+password changed for (\S+)'
            ),
            
            # Invalid User
            'invalid_user': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[(\d+)\]:\s+Invalid user (\S+) from ([\d\.]+)'
            ),
            
            # Authentication failure (general)
            'auth_failure': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*authentication failure.*user=(\S+)'
            ),
            
            # Session opened
            'session_opened': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*systemd-logind\[(\d+)\]:\s+New session (\S+) of user (\S+)'
            ),
            
            # Session closed
            'session_closed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*systemd-logind\[(\d+)\]:\s+Removed session (\S+)'
            )
        }
    
    def parse_timestamp(self, timestamp_str):
        """
        Parse log timestamp to datetime object
        
        Args:
            timestamp_str: Timestamp string from log
            
        Returns:
            datetime: Parsed datetime object
        """
        try:
            # Add current year since auth.log doesn't include it
            current_year = datetime.now().year
            full_timestamp = f"{current_year} {timestamp_str}"
            return datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
        except Exception as e:
            print(f"[ERROR] Failed to parse timestamp '{timestamp_str}': {e}")
            return datetime.now()
    
    def load_positions(self):
        """
        Load last read positions for log files
        """
        try:
            if os.path.exists(self.position_file):
                with open(self.position_file, 'r') as f:
                    self.log_positions = json.load(f)
                print(f"[INFO] Loaded log positions from {self.position_file}")
        except Exception as e:
            print(f"[WARNING] Could not load log positions: {e}")
            self.log_positions = {}
    
    def save_positions(self):
        """
        Save current log file positions
        """
        try:
            with open(self.position_file, 'w') as f:
                json.dump(self.log_positions, f, indent=2)
        except Exception as e:
            print(f"[ERROR] Failed to save log positions: {e}")
    
    def read_log_file(self, log_file):
        """
        Read new lines from log file since last position
        
        Args:
            log_file: Path to log file
            
        Returns:
            list: New log lines
        """
        new_lines = []
        
        try:
            if not os.path.exists(log_file):
                return new_lines
            
            # Get file size
            current_size = os.path.getsize(log_file)
            
            # Get last known position
            last_position = self.log_positions.get(log_file, 0)
            
            # If file was rotated (smaller than last position), start from beginning
            if current_size < last_position:
                print(f"[INFO] Log file {log_file} was rotated, starting from beginning")
                last_position = 0
            
            # Read new lines
            with open(log_file, 'r', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                
                # Update position
                self.log_positions[log_file] = f.tell()
            
            return new_lines
            
        except PermissionError:
            print(f"[ERROR] Permission denied reading {log_file}")
            return []
        except Exception as e:
            print(f"[ERROR] Error reading log file {log_file}: {e}")
            return []
    
    def check_brute_force(self, username, ip_address, timestamp):
        """
        Check if failed login attempts indicate brute force attack
        
        Args:
            username: Username attempted
            ip_address: Source IP address
            timestamp: Timestamp of attempt
            
        Returns:
            dict or None: Brute force event if detected
        """
        key = f"{username}@{ip_address}"
        
        # Add current attempt
        self.failed_attempts[key].append(timestamp)
        
        # Remove old attempts outside the time window
        cutoff_time = timestamp - timedelta(seconds=self.brute_force_window)
        self.failed_attempts[key] = [
            t for t in self.failed_attempts[key] if t > cutoff_time
        ]
        
        # Check if threshold exceeded
        attempt_count = len(self.failed_attempts[key])
        
        if attempt_count >= self.brute_force_threshold:
            return {
                'event_type': 'brute_force_attack',
                'severity': 'critical',
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'source_ip': ip_address,
                'attempt_count': attempt_count,
                'time_window': self.brute_force_window,
                'mitre_technique': 'T1110',
                'description': f'Brute force attack detected: {attempt_count} failed login attempts for user {username} from {ip_address} in {self.brute_force_window} seconds'
            }
        
        return None
    
    def is_suspicious_username(self, username):
        """
        Check if username is in suspicious list
        
        Args:
            username: Username to check
            
        Returns:
            bool: True if suspicious
        """
        return username.lower() in [u.lower() for u in self.suspicious_usernames]
    
    def parse_log_line(self, line):
        """
        Parse a single log line and extract security events
        
        Args:
            line: Log line to parse
            
        Returns:
            list: Security events detected in this line
        """
        events = []
        
        # SSH Failed Password
        if self.monitor_ssh:
            match = self.patterns['ssh_failed_password'].search(line)
            if match:
                timestamp_str, pid, username, ip, port = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'ssh_failed_login',
                    'severity': 'medium',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'source_ip': ip,
                    'source_port': port,
                    'pid': pid,
                    'mitre_technique': 'T1110',
                    'description': f'SSH failed login attempt for user {username} from {ip}'
                }
                events.append(event)
                
                # Check for brute force
                brute_force_event = self.check_brute_force(username, ip, timestamp)
                if brute_force_event:
                    events.append(brute_force_event)
                
                # Check for suspicious username
                if self.is_suspicious_username(username):
                    events.append({
                        'event_type': 'suspicious_username_attempt',
                        'severity': 'high',
                        'timestamp': timestamp.isoformat(),
                        'username': username,
                        'source_ip': ip,
                        'mitre_technique': 'T1078',
                        'description': f'Login attempt with suspicious username: {username} from {ip}'
                    })
        
        # SSH Accepted Login
        if self.monitor_ssh:
            match = self.patterns['ssh_accepted'].search(line)
            if match:
                timestamp_str, pid, username, ip, port = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'ssh_successful_login',
                    'severity': 'info',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'source_ip': ip,
                    'source_port': port,
                    'pid': pid,
                    'mitre_technique': 'T1021.004',
                    'description': f'SSH successful login for user {username} from {ip}'
                }
                events.append(event)
        
        # Invalid User
        if self.monitor_ssh:
            match = self.patterns['invalid_user'].search(line)
            if match:
                timestamp_str, pid, username, ip = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'invalid_user_attempt',
                    'severity': 'high',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'source_ip': ip,
                    'pid': pid,
                    'mitre_technique': 'T1110',
                    'description': f'SSH login attempt with invalid user {username} from {ip}'
                }
                events.append(event)
        
        # Sudo Command Execution
        if self.monitor_sudo:
            match = self.patterns['sudo_command'].search(line)
            if match:
                timestamp_str, username, tty, pwd, target_user, command = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'sudo_command_executed',
                    'severity': 'info',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'target_user': target_user,
                    'command': command,
                    'tty': tty,
                    'working_directory': pwd,
                    'mitre_technique': 'T1548.003',
                    'description': f'User {username} executed sudo command as {target_user}: {command}'
                }
                events.append(event)
        
        # Sudo Authentication Failure
        if self.monitor_sudo:
            match = self.patterns['sudo_auth_failure'].search(line)
            if match:
                timestamp_str, username, attempts = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'sudo_auth_failure',
                    'severity': 'high',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'attempt_count': attempts,
                    'mitre_technique': 'T1110',
                    'description': f'Sudo authentication failure for user {username} ({attempts} attempts)'
                }
                events.append(event)
        
        # User Added
        if self.monitor_user_changes:
            match = self.patterns['user_added'].search(line)
            if match:
                timestamp_str, pid, username = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'user_account_created',
                    'severity': 'high',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'pid': pid,
                    'mitre_technique': 'T1136.001',
                    'description': f'New user account created: {username}'
                }
                events.append(event)
        
        # User Deleted
        if self.monitor_user_changes:
            match = self.patterns['user_deleted'].search(line)
            if match:
                timestamp_str, pid, username = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'user_account_deleted',
                    'severity': 'high',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'pid': pid,
                    'mitre_technique': 'T1531',
                    'description': f'User account deleted: {username}'
                }
                events.append(event)
        
        # Password Changed
        if self.monitor_user_changes:
            match = self.patterns['password_changed'].search(line)
            if match:
                timestamp_str, pid, username = match.groups()
                timestamp = self.parse_timestamp(timestamp_str)
                
                event = {
                    'event_type': 'password_changed',
                    'severity': 'medium',
                    'timestamp': timestamp.isoformat(),
                    'username': username,
                    'pid': pid,
                    'mitre_technique': 'T1098',
                    'description': f'Password changed for user: {username}'
                }
                events.append(event)
        
        return events
    
    def monitor(self):
        """
        Monitor authentication logs and detect security events
        
        Returns:
            list: Detected security events
        """
        all_events = []
        
        print("[INFO] Starting authentication monitoring...")
        
        for log_file in self.log_files:
            if not os.path.exists(log_file):
                print(f"[WARNING] Log file not found: {log_file}")
                continue
            
            print(f"[INFO] Reading log file: {log_file}")
            
            # Read new lines
            new_lines = self.read_log_file(log_file)
            
            if not new_lines:
                print(f"[INFO] No new entries in {log_file}")
                continue
            
            print(f"[INFO] Processing {len(new_lines)} new log entries")
            
            # Parse each line
            for line in new_lines:
                events = self.parse_log_line(line)
                all_events.extend(events)
        
        # Save updated positions
        self.save_positions()
        
        if all_events:
            print(f"[ALERT] Detected {len(all_events)} authentication events")
        else:
            print("[INFO] No authentication events detected")
        
        return all_events


# Test function
if __name__ == "__main__":
    test_config = {
        'log_files': ['/var/log/auth.log'],
        'position_file': 'data/auth_log_position.json',
        'brute_force_threshold': 3,
        'brute_force_window': 300,
        'monitor_sudo': True,
        'monitor_ssh': True,
        'monitor_user_changes': True,
        'suspicious_usernames': ['admin', 'root', 'test']
    }
    
    monitor = AuthenticationMonitor(test_config)
    events = monitor.monitor()
    
    print("\n" + "="*60)
    print("DETECTED EVENTS:")
    print("="*60)
    
    for event in events:
        print(json.dumps(event, indent=2))