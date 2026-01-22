"""
Network Monitor Module for HIDS Agent
Detects port scans, suspicious connections, unusual traffic patterns
MITRE ATT&CK: T1046 (Network Service Discovery), T1071 (Application Layer Protocol),
              T1090 (Proxy), T1041 (Exfiltration), T1219 (Remote Access)
"""

import os
import json
import psutil
import socket
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter


class NetworkMonitor:
    def __init__(self, config):
        """
        Initialize Network Monitor
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.baseline_file = config.get('baseline_file', 'data/network_baseline.json')
        self.monitor_connections = config.get('monitor_connections', True)
        self.monitor_listening_ports = config.get('monitor_listening_ports', True)
        self.detect_port_scans = config.get('detect_port_scans', True)
        self.port_scan_threshold = config.get('port_scan_threshold', 10)
        self.port_scan_window = config.get('port_scan_window', 60)
        self.connection_rate_threshold = config.get('connection_rate_threshold', 50)
        self.connection_rate_window = config.get('connection_rate_window', 60)
        self.data_transfer_threshold = config.get('data_transfer_threshold', 104857600)  # 100MB
        self.suspicious_ports = config.get('suspicious_ports', [])
        self.allowed_outbound_ports = config.get('allowed_outbound_ports', [])
        self.suspicious_ips = config.get('suspicious_ips', [])
        self.whitelist_ips = config.get('whitelist_ips', ['127.0.0.1', '::1'])
        self.tor_monitoring_enabled = config.get('check_tor_connections', True)
        self.proxy_monitoring_enabled = config.get('check_proxy_usage', True)
        self.tunneling_monitoring_enabled = config.get('check_tunneling', True)
        
        # Baseline data
        self.baseline = {}
        
        # Track connection history for port scan detection
        self.connection_history = defaultdict(list)
        
        # Track port access attempts
        self.port_access_history = defaultdict(list)
        
        # Track data transfer
        self.previous_io_counters = {}
        
        # Known Tor exit node ports
        self.tor_ports = [9001, 9030, 9050, 9051, 9150]
        
        # Common proxy ports
        self.proxy_ports = [3128, 8080, 8888, 1080, 3129, 8123]
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
    
    def is_whitelisted_ip(self, ip):
        """
        Check if IP is whitelisted
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if whitelisted
        """
        return ip in self.whitelist_ips
    
    def is_private_ip(self, ip):
        """
        Check if IP is private/local
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if private
        """
        if ip.startswith('127.') or ip == '::1':
            return True
        if ip.startswith('10.'):
            return True
        if ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31:
            return True
        if ip.startswith('192.168.'):
            return True
        if ip.startswith('169.254.'):  # Link-local
            return True
        return False
    
    def get_active_connections(self):
        """
        Get all active network connections
        
        Returns:
            list: List of connection dictionaries
        """
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                
                # Get process name if PID available
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        conn_info['process_name'] = proc.name()
                        conn_info['username'] = proc.username()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        conn_info['process_name'] = 'unknown'
                        conn_info['username'] = 'unknown'
                
                connections.append(conn_info)
        
        except (psutil.AccessDenied, PermissionError):
            print("[WARNING] Permission denied accessing network connections. Run as root.")
        except Exception as e:
            print(f"[ERROR] Error getting network connections: {e}")
        
        return connections
    
    def get_listening_ports(self):
        """
        Get all listening ports
        
        Returns:
            list: List of listening port dictionaries
        """
        listening = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port if conn.laddr else None,
                        'address': conn.laddr.ip if conn.laddr else None,
                        'pid': conn.pid,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Get process info
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            port_info['process_name'] = proc.name()
                            port_info['username'] = proc.username()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            port_info['process_name'] = 'unknown'
                            port_info['username'] = 'unknown'
                    
                    listening.append(port_info)
        
        except (psutil.AccessDenied, PermissionError):
            print("[WARNING] Permission denied accessing listening ports")
        except Exception as e:
            print(f"[ERROR] Error getting listening ports: {e}")
        
        return listening
    
    def check_port_scan(self, connections):
        """
        Detect potential port scanning activity
        
        Args:
            connections: List of current connections
            
        Returns:
            list: Port scan events
        """
        events = []
        
        if not self.detect_port_scans:
            return events
        
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.port_scan_window)
        
        # Track unique destination ports per source IP
        source_port_map = defaultdict(set)
        
        for conn in connections:
            if not conn.get('remote_addr'):
                continue
            
            try:
                remote_ip = conn['remote_addr'].split(':')[0]
                remote_port = int(conn['remote_addr'].split(':')[1])
                
                # Skip private IPs
                if self.is_private_ip(remote_ip):
                    continue
                
                # Track port access
                self.port_access_history[remote_ip].append({
                    'port': remote_port,
                    'time': current_time
                })
                
                # Clean old entries
                self.port_access_history[remote_ip] = [
                    entry for entry in self.port_access_history[remote_ip]
                    if entry['time'] > cutoff_time
                ]
                
                # Count unique ports accessed
                unique_ports = set(entry['port'] for entry in self.port_access_history[remote_ip])
                
                # Check if threshold exceeded
                if len(unique_ports) >= self.port_scan_threshold:
                    events.append({
                        'event_type': 'port_scan_detected',
                        'severity': 'critical',
                        'timestamp': current_time.isoformat(),
                        'source_ip': remote_ip,
                        'unique_ports_accessed': len(unique_ports),
                        'ports': list(unique_ports)[:20],  # Limit to first 20
                        'time_window': self.port_scan_window,
                        'mitre_technique': 'T1046',
                        'description': f'Port scan detected from {remote_ip}: {len(unique_ports)} unique ports in {self.port_scan_window}s'
                    })
                    
                    # Clear history for this IP to avoid duplicate alerts
                    self.port_access_history[remote_ip] = []
            
            except (ValueError, IndexError):
                continue
        
        return events
    
    def check_suspicious_connections(self, connections):
        """
        Check for suspicious network connections
        
        Args:
            connections: List of current connections
            
        Returns:
            list: Suspicious connection events
        """
        events = []
        
        for conn in connections:
            if not conn.get('remote_addr'):
                continue
            
            try:
                remote_ip = conn['remote_addr'].split(':')[0]
                remote_port = int(conn['remote_addr'].split(':')[1])
                local_port = int(conn['local_addr'].split(':')[1]) if conn.get('local_addr') else 0
                
                # Skip whitelisted IPs
                if self.is_whitelisted_ip(remote_ip):
                    continue
                
                # Check for connections to suspicious ports
                if remote_port in self.suspicious_ports:
                    events.append({
                        'event_type': 'connection_to_suspicious_port',
                        'severity': 'high',
                        'timestamp': datetime.now().isoformat(),
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'local_port': local_port,
                        'process_name': conn.get('process_name', 'unknown'),
                        'username': conn.get('username', 'unknown'),
                        'pid': conn.get('pid'),
                        'status': conn.get('status'),
                        'mitre_technique': 'T1071',
                        'description': f'Connection to suspicious port {remote_port} at {remote_ip}'
                    })
                
                # Check for suspicious IPs
                if remote_ip in self.suspicious_ips:
                    events.append({
                        'event_type': 'connection_to_suspicious_ip',
                        'severity': 'critical',
                        'timestamp': datetime.now().isoformat(),
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'local_port': local_port,
                        'process_name': conn.get('process_name', 'unknown'),
                        'pid': conn.get('pid'),
                        'mitre_technique': 'T1071',
                        'description': f'Connection to blacklisted IP: {remote_ip}'
                    })
                
                # Check for outbound connections to non-standard ports
                if conn.get('status') == 'ESTABLISHED':
                    if remote_port not in self.allowed_outbound_ports and not self.is_private_ip(remote_ip):
                        # Only alert for non-common processes
                        process_name = conn.get('process_name', '').lower()
                        if process_name not in ['chrome', 'firefox', 'apt', 'dpkg', 'snap']:
                            events.append({
                                'event_type': 'unusual_outbound_connection',
                                'severity': 'medium',
                                'timestamp': datetime.now().isoformat(),
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'process_name': conn.get('process_name', 'unknown'),
                                'username': conn.get('username', 'unknown'),
                                'pid': conn.get('pid'),
                                'mitre_technique': 'T1071',
                                'description': f'Unusual outbound connection to {remote_ip}:{remote_port} by {process_name}'
                            })
            
            except (ValueError, IndexError):
                continue
        
        return events
    
    def check_tor_connections(self, connections):
        """
        Detect Tor network usage
        
        Args:
            connections: List of current connections
            
        Returns:
            list: Tor connection events
        """
        events = []
        
        if not self.tor_monitoring_enabled:
            return events
        
        for conn in connections:
            if not conn.get('remote_addr'):
                continue
            
            try:
                remote_port = int(conn['remote_addr'].split(':')[1])
                local_port = int(conn['local_addr'].split(':')[1]) if conn.get('local_addr') else 0
                
                # Check for Tor ports
                if remote_port in self.tor_ports or local_port in self.tor_ports:
                    events.append({
                        'event_type': 'tor_connection_detected',
                        'severity': 'high',
                        'timestamp': datetime.now().isoformat(),
                        'remote_addr': conn.get('remote_addr'),
                        'local_port': local_port,
                        'process_name': conn.get('process_name', 'unknown'),
                        'pid': conn.get('pid'),
                        'mitre_technique': 'T1090.003',
                        'description': f'Tor network connection detected on port {remote_port or local_port}'
                    })
            
            except (ValueError, IndexError):
                continue
        
        return events
    
    def check_proxy_connections(self, connections):
        """
        Detect proxy usage
        
        Args:
            connections: List of current connections
            
        Returns:
            list: Proxy connection events
        """
        events = []
        
        if not self.proxy_monitoring_enabled:
            return events
        
        for conn in connections:
            if not conn.get('remote_addr'):
                continue
            
            try:
                remote_port = int(conn['remote_addr'].split(':')[1])
                local_port = int(conn['local_addr'].split(':')[1]) if conn.get('local_addr') else 0
                
                # Check for proxy ports
                if remote_port in self.proxy_ports or local_port in self.proxy_ports:
                    events.append({
                        'event_type': 'proxy_connection_detected',
                        'severity': 'medium',
                        'timestamp': datetime.now().isoformat(),
                        'remote_addr': conn.get('remote_addr'),
                        'local_port': local_port,
                        'proxy_port': remote_port or local_port,
                        'process_name': conn.get('process_name', 'unknown'),
                        'pid': conn.get('pid'),
                        'mitre_technique': 'T1090',
                        'description': f'Proxy connection detected on port {remote_port or local_port}'
                    })
            
            except (ValueError, IndexError):
                continue
        
        return events
    
    def check_new_listening_ports(self, current_listening):
        """
        Detect new listening ports not in baseline
        
        Args:
            current_listening: List of current listening ports
            
        Returns:
            list: New listening port events
        """
        events = []
        
        baseline_ports = set(self.baseline.get('listening_ports', []))
        current_ports = set(port['port'] for port in current_listening if port.get('port'))
        
        new_ports = current_ports - baseline_ports
        
        for port_info in current_listening:
            port = port_info.get('port')
            if port in new_ports:
                # Check if it's a suspicious port
                severity = 'critical' if port in self.suspicious_ports else 'medium'
                
                events.append({
                    'event_type': 'new_listening_port',
                    'severity': severity,
                    'timestamp': datetime.now().isoformat(),
                    'port': port,
                    'address': port_info.get('address'),
                    'process_name': port_info.get('process_name', 'unknown'),
                    'username': port_info.get('username', 'unknown'),
                    'pid': port_info.get('pid'),
                    'mitre_technique': 'T1571',
                    'description': f'New listening port detected: {port} ({port_info.get("process_name", "unknown")})'
                })
        
        return events
    
    def check_high_connection_rate(self, connections):
        """
        Detect unusually high connection rates (potential DDoS or scanning)
        
        Args:
            connections: List of current connections
            
        Returns:
            list: High connection rate events
        """
        events = []
        
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.connection_rate_window)
        
        # Track connections per process
        process_connections = defaultdict(list)
        
        for conn in connections:
            pid = conn.get('pid')
            if pid:
                process_connections[pid].append(current_time)
        
        # Check connection rates
        for pid, timestamps in process_connections.items():
            if len(timestamps) >= self.connection_rate_threshold:
                try:
                    proc = psutil.Process(pid)
                    events.append({
                        'event_type': 'high_connection_rate',
                        'severity': 'high',
                        'timestamp': current_time.isoformat(),
                        'pid': pid,
                        'process_name': proc.name(),
                        'connection_count': len(timestamps),
                        'time_window': self.connection_rate_window,
                        'mitre_technique': 'T1046',
                        'description': f'High connection rate: {len(timestamps)} connections in {self.connection_rate_window}s'
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        return events
    
    def create_baseline(self):
        """
        Create baseline of normal network activity
        
        Returns:
            dict: Baseline data
        """
        print("[INFO] Creating network baseline...")
        
        baseline_data = {
            'created_at': datetime.now().isoformat(),
            'listening_ports': [],
            'common_connections': {}
        }
        
        # Get listening ports
        listening = self.get_listening_ports()
        baseline_data['listening_ports'] = [p['port'] for p in listening if p.get('port')]
        
        # Get active connections
        connections = self.get_active_connections()
        
        # Track common destination IPs and ports
        for conn in connections:
            if conn.get('remote_addr'):
                try:
                    remote_ip = conn['remote_addr'].split(':')[0]
                    remote_port = int(conn['remote_addr'].split(':')[1])
                    
                    if not self.is_private_ip(remote_ip):
                        key = f"{remote_ip}:{remote_port}"
                        baseline_data['common_connections'][key] = {
                            'process': conn.get('process_name', 'unknown'),
                            'count': baseline_data['common_connections'].get(key, {}).get('count', 0) + 1
                        }
                except (ValueError, IndexError):
                    continue
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        self.baseline = baseline_data
        print(f"[SUCCESS] Network baseline created")
        print(f"  - {len(baseline_data['listening_ports'])} listening ports")
        print(f"  - {len(baseline_data['common_connections'])} common connections")
        
        return baseline_data
    
    def load_baseline(self):
        """
        Load existing network baseline
        
        Returns:
            bool: True if loaded successfully
        """
        try:
            if not os.path.exists(self.baseline_file):
                print("[WARNING] No network baseline found. Creating new baseline...")
                self.create_baseline()
                return True
            
            with open(self.baseline_file, 'r') as f:
                baseline_data = json.load(f)
                self.baseline = baseline_data
                print(f"[INFO] Network baseline loaded")
                return True
        
        except Exception as e:
            print(f"[ERROR] Failed to load network baseline: {e}")
            return False
    
    def monitor(self):
        """
        Monitor network activity and detect anomalies
        
        Returns:
            list: Detected security events
        """
        events = []
        
        print("[INFO] Starting network monitoring...")
        
        # Get current network state
        connections = self.get_active_connections()
        listening = self.get_listening_ports()
        
        print(f"[INFO] Active connections: {len(connections)}")
        print(f"[INFO] Listening ports: {len(listening)}")
        
        # Run all checks
        
        # 1. Port scan detection
        port_scan_events = self.check_port_scan(connections)
        events.extend(port_scan_events)
        
        # 2. Suspicious connections
        suspicious_conn_events = self.check_suspicious_connections(connections)
        events.extend(suspicious_conn_events)
        
        # 3. Tor connections
        tor_events = self.check_tor_connections(connections)
        events.extend(tor_events)
        
        # 4. Proxy connections
        proxy_events = self.check_proxy_connections(connections)
        events.extend(proxy_events)
        
        # 5. New listening ports
        if self.monitor_listening_ports:
            new_port_events = self.check_new_listening_ports(listening)
            events.extend(new_port_events)
        
        # 6. High connection rate
        high_rate_events = self.check_high_connection_rate(connections)
        events.extend(high_rate_events)
        
        if events:
            print(f"[ALERT] Detected {len(events)} network security events")
        else:
            print("[INFO] No suspicious network activity detected")
        
        return events


# Test function
if __name__ == "__main__":
    test_config = {
        'baseline_file': 'data/network_baseline.json',
        'monitor_connections': True,
        'monitor_listening_ports': True,
        'detect_port_scans': True,
        'port_scan_threshold': 5,
        'port_scan_window': 60,
        'connection_rate_threshold': 30,
        'suspicious_ports': [4444, 5555, 31337],
        'allowed_outbound_ports': [80, 443, 22, 53],
        'check_tor_connections': True,
        'check_proxy_usage': True
    }
    
    monitor = NetworkMonitor(test_config)
    monitor.load_baseline()
    
    print("\n" + "="*60)
    events = monitor.monitor()
    
    print("\n" + "="*60)
    print("DETECTED EVENTS:")
    print("="*60)
    
    for event in events:
        print(json.dumps(event, indent=2))