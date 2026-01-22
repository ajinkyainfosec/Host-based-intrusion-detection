"""
Network Event Analysis Tool
Analyze network-related security events from HIDS
"""

import requests
import json
import argparse
from collections import Counter, defaultdict
from datetime import datetime


class NetworkAnalyzer:
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
    
    def fetch_network_events(self, limit=None):
        """Fetch network-related events"""
        try:
            params = {'limit': limit} if limit else {}
            response = requests.get(
                f"{self.server_url}/api/events",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('events', [])
                
                # Filter for network events
                network_events = [
                    e for e in events 
                    if 'network' in e.get('event_type', '').lower() or
                       'connection' in e.get('event_type', '').lower() or
                       'port' in e.get('event_type', '').lower()
                ]
                
                return network_events
        except Exception as e:
            print(f"[ERROR] Failed to fetch events: {e}")
        
        return []
    
    def analyze_port_scans(self, events):
        """Analyze port scan events"""
        scans = [e for e in events if e.get('event_type') == 'port_scan_detected']
        
        if not scans:
            print("\n[INFO] No port scans detected")
            return
        
        print("\n" + "="*70)
        print("🚨 PORT SCAN ANALYSIS")
        print("="*70)
        print(f"Total Port Scans Detected: {len(scans)}\n")
        
        # Group by source IP
        by_source = defaultdict(list)
        for scan in scans:
            source = scan.get('source_ip', 'unknown')
            by_source[source].append(scan)
        
        print("Port Scans by Source IP:")
        for source, scan_events in by_source.items():
            total_ports = sum(e.get('unique_ports_accessed', 0) for e in scan_events)
            print(f"\n  Source: {source}")
            print(f"  Scan Attempts: {len(scan_events)}")
            print(f"  Total Unique Ports: {total_ports}")
            
            # Show sample ports
            if scan_events:
                sample_ports = scan_events[0].get('ports', [])[:10]
                print(f"  Sample Ports: {sample_ports}")
    
    def analyze_suspicious_connections(self, events):
        """Analyze suspicious connection events"""
        suspicious = [
            e for e in events 
            if 'suspicious' in e.get('event_type', '') or
               e.get('event_type') in ['connection_to_suspicious_port', 'connection_to_suspicious_ip']
        ]
        
        if not suspicious:
            print("\n[INFO] No suspicious connections detected")
            return
        
        print("\n" + "="*70)
        print("⚠️  SUSPICIOUS CONNECTION ANALYSIS")
        print("="*70)
        print(f"Total Suspicious Connections: {len(suspicious)}\n")
        
        # By port
        by_port = Counter()
        for conn in suspicious:
            port = conn.get('remote_port')
            if port:
                by_port[port] += 1
        
        print("Connections by Suspicious Port:")
        for port, count in by_port.most_common(10):
            print(f"  Port {port:5} : {count:3} connections")
        
        # By process
        by_process = Counter()
        for conn in suspicious:
            process = conn.get('process_name', 'unknown')
            by_process[process] += 1
        
        print("\nConnections by Process:")
        for process, count in by_process.most_common(10):
            print(f"  {process:20} : {count:3} connections")
    
    def analyze_new_listeners(self, events):
        """Analyze new listening port events"""
        listeners = [e for e in events if e.get('event_type') == 'new_listening_port']
        
        if not listeners:
            print("\n[INFO] No new listening ports detected")
            return
        
        print("\n" + "="*70)
        print("📡 NEW LISTENING PORT ANALYSIS")
        print("="*70)
        print(f"Total New Listeners: {len(listeners)}\n")
        
        for listener in listeners:
            port = listener.get('port')
            process = listener.get('process_name', 'unknown')
            user = listener.get('username', 'unknown')
            severity = listener.get('severity', 'unknown')
            
            print(f"  Port {port:5} | {process:15} | User: {user:10} | Severity: {severity}")
    
    def analyze_tor_proxy(self, events):
        """Analyze Tor and Proxy connections"""
        tor_events = [e for e in events if 'tor' in e.get('event_type', '').lower()]
        proxy_events = [e for e in events if 'proxy' in e.get('event_type', '').lower()]
        
        if not tor_events and not proxy_events:
            print("\n[INFO] No Tor/Proxy activity detected")
            return
        
        print("\n" + "="*70)
        print("🔒 TOR & PROXY ACTIVITY ANALYSIS")
        print("="*70)
        
        if tor_events:
            print(f"\n🧅 Tor Connections: {len(tor_events)}")
            for event in tor_events[:5]:
                print(f"  Process: {event.get('process_name', 'unknown')}")
                print(f"  Remote: {event.get('remote_addr', 'N/A')}")
                print(f"  Time: {event.get('timestamp', 'N/A')[:19]}")
                print()
        
        if proxy_events:
            print(f"🌐 Proxy Connections: {len(proxy_events)}")
            for event in proxy_events[:5]:
                print(f"  Port: {event.get('proxy_port', 'unknown')}")
                print(f"  Process: {event.get('process_name', 'unknown')}")
                print(f"  Time: {event.get('timestamp', 'N/A')[:19]}")
                print()
    
    def analyze_connection_rates(self, events):
        """Analyze high connection rate events"""
        high_rate = [e for e in events if e.get('event_type') == 'high_connection_rate']
        
        if not high_rate:
            print("\n[INFO] No high connection rates detected")
            return
        
        print("\n" + "="*70)
        print("📊 HIGH CONNECTION RATE ANALYSIS")
        print("="*70)
        print(f"Total High Rate Events: {len(high_rate)}\n")
        
        for event in high_rate:
            process = event.get('process_name', 'unknown')
            count = event.get('connection_count', 0)
            window = event.get('time_window', 0)
            
            print(f"  Process: {process}")
            print(f"  Connections: {count} in {window}s")
            print(f"  Rate: {count/window:.2f} connections/sec")
            print()
    
    def generate_network_report(self, events):
        """Generate comprehensive network security report"""
        print("\n" + "="*70)
        print(" "*20 + "NETWORK SECURITY REPORT")
        print("="*70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Network Events: {len(events)}")
        print("="*70)
        
        # Event type distribution
        event_types = Counter([e.get('event_type') for e in events])
        
        print("\nEvent Type Distribution:")
        for event_type, count in event_types.most_common():
            print(f"  {event_type:35} : {count:3}")
        
        # Severity distribution
        severity_counts = Counter([e.get('severity') for e in events])
        
        print("\nSeverity Distribution:")
        for severity in ['critical', 'high', 'medium', 'info']:
            count = severity_counts.get(severity, 0)
            print(f"  {severity.upper():10} : {count:3}")
        
        # Run detailed analyses
        self.analyze_port_scans(events)
        self.analyze_suspicious_connections(events)
        self.analyze_new_listeners(events)
        self.analyze_tor_proxy(events)
        self.analyze_connection_rates(events)
        
        # Top remote IPs
        remote_ips = Counter()
        for event in events:
            if event.get('remote_ip'):
                remote_ips[event['remote_ip']] += 1
            elif event.get('source_ip'):
                remote_ips[event['source_ip']] += 1
        
        if remote_ips:
            print("\n" + "="*70)
            print("🌍 TOP REMOTE IP ADDRESSES")
            print("="*70)
            for ip, count in remote_ips.most_common(10):
                print(f"  {ip:20} : {count:3} events")
        
        # MITRE ATT&CK techniques
        mitre_techniques = Counter([e.get('mitre_technique') for e in events if e.get('mitre_technique')])
        
        if mitre_techniques:
            print("\n" + "="*70)
            print("🎯 MITRE ATT&CK TECHNIQUES")
            print("="*70)
            for technique, count in mitre_techniques.most_common():
                print(f"  {technique:15} : {count:3} detections")
        
        print("\n" + "="*70)
        print("END OF NETWORK REPORT")
        print("="*70)
    
    def show_timeline(self, events, hours=24):
        """Show timeline of network events"""
        print("\n" + "="*70)
        print(f"📅 NETWORK EVENT TIMELINE (Last {hours} hours)")
        print("="*70)
        
        # Group by hour
        by_hour = defaultdict(list)
        
        for event in events:
            try:
                timestamp = event.get('timestamp', '')
                dt = datetime.fromisoformat(timestamp)
                hour_key = dt.strftime('%Y-%m-%d %H:00')
                by_hour[hour_key].append(event)
            except:
                continue
        
        # Sort and display
        for hour in sorted(by_hour.keys(), reverse=True)[:hours]:
            events_in_hour = by_hour[hour]
            event_types = Counter([e.get('event_type') for e in events_in_hour])
            
            print(f"\n{hour}")
            print(f"  Total Events: {len(events_in_hour)}")
            for event_type, count in event_types.most_common(5):
                print(f"    • {event_type:30} : {count}")


def main():
    parser = argparse.ArgumentParser(description='HIDS Network Event Analysis Tool')
    parser.add_argument('--server', default='http://localhost:5000', help='Server URL')
    parser.add_argument('--limit', type=int, help='Limit number of events')
    parser.add_argument('--report', action='store_true', help='Generate full report')
    parser.add_argument('--timeline', action='store_true', help='Show event timeline')
    parser.add_argument('--port-scans', action='store_true', help='Show only port scans')
    parser.add_argument('--suspicious', action='store_true', help='Show suspicious connections')
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer(args.server)
    
    print("[INFO] Fetching network events from server...")
    events = analyzer.fetch_network_events(limit=args.limit)
    
    if not events:
        print("[INFO] No network events found")
        return
    
    print(f"[INFO] Retrieved {len(events)} network events")
    
    if args.report:
        analyzer.generate_network_report(events)
    elif args.timeline:
        analyzer.show_timeline(events)
    elif args.port_scans:
        analyzer.analyze_port_scans(events)
    elif args.suspicious:
        analyzer.analyze_suspicious_connections(events)
    else:
        # Default: show summary
        analyzer.generate_network_report(events)


if __name__ == "__main__":
    main()