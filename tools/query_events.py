"""
HIDS Event Query and Analysis Tool
Query and analyze security events from the server
"""

import requests
import json
import argparse
from datetime import datetime
from collections import Counter


class EventAnalyzer:
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
    
    def fetch_events(self, limit=None, severity=None, event_type=None):
        """Fetch events from server with filters"""
        params = {}
        if limit:
            params['limit'] = limit
        if severity:
            params['severity'] = severity
        
        try:
            response = requests.get(
                f"{self.server_url}/api/events",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('events', [])
                
                # Filter by event type if specified
                if event_type:
                    events = [e for e in events if e.get('event_type') == event_type]
                
                return events
            else:
                print(f"[ERROR] Server returned status {response.status_code}")
                return []
        except Exception as e:
            print(f"[ERROR] Failed to fetch events: {e}")
            return []
    
    def analyze_by_mitre(self, events):
        """Analyze events by MITRE ATT&CK technique"""
        mitre_counts = Counter()
        
        for event in events:
            technique = event.get('mitre_technique', 'Unknown')
            mitre_counts[technique] += 1
        
        print("\n" + "="*60)
        print("MITRE ATT&CK TECHNIQUE DISTRIBUTION")
        print("="*60)
        
        for technique, count in mitre_counts.most_common():
            print(f"{technique:15} : {count:4} events")
    
    def analyze_by_severity(self, events):
        """Analyze events by severity"""
        severity_counts = Counter()
        
        for event in events:
            severity = event.get('severity', 'unknown')
            severity_counts[severity] += 1
        
        print("\n" + "="*60)
        print("SEVERITY DISTRIBUTION")
        print("="*60)
        
        for severity in ['critical', 'high', 'medium', 'info']:
            count = severity_counts.get(severity, 0)
            print(f"{severity.upper():10} : {count:4} events")
    
    def analyze_process_events(self, events):
        """Analyze process-related events"""
        process_events = [e for e in events if 'process' in e.get('event_type', '')]
        
        if not process_events:
            print("\n[INFO] No process-related events found")
            return
        
        print("\n" + "="*60)
        print("PROCESS MONITORING ANALYSIS")
        print("="*60)
        print(f"Total Process Events: {len(process_events)}")
        print()
        
        # Analyze by event type
        event_types = Counter([e.get('event_type') for e in process_events])
        
        print("Process Event Types:")
        for event_type, count in event_types.most_common():
            print(f"  {event_type:35} : {count}")
        
        # Show crypto miner detections
        crypto_events = [e for e in process_events if 'crypto' in e.get('event_type', '')]
        if crypto_events:
            print(f"\n🚨 CRYPTO MINERS DETECTED: {len(crypto_events)}")
            for event in crypto_events:
                print(f"  - {event.get('process_name')} (PID: {event.get('pid')})")
                print(f"    CPU: {event.get('cpu_percent', 'N/A')}%")
        
        # Show reverse shell detections
        shell_events = [e for e in process_events if 'reverse_shell' in e.get('event_type', '')]
        if shell_events:
            print(f"\n🚨 REVERSE SHELLS DETECTED: {len(shell_events)}")
            for event in shell_events:
                print(f"  - {event.get('process_name')} (PID: {event.get('pid')})")
                print(f"    Command: {event.get('cmdline', 'N/A')[:60]}...")
        
        # Show high resource usage
        resource_events = [e for e in process_events if 'high_resource' in e.get('event_type', '')]
        if resource_events:
            print(f"\n⚠️  HIGH RESOURCE USAGE: {len(resource_events)}")
            for event in resource_events:
                print(f"  - {event.get('process_name')} (PID: {event.get('pid')})")
                print(f"    CPU: {event.get('cpu_percent', 0):.1f}% | Memory: {event.get('memory_percent', 0):.1f}%")
    
    def show_event_details(self, events, limit=10):
        """Show detailed information for specific events"""
        print("\n" + "="*60)
        print(f"EVENT DETAILS (Showing {min(limit, len(events))} of {len(events)})")
        print("="*60)
        
        for i, event in enumerate(events[:limit], 1):
            print(f"\n[{i}] {event.get('event_type', 'Unknown').upper()}")
            print(f"    Severity: {event.get('severity', 'N/A')}")
            print(f"    Time: {event.get('timestamp', 'N/A')}")
            print(f"    MITRE: {event.get('mitre_technique', 'N/A')}")
            print(f"    Description: {event.get('description', 'No description')}")
            
            # Show process-specific details
            if event.get('pid'):
                print(f"    PID: {event.get('pid')}")
                print(f"    Process: {event.get('process_name', 'N/A')}")
                print(f"    User: {event.get('username', 'N/A')}")
                if event.get('cmdline'):
                    print(f"    Command: {event.get('cmdline')[:80]}...")
            
            # Show file-specific details
            if event.get('filepath'):
                print(f"    File: {event.get('filepath')}")
                if event.get('old_hash'):
                    print(f"    Old Hash: {event.get('old_hash')[:16]}...")
                if event.get('new_hash'):
                    print(f"    New Hash: {event.get('new_hash')[:16]}...")
            
            # Show auth-specific details
            if event.get('source_ip'):
                print(f"    Source IP: {event.get('source_ip')}")
                if event.get('attempt_count'):
                    print(f"    Attempts: {event.get('attempt_count')}")
    
    def generate_report(self, events):
        """Generate comprehensive security report"""
        print("\n" + "="*70)
        print(" "*20 + "HIDS SECURITY REPORT")
        print("="*70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Events: {len(events)}")
        print("="*70)
        
        # Severity analysis
        self.analyze_by_severity(events)
        
        # MITRE ATT&CK analysis
        self.analyze_by_mitre(events)
        
        # Process analysis
        self.analyze_process_events(events)
        
        # Critical events summary
        critical_events = [e for e in events if e.get('severity') in ['critical', 'high']]
        if critical_events:
            print("\n" + "="*60)
            print("⚠️  CRITICAL & HIGH SEVERITY EVENTS")
            print("="*60)
            self.show_event_details(critical_events, limit=5)
        
        print("\n" + "="*70)
        print("END OF REPORT")
        print("="*70)


def main():
    parser = argparse.ArgumentParser(description='HIDS Event Query and Analysis Tool')
    parser.add_argument('--server', default='http://localhost:5000', help='Server URL')
    parser.add_argument('--limit', type=int, help='Limit number of events')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'info'], help='Filter by severity')
    parser.add_argument('--type', help='Filter by event type')
    parser.add_argument('--report', action='store_true', help='Generate full report')
    parser.add_argument('--process', action='store_true', help='Show only process events')
    parser.add_argument('--mitre', help='Filter by MITRE technique')
    
    args = parser.parse_args()
    
    analyzer = EventAnalyzer(args.server)
    
    print("[INFO] Fetching events from server...")
    events = analyzer.fetch_events(limit=args.limit, severity=args.severity, event_type=args.type)
    
    if not events:
        print("[INFO] No events found matching criteria")
        return
    
    print(f"[INFO] Retrieved {len(events)} events")
    
    # Filter by MITRE if specified
    if args.mitre:
        events = [e for e in events if e.get('mitre_technique') == args.mitre]
        print(f"[INFO] Filtered to {len(events)} events with MITRE technique {args.mitre}")
    
    # Show process events only
    if args.process:
        events = [e for e in events if 'process' in e.get('event_type', '')]
        print(f"[INFO] Filtered to {len(events)} process events")
    
    # Generate report or show details
    if args.report:
        analyzer.generate_report(events)
    else:
        analyzer.show_event_details(events, limit=args.limit or 10)


if __name__ == "__main__":
    main()