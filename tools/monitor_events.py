"""
Real-time Event Monitor - Display HIDS events in terminal
"""

import requests
import time
import json
from datetime import datetime
from collections import Counter


class EventMonitor:
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
        self.last_event_count = 0
        
        # Color codes
        self.COLORS = {
            'critical': '\033[91m',  # Red
            'high': '\033[93m',      # Yellow
            'medium': '\033[94m',    # Blue
            'info': '\033[92m',      # Green
            'reset': '\033[0m'
        }
    
    def get_color(self, severity):
        """Get color code for severity level"""
        return self.COLORS.get(severity.lower(), self.COLORS['reset'])
    
    def fetch_events(self):
        """Fetch latest events from server"""
        try:
            response = requests.get(f"{self.server_url}/api/events?limit=100", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('events', [])
        except Exception as e:
            print(f"[ERROR] Failed to fetch events: {e}")
        return []
    
    def fetch_stats(self):
        """Fetch statistics from server"""
        try:
            response = requests.get(f"{self.server_url}/api/stats", timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"[ERROR] Failed to fetch stats: {e}")
        return {}
    
    def clear_screen(self):
        """Clear terminal screen"""
        print("\033[2J\033[H", end='')
    
    def display_header(self):
        """Display dashboard header"""
        print("=" * 80)
        print(" " * 20 + "HIDS REAL-TIME EVENT MONITOR")
        print("=" * 80)
        print(f"Server: {self.server_url} | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()
    
    def display_stats(self, stats):
        """Display event statistics"""
        print("📊 EVENT STATISTICS")
        print("-" * 80)
        print(f"Total Events: {stats.get('total_events', 0)}")
        print()
        
        # Severity breakdown
        print("By Severity:")
        by_severity = stats.get('by_severity', {})
        for severity in ['critical', 'high', 'medium', 'info']:
            count = by_severity.get(severity, 0)
            color = self.get_color(severity)
            bar = "█" * min(count, 50)
            print(f"  {color}{severity.upper():10}{self.COLORS['reset']}: {count:4} {bar}")
        print()
        
        # Event type breakdown
        print("By Event Type:")
        by_type = stats.get('by_type', {})
        sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]
        for event_type, count in sorted_types:
            bar = "▪" * min(count, 40)
            print(f"  {event_type:30}: {count:4} {bar}")
        print()
        
        # Agent breakdown
        print("By Agent:")
        by_agent = stats.get('by_agent', {})
        for agent, count in by_agent.items():
            print(f"  {agent:30}: {count:4}")
        print()
    
    def display_recent_events(self, events, limit=10):
        """Display most recent events"""
        print("🚨 RECENT EVENTS")
        print("-" * 80)
        
        if not events:
            print("No events detected yet.")
            return
        
        # Show most recent events
        recent = events[-limit:][::-1]
        
        for i, event in enumerate(recent, 1):
            severity = event.get('severity', 'info')
            color = self.get_color(severity)
            
            timestamp = event.get('timestamp', 'N/A')
            event_type = event.get('event_type', 'unknown')
            description = event.get('description', 'No description')
            agent = event.get('agent_info', {}).get('agent_name', 'unknown')
            mitre = event.get('mitre_technique', 'N/A')
            
            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime('%H:%M:%S')
            except:
                time_str = timestamp[:8] if len(timestamp) > 8 else timestamp
            
            print(f"{color}[{severity.upper():8}]{self.COLORS['reset']} " + 
                  f"{time_str} | {agent:15} | {event_type:25}")
            print(f"           MITRE: {mitre:10} | {description[:60]}")
            print()
    
    def display_alerts(self, events):
        """Display critical and high severity alerts"""
        critical_events = [e for e in events if e.get('severity') in ['critical', 'high']]
        
        if not critical_events:
            return
        
        print("⚠️  ACTIVE ALERTS")
        print("-" * 80)
        
        # Group by type
        alert_counts = Counter([e.get('event_type') for e in critical_events])
        
        for event_type, count in alert_counts.most_common():
            severity = 'critical' if any(e.get('severity') == 'critical' 
                                        for e in critical_events 
                                        if e.get('event_type') == event_type) else 'high'
            color = self.get_color(severity)
            print(f"{color}  • {event_type:30} ({count} occurrence{'s' if count > 1 else ''}){self.COLORS['reset']}")
        print()
    
    def run(self, refresh_interval=5):
        """Run the monitoring dashboard"""
        print("Starting HIDS Event Monitor...")
        print(f"Refresh interval: {refresh_interval} seconds")
        print("Press Ctrl+C to exit")
        time.sleep(2)
        
        try:
            while True:
                self.clear_screen()
                
                # Fetch data
                events = self.fetch_events()
                stats = self.fetch_stats()
                
                # Display dashboard
                self.display_header()
                self.display_stats(stats)
                self.display_alerts(events)
                self.display_recent_events(events, limit=8)
                
                print("-" * 80)
                print(f"Auto-refresh in {refresh_interval}s | Press Ctrl+C to exit")
                
                # Check for new events
                current_count = len(events)
                if current_count > self.last_event_count:
                    new_events = current_count - self.last_event_count
                    print(f"\n🔔 {new_events} new event(s) detected!")
                self.last_event_count = current_count
                
                time.sleep(refresh_interval)
                
        except KeyboardInterrupt:
            print("\n\n[INFO] Monitor stopped by user")


def main():
    import sys
    
    server_url = 'http://localhost:5000'
    refresh = 5
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    if len(sys.argv) > 2:
        refresh = int(sys.argv[2])
    
    monitor = EventMonitor(server_url)
    monitor.run(refresh_interval=refresh)


if __name__ == "__main__":
    main()