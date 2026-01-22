"""
HIDS Agent Main Application
Coordinates all monitoring modules and sends events to server
"""

import json
import time
import schedule
import signal
import sys
from datetime import datetime
from modules.file_monitor import FileIntegrityMonitor
from modules.auth_monitor import AuthenticationMonitor
from modules.process_monitor import ProcessMonitor
from modules.network_monitor import NetworkMonitor
from modules.network_client import NetworkClient


class HIDSAgent:
    def __init__(self, config_file='config.json'):
        """
        Initialize HIDS Agent
        
        Args:
            config_file: Path to configuration file
        """
        self.running = False
        self.config = self.load_config(config_file)
        
        # Initialize modules
        self.file_monitor = None
        self.auth_monitor = None
        self.process_monitor = None
        self.network_monitor = None
        self.network_client = None
        
        self.setup_modules()
        self.setup_signal_handlers()
    
    def load_config(self, config_file):
        """
        Load configuration from JSON file
        
        Args:
            config_file: Path to config file
            
        Returns:
            dict: Configuration dictionary
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                print(f"[INFO] Configuration loaded from {config_file}")
                return config
        except FileNotFoundError:
            print(f"[ERROR] Configuration file not found: {config_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON in config file: {e}")
            sys.exit(1)
    
    def setup_modules(self):
        """
        Initialize all monitoring modules
        """
        print("[INFO] Initializing HIDS Agent modules...")
        
        # Initialize network client
        self.network_client = NetworkClient(self.config['agent'])
        
        # Test server connection
        if not self.network_client.test_connection():
            print("[WARNING] Server is not reachable. Events will be logged locally.")
        
        # Initialize file integrity monitor
        if self.config['file_monitor']['enabled']:
            self.file_monitor = FileIntegrityMonitor(self.config['file_monitor'])
            self.file_monitor.load_baseline()
            print("[INFO] File Integrity Monitor initialized")
        
        # Initialize authentication monitor
        if self.config['auth_monitor']['enabled']:
            self.auth_monitor = AuthenticationMonitor(self.config['auth_monitor'])
            print("[INFO] Authentication Monitor initialized")
        
        # Initialize process monitor
        if self.config['process_monitor']['enabled']:
            self.process_monitor = ProcessMonitor(self.config['process_monitor'])
            self.process_monitor.load_baseline()
            print("[INFO] Process Monitor initialized")
        
        # Initialize network monitor
        if self.config['network_monitor']['enabled']:
            self.network_monitor = NetworkMonitor(self.config['network_monitor'])
            self.network_monitor.load_baseline()
            print("[INFO] Network Monitor initialized")
        
        print("[SUCCESS] All modules initialized")
    
    def setup_signal_handlers(self):
        """
        Setup signal handlers for graceful shutdown
        """
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """
        Handle shutdown signals
        """
        print("\n[INFO] Shutdown signal received. Stopping agent...")
        self.stop()
        sys.exit(0)
    
    def run_file_integrity_check(self):
        """
        Run file integrity monitoring
        """
        print("\n" + "="*60)
        print(f"[INFO] Running File Integrity Check - {datetime.now()}")
        print("="*60)
        
        if self.file_monitor:
            events = self.file_monitor.check_integrity()
            
            if events:
                # Send events to server
                sent_count = self.network_client.send_events(events)
                print(f"[INFO] Sent {sent_count}/{len(events)} events to server")
                
                # Also save events locally
                self.save_events_locally(events)
    
    def run_authentication_monitoring(self):
        """
        Run authentication monitoring
        """
        print("\n" + "="*60)
        print(f"[INFO] Running Authentication Monitoring - {datetime.now()}")
        print("="*60)
        
        if self.auth_monitor:
            events = self.auth_monitor.monitor()
            
            if events:
                # Send events to server
                sent_count = self.network_client.send_events(events)
                print(f"[INFO] Sent {sent_count}/{len(events)} events to server")
                
                # Also save events locally
                self.save_events_locally(events)
    
    def run_process_monitoring(self):
        """
        Run process monitoring
        """
        print("\n" + "="*60)
        print(f"[INFO] Running Process Monitoring - {datetime.now()}")
        print("="*60)
        
        if self.process_monitor:
            events = self.process_monitor.monitor()
            
            if events:
                # Send events to server
                sent_count = self.network_client.send_events(events)
                print(f"[INFO] Sent {sent_count}/{len(events)} events to server")
                
                # Also save events locally
                self.save_events_locally(events)
    
    def run_network_monitoring(self):
        """
        Run network monitoring
        """
        print("\n" + "="*60)
        print(f"[INFO] Running Network Monitoring - {datetime.now()}")
        print("="*60)
        
        if self.network_monitor:
            events = self.network_monitor.monitor()
            
            if events:
                # Send events to server
                sent_count = self.network_client.send_events(events)
                print(f"[INFO] Sent {sent_count}/{len(events)} events to server")
                
                # Also save events locally
                self.save_events_locally(events)
    
    def save_events_locally(self, events):
        """
        Save events to local log file as backup
        
        Args:
            events: List of events to save
        """
        try:
            import os
            os.makedirs('logs', exist_ok=True)
            log_file = 'logs/events.log'
            with open(log_file, 'a') as f:
                for event in events:
                    f.write(json.dumps(event) + '\n')
        except Exception as e:
            print(f"[ERROR] Failed to save events locally: {e}")
    
    def send_startup_event(self):
        """
        Send agent startup event to server
        """
        startup_event = {
            'event_type': 'agent_startup',
            'severity': 'info',
            'timestamp': datetime.now().isoformat(),
            'description': 'HIDS Agent started successfully',
            'modules_enabled': {
                'file_monitor': self.config['file_monitor']['enabled'],
                'auth_monitor': self.config['auth_monitor']['enabled'],
                'process_monitor': self.config['process_monitor']['enabled'],
                'network_monitor': self.config['network_monitor']['enabled']
            }
        }
        self.network_client.send_event(startup_event)
    
    def schedule_tasks(self):
        """
        Schedule periodic monitoring tasks
        """
        scan_interval = self.config['agent'].get('scan_interval', 300)
        
        # Schedule file integrity check
        if self.file_monitor:
            schedule.every(scan_interval).seconds.do(self.run_file_integrity_check)
            print(f"[INFO] Scheduled file integrity check every {scan_interval} seconds")
        
        # Schedule authentication monitoring (more frequent - every 30 seconds)
        if self.auth_monitor:
            schedule.every(30).seconds.do(self.run_authentication_monitoring)
            print(f"[INFO] Scheduled authentication monitoring every 30 seconds")
        
        # Schedule process monitoring (every 2 minutes)
        if self.process_monitor:
            schedule.every(2).minutes.do(self.run_process_monitoring)
            print(f"[INFO] Scheduled process monitoring every 2 minutes")
        
        # Schedule network monitoring (every 1 minute)
        if self.network_monitor:
            schedule.every(1).minutes.do(self.run_network_monitoring)
            print(f"[INFO] Scheduled network monitoring every 1 minute")
        
        # Schedule heartbeat every 5 minutes
        schedule.every(5).minutes.do(self.network_client.send_heartbeat)
        print(f"[INFO] Scheduled heartbeat every 5 minutes")
    
    def start(self):
        """
        Start the HIDS Agent
        """
        print("\n" + "="*60)
        print("  HOST-BASED INTRUSION DETECTION SYSTEM (HIDS) AGENT")
        print("="*60)
        print(f"Agent Name: {self.config['agent']['name']}")
        print(f"Server URL: {self.config['agent']['server_url']}")
        print(f"Modules Enabled:")
        print(f"  - File Integrity Monitor: {self.config['file_monitor']['enabled']}")
        print(f"  - Authentication Monitor: {self.config['auth_monitor']['enabled']}")
        print(f"  - Process Monitor: {self.config['process_monitor']['enabled']}")
        print(f"  - Network Monitor: {self.config['network_monitor']['enabled']}")
        print("="*60 + "\n")
        
        self.running = True
        
        # Send startup event
        self.send_startup_event()
        
        # Run initial checks
        if self.file_monitor:
            self.run_file_integrity_check()
        
        if self.auth_monitor:
            self.run_authentication_monitoring()
        
        if self.process_monitor:
            self.run_process_monitoring()
        
        if self.network_monitor:
            self.run_network_monitoring()
        
        # Schedule periodic tasks
        self.schedule_tasks()
        
        print("\n[INFO] HIDS Agent is running. Press Ctrl+C to stop.\n")
        
        # Main loop
        try:
            while self.running:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """
        Stop the HIDS Agent
        """
        print("\n[INFO] Stopping HIDS Agent...")
        self.running = False
        
        # Send shutdown event
        shutdown_event = {
            'event_type': 'agent_shutdown',
            'severity': 'info',
            'timestamp': datetime.now().isoformat(),
            'description': 'HIDS Agent shutting down'
        }
        self.network_client.send_event(shutdown_event)
        
        print("[SUCCESS] HIDS Agent stopped")


def main():
    """
    Main entry point
    """
    # Check if running as root (needed for some monitoring tasks)
    import os
    if os.geteuid() != 0:
        print("[WARNING] Agent is not running as root. Some monitoring features may not work.")
        print("[WARNING] Run with: sudo python3 main.py")
    
    # Start agent
    agent = HIDSAgent('config.json')
    agent.start()


if __name__ == "__main__":
    main()