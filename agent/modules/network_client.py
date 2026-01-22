"""
Network Client Module for HIDS Agent
Sends security events to the central server
"""

import requests
import json
import socket
from datetime import datetime


class NetworkClient:
    def __init__(self, config):
        """
        Initialize Network Client
        
        Args:
            config: Configuration dictionary with server details
        """
        self.server_url = config.get('server_url', 'http://localhost:5000/api/events')
        self.agent_name = config.get('name', socket.gethostname())
        self.timeout = 10
        
    def get_agent_info(self):
        """
        Get agent system information
        
        Returns:
            dict: Agent information
        """
        return {
            'agent_name': self.agent_name,
            'hostname': socket.gethostname(),
            'ip_address': socket.gethostbyname(socket.gethostname())
        }
    
    def send_event(self, event):
        """
        Send a single event to the server
        
        Args:
            event: Event dictionary
            
        Returns:
            bool: True if successful
        """
        try:
            # Add agent information to event
            event['agent_info'] = self.get_agent_info()
            
            # Send POST request to server
            response = requests.post(
                self.server_url,
                json=event,
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                print(f"[SUCCESS] Event sent to server: {event['event_type']}")
                return True
            else:
                print(f"[ERROR] Server returned status {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Cannot connect to server at {self.server_url}")
            return False
        except requests.exceptions.Timeout:
            print(f"[ERROR] Connection timeout to server")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to send event: {e}")
            return False
    
    def send_events(self, events):
        """
        Send multiple events to the server
        
        Args:
            events: List of event dictionaries
            
        Returns:
            int: Number of successfully sent events
        """
        success_count = 0
        
        for event in events:
            if self.send_event(event):
                success_count += 1
        
        return success_count
    
    def send_heartbeat(self):
        """
        Send heartbeat to server to indicate agent is alive
        
        Returns:
            bool: True if successful
        """
        heartbeat = {
            'event_type': 'agent_heartbeat',
            'severity': 'info',
            'timestamp': datetime.now().isoformat(),
            'agent_info': self.get_agent_info(),
            'description': 'Agent heartbeat'
        }
        
        return self.send_event(heartbeat)
    
    def test_connection(self):
        """
        Test connection to server
        
        Returns:
            bool: True if server is reachable
        """
        try:
            response = requests.get(
                self.server_url.replace('/api/events', '/health'),
                timeout=5
            )
            if response.status_code == 200:
                print(f"[SUCCESS] Server connection OK")
                return True
            else:
                print(f"[WARNING] Server returned status {response.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Server unreachable: {e}")
            return False


# Test function
if __name__ == "__main__":
    test_config = {
        'server_url': 'http://localhost:5000/api/events',
        'name': 'test-agent'
    }
    
    client = NetworkClient(test_config)
    
    # Test connection
    client.test_connection()
    
    # Test event
    test_event = {
        'event_type': 'test_event',
        'severity': 'info',
        'timestamp': datetime.now().isoformat(),
        'description': 'Test event from agent'
    }
    
    client.send_event(test_event)