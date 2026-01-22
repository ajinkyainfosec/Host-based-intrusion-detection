"""
HIDS Server - Basic API to receive events from agents
"""

from flask import Flask, request, jsonify
from datetime import datetime
import json
import os


app = Flask(__name__)

# Create logs directory
os.makedirs('logs', exist_ok=True)
os.makedirs('database', exist_ok=True)

# Simple in-memory storage (will be replaced with database later)
events_storage = []


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'server': 'HIDS Server v1.0'
    }), 200


@app.route('/api/events', methods=['POST'])
def receive_event():
    """
    Receive security events from agents
    """
    try:
        event = request.get_json()
        
        if not event:
            return jsonify({'error': 'No event data provided'}), 400
        
        # Add server processing timestamp
        event['server_received_at'] = datetime.now().isoformat()
        
        # Store event
        events_storage.append(event)
        
        # Log event to file
        log_event(event)
        
        # Print event info
        agent_name = event.get('agent_info', {}).get('agent_name', 'unknown')
        event_type = event.get('event_type', 'unknown')
        severity = event.get('severity', 'unknown')
        
        print(f"[EVENT RECEIVED] Agent: {agent_name} | Type: {event_type} | Severity: {severity}")
        
        # Check severity and trigger alerts
        if severity in ['high', 'critical']:
            print(f"[ALERT] {event.get('description', 'No description')}")
        
        return jsonify({
            'status': 'success',
            'message': 'Event received',
            'event_id': len(events_storage)
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to process event: {e}")
        return jsonify({'error': str(e)}), 500


def log_event(event):
    """
    Log event to file
    """
    try:
        log_file = 'logs/server_events.log'
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        print(f"[ERROR] Failed to log event: {e}")


@app.route('/api/events', methods=['GET'])
def get_events():
    """
    Retrieve stored events (for testing)
    """
    # Get query parameters
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity', None)
    agent = request.args.get('agent', None)
    
    # Filter events
    filtered_events = events_storage
    
    if severity:
        filtered_events = [e for e in filtered_events if e.get('severity') == severity]
    
    if agent:
        filtered_events = [e for e in filtered_events 
                          if e.get('agent_info', {}).get('agent_name') == agent]
    
    # Return limited results
    return jsonify({
        'total': len(filtered_events),
        'events': filtered_events[-limit:]
    }), 200


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Get statistics about received events
    """
    stats = {
        'total_events': len(events_storage),
        'by_severity': {},
        'by_type': {},
        'by_agent': {}
    }
    
    for event in events_storage:
        # Count by severity
        severity = event.get('severity', 'unknown')
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        
        # Count by type
        event_type = event.get('event_type', 'unknown')
        stats['by_type'][event_type] = stats['by_type'].get(event_type, 0) + 1
        
        # Count by agent
        agent = event.get('agent_info', {}).get('agent_name', 'unknown')
        stats['by_agent'][agent] = stats['by_agent'].get(agent, 0) + 1
    
    return jsonify(stats), 200


def print_banner():
    """
    Print server banner
    """
    print("\n" + "="*60)
    print("  HOST-BASED INTRUSION DETECTION SYSTEM (HIDS) SERVER")
    print("="*60)
    print("  Status: Running")
    print("  Port: 5000")
    print("  Endpoints:")
    print("    - GET  /health           (Health check)")
    print("    - POST /api/events       (Receive events)")
    print("    - GET  /api/events       (Query events)")
    print("    - GET  /api/stats        (Statistics)")
    print("="*60 + "\n")


if __name__ == '__main__':
    print_banner()
    app.run(host='0.0.0.0', port=5000, debug=True)