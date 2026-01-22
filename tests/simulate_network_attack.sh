#!/bin/bash

###############################################################################
# HIDS Network Monitoring Test Script
# Simulates network-based attacks and suspicious activities
# WARNING: Run this only in a test environment
###############################################################################

echo "=========================================="
echo "HIDS Network Attack Simulation"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[ERROR]${NC} Please run as root (sudo)"
    exit 1
fi

echo -e "${YELLOW}[INFO]${NC} Starting network attack simulations..."
echo ""

###############################################################################
# Test 1: Port Scan Simulation
###############################################################################
echo -e "${GREEN}[TEST 1]${NC} Port Scan Simulation"
echo "Scanning localhost ports..."

if command -v nmap &> /dev/null; then
    # Use nmap if available
    nmap -p 1-100 localhost > /dev/null 2>&1 &
    NMAP_PID=$!
    echo -e "${GREEN}[SUCCESS]${NC} Port scan started with nmap (PID: $NMAP_PID)"
else
    # Fallback: Manual port scan using nc
    echo "Using netcat for port scanning..."
    for port in {20..35}; do
        timeout 0.5 nc -zv localhost $port 2>&1 | grep -q "succeeded" && echo "Port $port open"
    done &
    echo -e "${GREEN}[SUCCESS]${NC} Port scan started with netcat"
fi

echo ""
sleep 3

###############################################################################
# Test 2: Connection to Suspicious Port (4444)
###############################################################################
echo -e "${GREEN}[TEST 2]${NC} Connection to Suspicious Port"
echo "Attempting connection to port 4444..."

if command -v nc &> /dev/null; then
    # Start listener on suspicious port
    timeout 20 nc -l -p 4444 &
    NC_LISTENER=$!
    
    sleep 2
    
    # Connect to it
    echo "test" | timeout 2 nc localhost 4444 &
    
    echo -e "${GREEN}[SUCCESS]${NC} Suspicious port connection (4444) established"
else
    echo -e "${YELLOW}[SKIP]${NC} Netcat not available"
fi

echo ""
sleep 2

###############################################################################
# Test 3: Multiple Rapid Connections (High Connection Rate)
###############################################################################
echo -e "${GREEN}[TEST 3]${NC} High Connection Rate Simulation"
echo "Creating rapid connections..."

# Create multiple connections to localhost SSH
for i in {1..15}; do
    timeout 1 nc -w 1 localhost 22 2>/dev/null &
done

echo -e "${GREEN}[SUCCESS]${NC} Generated 15 rapid connections"
echo ""
sleep 2

###############################################################################
# Test 4: Unusual Outbound Connection
###############################################################################
echo -e "${GREEN}[TEST 4]${NC} Unusual Outbound Connection"
echo "Connecting to unusual port..."

# Try connecting to unusual high port
timeout 5 nc -w 2 8.8.8.8 9999 2>/dev/null &

echo -e "${GREEN}[SUCCESS]${NC} Unusual outbound connection attempted"
echo ""
sleep 2

###############################################################################
# Test 5: New Listening Port
###############################################################################
echo -e "${GREEN}[TEST 5]${NC} New Listening Port"
echo "Opening new listening port 8888..."

if command -v nc &> /dev/null; then
    timeout 30 nc -l -p 8888 &
    NEW_LISTENER=$!
    
    echo -e "${GREEN}[SUCCESS]${NC} New listening port 8888 opened (PID: $NEW_LISTENER)"
else
    # Alternative: Use Python
    timeout 30 python3 -m http.server 8888 &>/dev/null &
    NEW_LISTENER=$!
    echo -e "${GREEN}[SUCCESS]${NC} New listening port 8888 opened with Python (PID: $NEW_LISTENER)"
fi

echo ""
sleep 2

###############################################################################
# Test 6: Tor Port Simulation (9050)
###############################################################################
echo -e "${GREEN}[TEST 6]${NC} Tor Port Activity Simulation"
echo "Simulating Tor network activity..."

if command -v nc &> /dev/null; then
    timeout 15 nc -l -p 9050 &
    TOR_SIM=$!
    
    sleep 1
    echo "test" | timeout 2 nc localhost 9050 &
    
    echo -e "${GREEN}[SUCCESS]${NC} Tor port activity simulated (PID: $TOR_SIM)"
else
    echo -e "${YELLOW}[SKIP]${NC} Netcat not available"
fi

echo ""
sleep 2

###############################################################################
# Test 7: Proxy Port Activity (3128)
###############################################################################
echo -e "${GREEN}[TEST 7]${NC} Proxy Port Activity"
echo "Simulating proxy connection..."

if command -v nc &> /dev/null; then
    timeout 15 nc -l -p 3128 &
    PROXY_SIM=$!
    
    sleep 1
    echo "CONNECT test" | timeout 2 nc localhost 3128 &
    
    echo -e "${GREEN}[SUCCESS]${NC} Proxy port activity simulated (PID: $PROXY_SIM)"
else
    echo -e "${YELLOW}[SKIP]${NC} Netcat not available"
fi

echo ""
sleep 2

###############################################################################
# Test 8: Multiple Port Probing (Port Scan Detection)
###############################################################################
echo -e "${GREEN}[TEST 8]${NC} Aggressive Port Probing"
echo "Probing multiple ports rapidly..."

# Probe 20 different ports quickly
for port in 21 22 23 25 80 110 143 443 445 3306 3389 5432 8080 8443 9090 27017 6379 11211 50000 50001; do
    timeout 0.3 nc -zv localhost $port 2>&1 &
done

echo -e "${GREEN}[SUCCESS]${NC} Port probing completed (20 ports)"
echo ""
sleep 2

###############################################################################
# Test 9: Suspicious Port Range Listener
###############################################################################
echo -e "${GREEN}[TEST 9]${NC} Suspicious Port Range"
echo "Opening listeners on suspicious port range..."

if command -v nc &> /dev/null; then
    # Open listeners on multiple suspicious ports
    for port in 5555 6666 31337; do
        timeout 20 nc -l -p $port &>/dev/null &
        echo "  Opened port $port"
    done
    
    echo -e "${GREEN}[SUCCESS]${NC} Multiple suspicious ports opened"
else
    echo -e "${YELLOW}[SKIP]${NC} Netcat not available"
fi

echo ""
sleep 2

###############################################################################
# Summary and Wait
###############################################################################
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "✓ Port scan simulation"
echo "✓ Connection to suspicious port (4444)"
echo "✓ High connection rate"
echo "✓ Unusual outbound connection"
echo "✓ New listening port (8888)"
echo "✓ Tor port activity (9050)"
echo "✓ Proxy port activity (3128)"
echo "✓ Aggressive port probing"
echo "✓ Suspicious port listeners"
echo ""

echo -e "${YELLOW}[INFO]${NC} Network activities will continue for monitoring..."
echo -e "${YELLOW}[INFO]${NC} Check HIDS Agent for detected network events"
echo -e "${YELLOW}[INFO]${NC} Waiting 30 seconds before cleanup..."
echo ""

# Wait for analysis
sleep 30

###############################################################################
# Cleanup
###############################################################################
echo -e "${YELLOW}[INFO]${NC} Cleaning up..."

# Kill all netcat processes
killall nc 2>/dev/null
pkill -f "nc -l" 2>/dev/null

# Kill specific processes
kill $NC_LISTENER 2>/dev/null
kill $NEW_LISTENER 2>/dev/null
kill $TOR_SIM 2>/dev/null
kill $PROXY_SIM 2>/dev/null
kill $NMAP_PID 2>/dev/null

# Kill Python HTTP servers
pkill -f "http.server 8888" 2>/dev/null

echo -e "${GREEN}[COMPLETE]${NC} All network test processes cleaned up"
echo ""
echo -e "${YELLOW}[TIP]${NC} Check detected network events:"
echo "  cd ../tools"
echo "  python3 query_events.py --type network --limit 20"
echo ""
echo -e "${YELLOW}[TIP]${NC} View network statistics:"
echo "  curl http://localhost:5000/api/stats | jq '.by_type'"