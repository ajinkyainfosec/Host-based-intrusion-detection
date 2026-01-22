#!/bin/bash

###############################################################################
# HIDS Process Monitoring Test Script
# Simulates suspicious process activities
# WARNING: Run this only in a test environment
###############################################################################

echo "=========================================="
echo "HIDS Process Attack Simulation"
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

echo -e "${YELLOW}[INFO]${NC} Starting process attack simulations..."
echo ""

###############################################################################
# Test 1: Simulate High CPU Usage (Crypto Miner Simulation)
###############################################################################
echo -e "${GREEN}[TEST 1]${NC} High CPU Usage Simulation (Crypto Miner)"
echo "Starting CPU-intensive process..."

# Create CPU-intensive script
cat > /tmp/cpu_stress.sh << 'EOF'
#!/bin/bash
# Simulate CPU-intensive mining activity
while true; do
    echo "scale=5000; a(1)*4" | bc -l > /dev/null 2>&1 &
done
EOF

chmod +x /tmp/cpu_stress.sh

# Run for 30 seconds
timeout 30 bash /tmp/cpu_stress.sh &
CPU_STRESS_PID=$!

echo -e "${GREEN}[SUCCESS]${NC} CPU stress started (PID: $CPU_STRESS_PID)"
echo -e "${YELLOW}[INFO]${NC} Process will run for 30 seconds..."
echo ""

sleep 5

###############################################################################
# Test 2: Suspicious Process Name
###############################################################################
echo -e "${GREEN}[TEST 2]${NC} Suspicious Process Name"
echo "Creating process with suspicious name..."

# Copy a harmless command to a suspicious name
cp /bin/sleep /tmp/xmrig
chmod +x /tmp/xmrig

# Run it
/tmp/xmrig 20 &
SUSPICIOUS_PID=$!

echo -e "${GREEN}[SUCCESS]${NC} Suspicious process started: xmrig (PID: $SUSPICIOUS_PID)"
echo ""

sleep 2

###############################################################################
# Test 3: Process from Suspicious Location (/tmp)
###############################################################################
echo -e "${GREEN}[TEST 3]${NC} Process Running from /tmp"
echo "Executing binary from /tmp..."

# Create a simple script in /tmp
cat > /tmp/suspicious_script.sh << 'EOF'
#!/bin/bash
sleep 15
EOF

chmod +x /tmp/suspicious_script.sh
/tmp/suspicious_script.sh &
TMP_PID=$!

echo -e "${GREEN}[SUCCESS]${NC} Process running from /tmp (PID: $TMP_PID)"
echo ""

sleep 2

###############################################################################
# Test 4: Suspicious Command Pattern
###############################################################################
echo -e "${GREEN}[TEST 4]${NC} Suspicious Command Execution"
echo "Executing command with suspicious pattern..."

# Simulate base64 decode pattern (common in attacks)
echo "dGVzdA==" | base64 -d > /dev/null 2>&1 &

# Simulate wget pattern
timeout 5 bash -c "echo 'wget simulation'" &

echo -e "${GREEN}[SUCCESS]${NC} Suspicious commands executed"
echo ""

sleep 2

###############################################################################
# Test 5: Netcat Listener (Reverse Shell Simulation)
###############################################################################
echo -e "${GREEN}[TEST 5]${NC} Netcat Listener (Reverse Shell Simulation)"

# Check if netcat is installed
if command -v nc &> /dev/null; then
    echo "Starting netcat listener on port 9999..."
    
    # Start netcat listener in background (will be killed soon)
    timeout 15 nc -l -p 9999 &
    NC_PID=$!
    
    echo -e "${GREEN}[SUCCESS]${NC} Netcat listener started (PID: $NC_PID)"
else
    echo -e "${YELLOW}[SKIP]${NC} Netcat not installed, skipping test"
fi

echo ""
sleep 2

###############################################################################
# Test 6: Hidden Process Attempt
###############################################################################
echo -e "${GREEN}[TEST 6]${NC} Hidden Process Simulation"
echo "Creating process with hidden characteristics..."

# Create process with space in name (hiding technique)
cat > "/tmp/ systemd" << 'EOF'
#!/bin/bash
sleep 20
EOF

chmod +x "/tmp/ systemd"
"/tmp/ systemd" &
HIDDEN_PID=$!

echo -e "${GREEN}[SUCCESS]${NC} Hidden process started (PID: $HIDDEN_PID)"
echo ""

sleep 2

###############################################################################
# Test 7: SUID Binary in /tmp (Privilege Escalation Attempt)
###############################################################################
echo -e "${GREEN}[TEST 7]${NC} SUID Binary in Suspicious Location"
echo "Creating SUID binary in /tmp..."

# Copy a safe binary and set SUID bit
cp /bin/echo /tmp/suid_test
chmod u+s /tmp/suid_test

# Run it
/tmp/suid_test "SUID test" &
SUID_PID=$!

echo -e "${GREEN}[SUCCESS]${NC} SUID binary executed from /tmp (PID: $SUID_PID)"
echo ""

sleep 2

###############################################################################
# Test 8: Multiple Connections to Suspicious Ports
###############################################################################
echo -e "${GREEN}[TEST 8]${NC} Connection to Suspicious Port"

if command -v nc &> /dev/null; then
    echo "Attempting connection to suspicious port 4444..."
    
    # Try to connect to suspicious port (will fail, but generates event)
    timeout 3 nc -w 1 127.0.0.1 4444 &> /dev/null &
    
    echo -e "${GREEN}[SUCCESS]${NC} Connection attempt logged"
else
    echo -e "${YELLOW}[SKIP]${NC} Netcat not available"
fi

echo ""
sleep 2

###############################################################################
# Summary and Cleanup Wait
###############################################################################
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "✓ High CPU usage (crypto miner simulation)"
echo "✓ Suspicious process name (xmrig)"
echo "✓ Process from /tmp directory"
echo "✓ Suspicious command patterns"
echo "✓ Netcat listener (reverse shell)"
echo "✓ Hidden process attempt"
echo "✓ SUID binary in /tmp"
echo "✓ Suspicious port connection"
echo ""

echo -e "${YELLOW}[INFO]${NC} Processes will continue for analysis..."
echo -e "${YELLOW}[INFO]${NC} Check HIDS Agent for detected events"
echo -e "${YELLOW}[INFO]${NC} Waiting 45 seconds before cleanup..."
echo ""

# Wait for analysis
sleep 45

###############################################################################
# Cleanup
###############################################################################
echo -e "${YELLOW}[INFO]${NC} Cleaning up test processes..."

# Kill CPU stress
pkill -f cpu_stress.sh
killall bc 2>/dev/null

# Kill other test processes
kill $SUSPICIOUS_PID 2>/dev/null
kill $TMP_PID 2>/dev/null
kill $NC_PID 2>/dev/null
kill $HIDDEN_PID 2>/dev/null
kill $SUID_PID 2>/dev/null

# Remove test files
rm -f /tmp/cpu_stress.sh
rm -f /tmp/xmrig
rm -f /tmp/suspicious_script.sh
rm -f "/tmp/ systemd"
rm -f /tmp/suid_test

echo -e "${GREEN}[COMPLETE]${NC} All test processes cleaned up"
echo ""
echo -e "${YELLOW}[TIP]${NC} Check server dashboard for detected events:"
echo "  curl http://localhost:5000/api/events?severity=high"