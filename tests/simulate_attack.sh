#!/bin/bash

###############################################################################
# HIDS Testing Script - Simulates Various Attack Scenarios
# WARNING: Run this only in a test environment
###############################################################################

echo "=========================================="
echo "HIDS Attack Simulation Test Script"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[ERROR]${NC} Please run as root (sudo)"
    exit 1
fi

echo -e "${YELLOW}[INFO]${NC} Starting attack simulations..."
echo ""

###############################################################################
# Test 1: File Integrity Violation
###############################################################################
echo -e "${GREEN}[TEST 1]${NC} File Integrity Violation"
echo "Modifying /etc/hosts file..."

# Backup original
cp /etc/hosts /etc/hosts.backup

# Modify file
echo "127.0.0.1   malicious.test.com" >> /etc/hosts
echo -e "${GREEN}[SUCCESS]${NC} File modified. Wait for next integrity scan."
echo ""

sleep 2

###############################################################################
# Test 2: Brute Force SSH Attack Simulation
###############################################################################
echo -e "${GREEN}[TEST 2]${NC} Brute Force SSH Attack Simulation"
echo "Attempting multiple failed SSH logins..."

# Create temporary script for SSH attempts
cat > /tmp/ssh_bruteforce.sh << 'EOF'
#!/bin/bash
for i in {1..6}; do
    echo "Attempt $i..."
    sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no wronguser@localhost 2>&1 | grep -q "denied"
    sleep 1
done
EOF

chmod +x /tmp/ssh_bruteforce.sh

# Install sshpass if not available
if ! command -v sshpass &> /dev/null; then
    echo "Installing sshpass..."
    apt-get install -y sshpass > /dev/null 2>&1
fi

# Run brute force simulation
bash /tmp/ssh_bruteforce.sh
rm /tmp/ssh_bruteforce.sh

echo -e "${GREEN}[SUCCESS]${NC} Brute force simulation completed."
echo ""

sleep 2

###############################################################################
# Test 3: Suspicious User Account Creation
###############################################################################
echo -e "${GREEN}[TEST 3]${NC} Suspicious User Account Creation"
echo "Creating suspicious user account..."

# Create user with suspicious name
useradd -m -s /bin/bash admin123
echo -e "${GREEN}[SUCCESS]${NC} User 'admin123' created."

sleep 2

# Delete user
userdel -r admin123
echo -e "${GREEN}[SUCCESS]${NC} User 'admin123' deleted."
echo ""

sleep 2

###############################################################################
# Test 4: Sudo Authentication Failure
###############################################################################
echo -e "${GREEN}[TEST 4]${NC} Sudo Authentication Failure"
echo "Simulating sudo password failure..."

# Create temporary user
useradd -m testuser
echo "testuser:testpass" | chpasswd

# Try sudo with wrong password (this will generate auth logs)
su - testuser -c "echo 'wrongpass' | sudo -S ls" 2>/dev/null

# Cleanup
userdel -r testuser

echo -e "${GREEN}[SUCCESS]${NC} Sudo failure simulated."
echo ""

sleep 2

###############################################################################
# Test 5: Password Change
###############################################################################
echo -e "${GREEN}[TEST 5]${NC} Password Change Event"
echo "Changing password for a test account..."

# Create temp user and change password
useradd tempuser
echo "tempuser:newpassword123" | chpasswd
userdel -r tempuser

echo -e "${GREEN}[SUCCESS]${NC} Password change simulated."
echo ""

sleep 2

###############################################################################
# Test 6: Hidden File Creation (will be covered in next module)
###############################################################################
echo -e "${GREEN}[TEST 6]${NC} Hidden File Creation"
echo "Creating hidden file in /tmp..."

# Create hidden file
echo "This is a hidden test file" > /tmp/.hidden_test_file
echo -e "${GREEN}[SUCCESS]${NC} Hidden file created at /tmp/.hidden_test_file"
echo ""

sleep 2

###############################################################################
# Cleanup and Summary
###############################################################################
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "✓ File integrity violation"
echo "✓ Brute force SSH attack"
echo "✓ Suspicious user account events"
echo "✓ Sudo authentication failure"
echo "✓ Password change event"
echo "✓ Hidden file creation"
echo ""
echo -e "${YELLOW}[INFO]${NC} Check your HIDS Agent and Server logs for detected events."
echo -e "${YELLOW}[INFO]${NC} Events should appear within the next scan cycle."
echo ""

# Restore /etc/hosts
echo -e "${YELLOW}[INFO]${NC} Restoring /etc/hosts..."
mv /etc/hosts.backup /etc/hosts

# Cleanup hidden file
rm -f /tmp/.hidden_test_file

echo -e "${GREEN}[COMPLETE]${NC} All tests completed and cleanup done."