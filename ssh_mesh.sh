#!/bin/bash
# SSH Key Type: auto (auto-detect) | ed25519 (OpenSSH 6.5+/2014+) | rsa (legacy) | ecdsa (alternative)
set -euo pipefail
umask 022

# ---------------- Dependency Check ----------------
command -v sshpass >/dev/null 2>&1 || {
    echo -e "\033[0;91mERROR: sshpass not found.\033[0m"
    echo -e "\033[1;33mPlease install sshpass:\033[0m"
    echo "  - CentOS/RHEL: dnf install epel-release -y && dnf install sshpass -y"
    echo "  - Ubuntu/Debian: apt-get install sshpass -y"
    exit 1
}

# ---------------- Configuration ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODES_FILE="${SCRIPT_DIR}/nodes"
SSH_KEY_TYPE="auto"  # Set to "auto" for automatic detection, or specify: ed25519, rsa, ecdsa
RSA_KEY_BITS="4096"  # RSA key length for enhanced security (2048/3072/4096)

# Temporary files
ALL_KEYS_TEMP=$(mktemp /tmp/ssh_keys.XXXXXX)
KNOWN_HOSTS_TEMP=$(mktemp /tmp/ssh_hosts.XXXXXX)
VERIFY_LOG=$(mktemp /tmp/ssh_verify.XXXXXX)

# Color definitions - semantic naming for better maintainability
ERROR_COLOR='\033[0;91m'      # Bright red/orange - for errors and failures
SUCCESS_COLOR='\033[0;32m'    # Green - for success messages
WARNING_COLOR='\033[1;33m'    # Yellow - for warnings
INFO_COLOR='\033[0;36m'       # Cyan - for informational text
NC='\033[0m'                  # No Color

trap 'rm -f "$ALL_KEYS_TEMP" "$KNOWN_HOSTS_TEMP" "$VERIFY_LOG" 2>/dev/null; unset SSHPASS' EXIT

# ---------------- Auto-detect SSH Key Type ----------------
if [ "$SSH_KEY_TYPE" = "auto" ]; then
    echo -e "${INFO_COLOR}Detecting SSH key type support...${NC}"
    
    # Test if local system supports ed25519
    if ssh-keygen -t ed25519 -N '' -f /tmp/.ssh_ed25519_test >/dev/null 2>&1; then
        rm -f /tmp/.ssh_ed25519_test /tmp/.ssh_ed25519_test.pub
        SSH_KEY_TYPE="ed25519"
        echo -e "${SUCCESS_COLOR}✓ ed25519 supported → using ed25519${NC}"
        echo -e "${INFO_COLOR}  Assumption: All remote nodes support OpenSSH 6.5+ (CentOS 7+, Ubuntu 14.04+)${NC}"
    else
        SSH_KEY_TYPE="rsa"
        echo -e "${WARNING_COLOR}✓ ed25519 not supported → using rsa-${RSA_KEY_BITS} for compatibility${NC}"
        echo -e "${INFO_COLOR}  Security: Using ${RSA_KEY_BITS}-bit RSA for enhanced protection${NC}"
    fi
    echo ""
fi

# ---------------- Helper Functions ----------------
print_header() {
    echo -e "${INFO_COLOR}============================================================${NC}"
    echo -e "${INFO_COLOR}$1${NC}"
    echo -e "${INFO_COLOR}============================================================${NC}"
}

print_step() {
    echo -e "${INFO_COLOR}[$1]${NC} $2"
}

print_success() {
    echo -e "  ${SUCCESS_COLOR}✓${NC} $1"
}

print_error() {
    echo -e "  ${ERROR_COLOR}✗${NC} $1"
}

print_warning() {
    echo -e "  ${WARNING_COLOR}⚠${NC} $1"
}

# ---------------- Pre-checks ----------------
if [ ! -f "$NODES_FILE" ]; then
    echo -e "${ERROR_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${ERROR_COLOR}ERROR: Node configuration file not found${NC}"
    echo -e "${ERROR_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${INFO_COLOR}Expected file location:${NC} $NODES_FILE"
    echo ""
    echo -e "${INFO_COLOR}Purpose:${NC}"
    echo "  This file should contain a list of all hostnames or IP addresses"
    echo "  for the nodes that will participate in the SSH mesh network."
    echo ""
    echo -e "${INFO_COLOR}File Format:${NC}"
    echo "  - One hostname or IP address per line"
    echo "  - Lines starting with '#' are treated as comments"
    echo "  - Empty lines are ignored"
    echo ""
    echo -e "${INFO_COLOR}Example content:${NC}"
    echo "  # Production cluster nodes"
    echo "  node01.example.com"
    echo "  node02.example.com"
    echo "  192.168.1.10"
    echo "  192.168.1.11"
    echo ""
    echo -e "${INFO_COLOR}How to create:${NC}"
    echo "  mkdir -p $(dirname "$NODES_FILE")"
    echo "  cat > $NODES_FILE <<EOF"
    echo "  node1.mydomain.com"
    echo "  node2.mydomain.com"
    echo "  node3.mydomain.com"
    echo "  EOF"
    echo ""
    echo -e "${ERROR_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 1
fi

# Read and clean node list
mapfile -t NODES_RAW < <(grep -Ev '^\s*($|#)' "$NODES_FILE")

# Clean and validate nodes
NODES=()
DUPLICATES=()
declare -A SEEN_NODES

for node in "${NODES_RAW[@]}"; do
    # Remove leading/trailing whitespace
    node=$(echo "$node" | xargs)
    
    # Skip empty lines
    [ -z "$node" ] && continue
    
    # Convert to lowercase for duplicate detection
    node_lower=$(echo "$node" | tr '[:upper:]' '[:lower:]')
    
    # Check for duplicates (case-insensitive)
    if [[ -v SEEN_NODES[$node_lower] ]]; then
        DUPLICATES+=("$node (duplicate of ${SEEN_NODES[$node_lower]})")
        continue
    fi
    
    # Store original case but track by lowercase
    SEEN_NODES[$node_lower]="$node"
    NODES+=("$node_lower")
done

# Report issues if found
if [ ${#DUPLICATES[@]} -gt 0 ]; then
    print_warning "Found duplicate nodes (case-insensitive):"
    printf '  %s\n' "${DUPLICATES[@]}"
    echo ""
fi

NUM_NODES=${#NODES[@]}

if [ "$NUM_NODES" -lt 2 ]; then
    echo -e "${WARNING_COLOR}Warning: Node file contains fewer than 2 valid hosts.${NC}"
    echo -e "${WARNING_COLOR}Full mesh requires at least 2 hosts.${NC}"
    exit 1
fi

# Display cleaned node list (single line summary)
echo -e "${INFO_COLOR}Loaded ${NUM_NODES} node(s) from configuration file${NC}"
echo ""

# ---------------- Interactive Input for Username and Port ----------------
echo ""
# Username input with default value
read -p "Enter SSH Username [default: root]: " SSH_USER
SSH_USER="${SSH_USER:-root}"

# Port input with default value
read -p "Enter SSH Port [default: 22]: " SSH_PORT
SSH_PORT="${SSH_PORT:-22}"

# Validate port number
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
    echo -e "${ERROR_COLOR}ERROR: Invalid port number. Must be between 1-65535${NC}"
    exit 1
fi

# SSH default options (using the custom port)
SSH_OPTS="-q -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

# ---------------- Dry-run Mode ----------------
echo ""
read -p "Run in dry-run mode? (y=preview only, n=execute changes) [default: n]: " DRY_RUN_INPUT
DRY_RUN_INPUT=$(echo "$DRY_RUN_INPUT" | tr '[:upper:]' '[:lower:]')

if [[ "$DRY_RUN_INPUT" =~ ^(y|yes)$ ]]; then
    DRY_RUN=true
    echo -e "${WARNING_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WARNING_COLOR}DRY-RUN MODE ENABLED${NC}"
    echo -e "${WARNING_COLOR}No changes will be made to any nodes${NC}"
    echo -e "${WARNING_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
else
    DRY_RUN=false
fi

# ---------------- Safety Password Input ----------------
echo ""
while true; do
    read -rs -p "Enter Password for $SSH_USER: " PASS1; echo
    read -rs -p "Confirm Password: " PASS2; echo

    if [ -z "$PASS1" ]; then
        echo -e "${ERROR_COLOR}>> ERROR: Password cannot be empty. Please try again.${NC}"
    elif [ "$PASS1" == "$PASS2" ]; then
        export SSHPASS="$PASS1"
        break
    else
        echo -e "${ERROR_COLOR}>> ERROR: Passwords do not match. Please try again.${NC}"
    fi
done

# ---------------- Display Configuration ----------------
print_header "Full Mesh SSH Trust Orchestrator"
echo -e "  User: ${INFO_COLOR}$SSH_USER${NC}"
echo -e "  Nodes: ${INFO_COLOR}$NUM_NODES${NC}"
echo -e "  Port: ${INFO_COLOR}$SSH_PORT${NC}"
if [ "$SSH_KEY_TYPE" = "rsa" ]; then
    echo -e "  Key Type: ${INFO_COLOR}$SSH_KEY_TYPE-${RSA_KEY_BITS}${NC}"
else
    echo -e "  Key Type: ${INFO_COLOR}$SSH_KEY_TYPE${NC}"
fi
echo -e "  Total Paths: ${INFO_COLOR}$((NUM_NODES * (NUM_NODES - 1)))${NC}"
if [ "$DRY_RUN" = true ]; then
    echo -e "  Mode: ${WARNING_COLOR}DRY-RUN (Preview Only)${NC}"
else
    echo -e "  Mode: ${SUCCESS_COLOR}LIVE (Making Changes)${NC}"
fi
echo ""

# ---------------- Dry-run Detailed Preview ----------------
if [ "$DRY_RUN" = true ]; then
    # Prepare KEYSCAN_TYPES for preview
    if [ "$SSH_KEY_TYPE" = "rsa" ]; then
        KEYSCAN_TYPES_PREVIEW="rsa"
    else
        KEYSCAN_TYPES_PREVIEW="rsa,$SSH_KEY_TYPE"
    fi
    
    print_header "DRY-RUN: Preview of Operations"
    
    echo -e "${INFO_COLOR}Step 1: Key Generation${NC}"
    echo "  Will attempt to generate SSH keys on $NUM_NODES nodes"
    echo ""
    
    echo -e "${INFO_COLOR}Step 2: Key Collection${NC}"
    echo "  Will collect public keys from ~/.ssh/id_$SSH_KEY_TYPE.pub on each node"
    echo ""
    
    echo -e "${INFO_COLOR}Step 3: Fingerprint Scanning${NC}"
    echo "  Will scan SSH fingerprints using: ssh-keyscan -p $SSH_PORT -t $KEYSCAN_TYPES_PREVIEW"
    echo ""
    
    echo -e "${INFO_COLOR}Step 4: Key Distribution${NC}"
    echo "  Will distribute collected keys to all nodes:"
    echo "    - Update ~/.ssh/authorized_keys (merge, deduplicate)"
    echo "    - Update ~/.ssh/known_hosts (merge, deduplicate)"
    echo "    - Set permissions: ~/.ssh (700), authorized_keys (600), known_hosts (644)"
    echo ""
    
    echo -e "${INFO_COLOR}Step 5: Verification${NC}"
    echo "  Will test $((NUM_NODES * (NUM_NODES - 1))) passwordless SSH connections (full mesh)"
    echo ""
    
    print_header "DRY-RUN: Connectivity Test"
    echo -e "  Testing basic SSH connectivity to all nodes..."
    echo -n "  Progress: "
    
    REACHABLE_NODES=()
    UNREACHABLE_NODES=()
    
    for node in "${NODES[@]}"; do
        if sshpass -e ssh -q -p "$SSH_PORT" \
              -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o ConnectTimeout=5 \
              "$SSH_USER@$node" "echo 'OK'" >/dev/null 2>&1; then
            echo -n "."
            REACHABLE_NODES+=("$node")
        else
            echo -n "x"
            UNREACHABLE_NODES+=("$node")
        fi
    done
    
    echo " Done"
    echo ""
    print_header "DRY-RUN: Summary"
    echo -e "  Total Nodes:      ${INFO_COLOR}$NUM_NODES${NC}"
    echo -e "  Reachable:        ${SUCCESS_COLOR}${#REACHABLE_NODES[@]}${NC}"
    echo -e "  Unreachable:      ${ERROR_COLOR}${#UNREACHABLE_NODES[@]}${NC}"
    
    if [ ${#UNREACHABLE_NODES[@]} -gt 0 ]; then
        echo ""
        echo -e "${ERROR_COLOR}Unreachable nodes:${NC}"
        for node in "${UNREACHABLE_NODES[@]}"; do
            echo -e "  ${ERROR_COLOR}✗${NC} $node"
        done
        echo ""
        echo -e "${WARNING_COLOR}Please verify these issues before running in live mode:${NC}"
        echo "  1. Network connectivity"
        echo "  2. SSH service status (systemctl status sshd)"
        echo "  3. Correct username and password"
        echo "  4. Correct SSH port"
        echo "  5. Firewall rules (allow port $SSH_PORT)"
    fi
    
    echo ""
    echo -e "${SUCCESS_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${SUCCESS_COLOR}DRY-RUN COMPLETED${NC}"
    echo -e "${SUCCESS_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [ ${#REACHABLE_NODES[@]} -eq $NUM_NODES ]; then
        echo -e "All nodes are reachable. You can now run the script without dry-run mode."
    else
        echo -e "Some nodes are unreachable. Please fix the issues before proceeding."
    fi
    
    echo ""
    exit 0
fi

# ---------------- Step 1: Key Generation ----------------
print_step "1/5" "Generating SSH keys on all nodes..."
echo -n "  Progress: "

# Export variables for parallel execution
export SSH_USER
export SSH_PORT
export SSH_KEY_TYPE
export RSA_KEY_BITS
export SSHPASS

# Create temp file for results
KEYGEN_LOG=$(mktemp /tmp/ssh_keygen.XXXXXX)

# Limit parallel jobs to avoid system overload
PARALLEL_JOBS=$((NUM_NODES < 20 ? NUM_NODES : 20))

# Parallel key generation
printf '%s\n' "${NODES[@]}" | xargs -I {} -P "$PARALLEL_JOBS" bash -c '
    node="$1"
    
    # Use heredoc to avoid complex quote escaping
    if sshpass -e ssh -q -p "$SSH_PORT" \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 \
          "$SSH_USER@$node" bash <<'"'"'REMOTE_SCRIPT'"'"'
        mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
        if [ ! -f "$HOME/.ssh/id_'"$SSH_KEY_TYPE"'" ]; then
            if [ "'"$SSH_KEY_TYPE"'" = "rsa" ]; then
                ssh-keygen -t rsa -b '"$RSA_KEY_BITS"' -N "" -f "$HOME/.ssh/id_rsa" -q
            else
                ssh-keygen -t '"$SSH_KEY_TYPE"' -N "" -f "$HOME/.ssh/id_'"$SSH_KEY_TYPE"'" -q
            fi
        fi
REMOTE_SCRIPT
    then
        echo "OK:$node" >> "'"$KEYGEN_LOG"'"
        echo -n "." >&2
    else
        echo "FAIL:$node" >> "'"$KEYGEN_LOG"'"
        echo -n "x" >&2
    fi
' _ {}

echo " Done"
echo ""

# Parse results
FAILED_NODES=()
SUCCESS_NODES=()
while IFS=: read -r status node; do
    if [ "$status" = "FAIL" ]; then
        FAILED_NODES+=("$node")
    else
        SUCCESS_NODES+=("$node")
    fi
done < "$KEYGEN_LOG"

echo -e "  ${INFO_COLOR}→${NC} Successfully generated keys on ${#SUCCESS_NODES[@]}/${NUM_NODES} nodes"

rm -f "$KEYGEN_LOG"

if [ ${#FAILED_NODES[@]} -gt 0 ]; then
    echo ""
    echo -e "${ERROR_COLOR}ERROR: Failed to generate keys on ${#FAILED_NODES[@]} node(s)${NC}"
    if [ ${#FAILED_NODES[@]} -le 5 ]; then
        printf '  %s\n' "${FAILED_NODES[@]}"
    else
        printf '  %s\n' "${FAILED_NODES[@]:0:5}"
        echo -e "  ${INFO_COLOR}... and $((${#FAILED_NODES[@]} - 5)) more nodes${NC}"
    fi
    echo ""
    echo -e "${WARNING_COLOR}Please check:${NC}"
    echo "  1. Network connectivity to these nodes"
    echo "  2. SSH service is running (systemctl status sshd)"
    echo "  3. Password is correct for user '$SSH_USER'"
    echo "  4. User has proper permissions"
    echo "  5. Port $SSH_PORT is correct and accessible"
    exit 1
fi

echo ""

# ---------------- Step 2: Key Collection ----------------
print_step "2/5" "Collecting public keys from all nodes..."
echo -n "  Progress: "

# Create temp directory for individual key files
KEYS_TEMP_DIR=$(mktemp -d /tmp/ssh_keys_dir.XXXXXX)

# Parallel key collection
printf '%s\n' "${NODES[@]}" | xargs -I {} -P "$PARALLEL_JOBS" bash -c '
    node="$1"
    
    if sshpass -e ssh -q -p "$SSH_PORT" \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 \
          "$SSH_USER@$node" "cat \$HOME/.ssh/id_$SSH_KEY_TYPE.pub" \
          > "'"$KEYS_TEMP_DIR"'/${node}.pub" 2>/dev/null; then
        echo -n "." >&2
    else
        echo -n "x" >&2
        rm -f "'"$KEYS_TEMP_DIR"'/${node}.pub" 2>/dev/null
    fi
' _ {}

echo " Done"
echo ""

# Combine all collected keys
: > "$ALL_KEYS_TEMP"
cat "$KEYS_TEMP_DIR"/*.pub > "$ALL_KEYS_TEMP" 2>/dev/null || true
chmod 644 "$ALL_KEYS_TEMP"
KEY_COUNT=$(wc -l < "$ALL_KEYS_TEMP" | tr -d " ")

# Check for failures
EXPECTED_KEYS=$NUM_NODES
FAILED_NODES=()
for node in "${NODES[@]}"; do
    if [ ! -f "$KEYS_TEMP_DIR/${node}.pub" ]; then
        FAILED_NODES+=("$node")
    fi
done

echo -e "  ${INFO_COLOR}→${NC} Successfully collected ${KEY_COUNT}/${EXPECTED_KEYS} public keys"

rm -rf "$KEYS_TEMP_DIR"

if [ ${#FAILED_NODES[@]} -gt 0 ]; then
    echo ""
    echo -e "${ERROR_COLOR}ERROR: Failed to collect keys from ${#FAILED_NODES[@]} node(s)${NC}"
    if [ ${#FAILED_NODES[@]} -le 5 ]; then
        printf '  %s\n' "${FAILED_NODES[@]}"
    else
        printf '  %s\n' "${FAILED_NODES[@]:0:5}"
        echo -e "  ${INFO_COLOR}... and $((${#FAILED_NODES[@]} - 5)) more nodes${NC}"
    fi
    echo ""
    echo -e "${WARNING_COLOR}This usually means the key file doesn't exist or isn't readable.${NC}"
    exit 1
fi

echo ""

# ---------------- Step 3: Fingerprints Scan ----------------
print_step "3/5" "Scanning host fingerprints for known_hosts..."

# Avoid duplicate key types (e.g., if SSH_KEY_TYPE is "rsa", don't scan "rsa,rsa")
if [ "$SSH_KEY_TYPE" = "rsa" ]; then
    KEYSCAN_TYPES="rsa"
else
    KEYSCAN_TYPES="rsa,$SSH_KEY_TYPE"
fi

# Use -T to set timeout (default is 5s, increase for slow networks)
if ssh-keyscan -T 10 -p "$SSH_PORT" -t "$KEYSCAN_TYPES" "${NODES[@]}" 2>/dev/null > "$KNOWN_HOSTS_TEMP"; then
    chmod 644 "$KNOWN_HOSTS_TEMP"
    FINGERPRINT_COUNT=$(wc -l < "$KNOWN_HOSTS_TEMP")
    print_success "Collected $FINGERPRINT_COUNT host fingerprints"
else
    print_warning "Failed to scan host fingerprints"
    echo -e "${WARNING_COLOR}  Note: known_hosts may be incomplete.${NC}"
    echo -e "${WARNING_COLOR}  Impact: First SSH connection to each node may prompt for host verification.${NC}"
    echo -e "${WARNING_COLOR}  This is normal and does not affect passwordless authentication.${NC}"
fi

echo ""

# ---------------- Step 4: Distribution ----------------
print_step "4/5" "Distributing keys and enforcing SSH security..."
echo -n "  Progress: "

# Export required variables for parallel execution
export SSH_USER_VAR="$SSH_USER"
export SSH_PORT_VAR="$SSH_PORT"
export ALL_KEYS_TEMP_VAR="$ALL_KEYS_TEMP"
export KNOWN_HOSTS_TEMP_VAR="$KNOWN_HOSTS_TEMP"
export SSHPASS

# Create temp file for results
DIST_LOG=$(mktemp /tmp/ssh_dist.XXXXXX)
export DIST_LOG_VAR="$DIST_LOG"

# Limit parallel jobs to avoid system overload
PARALLEL_JOBS=$((NUM_NODES < 20 ? NUM_NODES : 20))

# Parallel distribution using xargs
printf '%s\n' "${NODES[@]}" | xargs -I {} -P "$PARALLEL_JOBS" bash -c '
    node="$1"
    
    # Transfer temporary files and setup SSH
    if cat "$ALL_KEYS_TEMP_VAR" | sshpass -e ssh -q -p "$SSH_PORT_VAR" \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 \
          "$SSH_USER_VAR@$node" "cat > ~/.ssh/auth_tmp.pub" 2>/dev/null && \
       cat "$KNOWN_HOSTS_TEMP_VAR" | sshpass -e ssh -q -p "$SSH_PORT_VAR" \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 \
          "$SSH_USER_VAR@$node" "cat > ~/.ssh/hosts_tmp.tmp" 2>/dev/null && \
       sshpass -e ssh -q -p "$SSH_PORT_VAR" \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 \
          "$SSH_USER_VAR@$node" "bash -s" 2>/dev/null <<'"'"'EOF'"'"'
set -e
# Ensure user can access home directory without over-relaxing permissions
chmod u+rwx "$HOME"
chmod 700 "$HOME/.ssh"

touch "$HOME/.ssh/authorized_keys"
sort -u "$HOME/.ssh/auth_tmp.pub" "$HOME/.ssh/authorized_keys" -o "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"

touch "$HOME/.ssh/known_hosts"
sort -u "$HOME/.ssh/hosts_tmp.tmp" "$HOME/.ssh/known_hosts" -o "$HOME/.ssh/known_hosts"
chmod 644 "$HOME/.ssh/known_hosts"

rm -f "$HOME/.ssh/auth_tmp.pub" "$HOME/.ssh/hosts_tmp.tmp"
EOF
    then
        echo "OK:$node" >> "$DIST_LOG_VAR"
        echo -n "." >&2
    else
        echo "FAIL:$node" >> "$DIST_LOG_VAR"
        echo -n "x" >&2
    fi
' _ {}

echo " Done"
echo ""

# Parse results and check for failures
FAILED_NODES=()
while IFS=: read -r status node; do
    if [ "$status" = "FAIL" ]; then
        FAILED_NODES+=("$node")
    fi
done < "$DIST_LOG"

# Cleanup
rm -f "$DIST_LOG"

if [ ${#FAILED_NODES[@]} -gt 0 ]; then
    echo ""
    echo -e "${ERROR_COLOR}ERROR: Failed to distribute keys to ${#FAILED_NODES[@]} node(s)${NC}"
    if [ ${#FAILED_NODES[@]} -le 5 ]; then
        printf '  %s\n' "${FAILED_NODES[@]}"
    else
        printf '  %s\n' "${FAILED_NODES[@]:0:5}"
        echo -e "  ${INFO_COLOR}... and $((${#FAILED_NODES[@]} - 5)) more nodes${NC}"
    fi
    exit 1
fi

echo ""

# ---------------- Step 5: Verification ----------------
TOTAL_PATHS=$(( NUM_NODES * (NUM_NODES - 1) ))
print_step "5/5" "Verifying full mesh connectivity ($TOTAL_PATHS paths)..."
echo -e "  ${INFO_COLOR}→${NC} Testing connections in parallel..."

: > "$VERIFY_LOG"

# Generate task list
GEN_TASKS=$(mktemp)
for src in "${NODES[@]}"; do
    for dst in "${NODES[@]}"; do
        [ "$src" == "$dst" ] && continue
        echo "$src $dst" >> "$GEN_TASKS"
    done
done

# Export variables for parallel execution
export SSH_USER_VAR="$SSH_USER"
export VERIFY_LOG_VAR="$VERIFY_LOG"
export SSH_PORT_VAR="$SSH_PORT"
export SSH_KEY_TYPE_VAR="$SSH_KEY_TYPE"
export SSHPASS

# Dynamic parallel jobs based on node count
PARALLEL_JOBS=$((NUM_NODES < 50 ? NUM_NODES : 50))

# Run verification in parallel with progress indicator
echo -n "  Progress: "
cat "$GEN_TASKS" | xargs -I {} -P "$PARALLEL_JOBS" bash -c '
    read -r src dst <<< "{}"
    if sshpass -e ssh -q -p "$SSH_PORT_VAR" -o StrictHostKeyChecking=no "$SSH_USER_VAR@$src" \
       "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -p $SSH_PORT_VAR -i ~/.ssh/id_$SSH_KEY_TYPE_VAR $SSH_USER_VAR@$dst hostname" >/dev/null 2>&1; then
        echo "OK: $src -> $dst" >> "$VERIFY_LOG_VAR"
        echo -n "." >&2
    else
        echo "FAIL: $src -> $dst" >> "$VERIFY_LOG_VAR"
        echo -n "x" >&2
    fi
'
echo " Done"

rm -f "$GEN_TASKS"

echo ""

# ---------------- Statistics & Results ----------------
OK_COUNT=$(grep -c "^OK" "$VERIFY_LOG" 2>/dev/null || echo 0)
FAIL_COUNT=$(grep -c "^FAIL" "$VERIFY_LOG" 2>/dev/null || echo 0)

# Remove any whitespace/newlines from counts
OK_COUNT=$(echo "$OK_COUNT" | tr -d '\n\r ')
FAIL_COUNT=$(echo "$FAIL_COUNT" | tr -d '\n\r ')

print_header "Verification Summary"
echo -e "  Total Paths:    ${INFO_COLOR}$TOTAL_PATHS${NC}"
echo -e "  Successful:     ${SUCCESS_COLOR}$OK_COUNT${NC}"
echo -e "  Failed:         ${ERROR_COLOR}$FAIL_COUNT${NC}"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${ERROR_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${ERROR_COLOR}Failed Connections:${NC}"
    echo -e "${ERROR_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    grep "^FAIL" "$VERIFY_LOG" | while read -r line; do
        echo -e "  ${ERROR_COLOR}✗${NC} ${line#FAIL: }"
    done
    echo ""
    echo -e "${WARNING_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WARNING_COLOR}Troubleshooting Suggestions:${NC}"
    echo -e "${WARNING_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "1. Permissions Check:"
    echo "   - Home directory: chmod 755 /home/$SSH_USER"
    echo "   - .ssh directory: chmod 700 ~/.ssh"
    echo "   - authorized_keys: chmod 600 ~/.ssh/authorized_keys"
    echo ""
    echo "2. SSH Configuration (/etc/ssh/sshd_config):"
    echo "   - PubkeyAuthentication yes"
    echo "   - AuthorizedKeysFile .ssh/authorized_keys"
    echo "   - PermitRootLogin (if using root)"
    echo "   - Port $SSH_PORT"
    echo "   After changes: systemctl restart sshd"
    echo ""
    echo "3. SELinux (if enabled):"
    echo "   - restorecon -R -v ~/.ssh"
    echo ""
    echo "4. Manual Test:"
    echo "   - ssh -p $SSH_PORT $SSH_USER@<source-host>"
    echo "   - ssh -p $SSH_PORT -vvv $SSH_USER@<destination-host>"
    echo ""
    echo "5. Check Logs:"
    echo "   - tail -f /var/log/secure (on destination)"
    echo "   - journalctl -u sshd -f"
    echo ""
    echo -e "${WARNING_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 1
else
    echo -e "${SUCCESS_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${SUCCESS_COLOR}✓ SUCCESS!${NC}"
    echo -e "${SUCCESS_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "Full mesh SSH trust successfully established!"
    echo -e "All ${NUM_NODES} nodes can now connect to each other passwordlessly."
    if [ "$SSH_KEY_TYPE" = "rsa" ]; then
        echo -e "Security: Using ${RSA_KEY_BITS}-bit RSA keys for enhanced protection."
    fi
    echo ""
    echo -e "${INFO_COLOR}Example usage:${NC}"
    if [ "$SSH_PORT" != "22" ]; then
        echo -e "  ssh -p $SSH_PORT $SSH_USER@${NODES[0]}"
        if [ "$NUM_NODES" -gt 1 ]; then
            echo -e "  ssh -p $SSH_PORT $SSH_USER@${NODES[1]}"
        fi
    else
        echo -e "  ssh $SSH_USER@${NODES[0]}"
        if [ "$NUM_NODES" -gt 1 ]; then
            echo -e "  ssh $SSH_USER@${NODES[1]}"
        fi
    fi
    echo -e "${SUCCESS_COLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 0
fi
