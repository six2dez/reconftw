#!/bin/bash
# Enhanced script to deploy ReconFTW in a LXC container on Proxmox using Debian 12

# Colors for better visualization
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging configuration
LOGFILE="/var/log/reconftw_deploy_$(date +%Y%m%d_%H%M%S).log"
exec 1> >(tee -a "$LOGFILE") 2>&1

# Logging function
log() {
   echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to show errors and exit
error_exit() {
   log "${RED}ERROR: $1${NC}"
   exit 1
}

# Function to validate numbers
validate_number() {
   if ! [[ "$1" =~ ^[0-9]+$ ]]; then
       error_exit "Please enter a valid number"
   fi
}

# Enhanced input function with validation
get_input() {
   local prompt=$1
   local default=$2
   local validate_func=$3
   local result

   while true; do
       read -p "$prompt [Default: $default]: " result
       result="${result:-$default}"
       
       if [[ -n "$validate_func" ]]; then
           if $validate_func "$result"; then
               echo "$result"
               return 0
           fi
       else
           echo "$result"
           return 0
       fi
   done
}

# Function to validate disk space
check_storage_space() {
   local storage=$1
   local required_space=$2
   
   # Get available space in GB
   available_space=$(pvesm status | grep "$storage" | awk '{print $5}' | sed 's/G//')
   
   if (( available_space < required_space )); then
       error_exit "Not enough space in $storage. Available: ${available_space}GB, Required: ${required_space}GB"
   fi
}

# Verify root execution
[[ $EUID -ne 0 ]] && error_exit "This script must be run as root"

# Verify Proxmox environment
[[ ! -f /etc/pve/local/pve-ssl.key ]] && error_exit "This script must be run on a Proxmox server"

# Template configuration
TEMPLATE_NAME="debian-11-standard_11.7-1_amd64.tar.zst"
TEMPLATE_PATH="local:vztmpl/${TEMPLATE_NAME}"

# Verify and download template
log "${YELLOW}Checking template...${NC}"
if ! pveam list local| grep -q $TEMPLATE_NAME; then
   log "Downloading template ${TEMPLATE_NAME}..."
   pveam download local $TEMPLATE_NAME || error_exit "Error downloading template"
fi

# Get next available ID
NEXTID=$(pvesh get /cluster/nextid)
CONTAINER_ID=$(get_input "Container ID" $NEXTID validate_number)

# Container configuration with validations
STORAGE=$(get_input "Storage" "local-lvm")
ROOTFS_SIZE=$(get_input "Root filesystem size (GB)" "20" validate_number)
MEMORY=$(get_input "RAM Memory (MB)" "2048" validate_number)
CPU_CORES=$(get_input "Number of CPUs" "2" validate_number)
HOSTNAME=$(get_input "Hostname" "reconftw-container")
PASSWORD=$(get_input "Password" "$(openssl rand -base64 12)")

# Verify storage space
check_storage_space "$STORAGE" "$ROOTFS_SIZE"

# Configuration summary
log "${GREEN}Container configuration:${NC}"
echo "ID: $CONTAINER_ID"
echo "Storage: $STORAGE"
echo "Size: ${ROOTFS_SIZE}GB"
echo "RAM: ${MEMORY}MB"
echo "CPUs: $CPU_CORES"
echo "Hostname: $HOSTNAME"

# Create container with error handling
log "${YELLOW}Creating LXC container...${NC}"
pct create $CONTAINER_ID $TEMPLATE_PATH \
   --storage $STORAGE \
   --rootfs $STORAGE:${ROOTFS_SIZE} \
   --memory $MEMORY \
   --cores $CPU_CORES \
   --hostname $HOSTNAME \
   --password "$PASSWORD" \
   --unprivileged 1 \
   --net0 name=eth0,bridge=vmbr0,ip=dhcp || error_exit "Error creating container"

# Start container
log "${YELLOW}Starting container...${NC}"
pct start $CONTAINER_ID || error_exit "Error starting container"

# Wait for container to be ready
log "Waiting for container to be ready..."
for i in {1..15}; do
   if pct exec $CONTAINER_ID -- systemctl is-system-running &>/dev/null; then
       break
   fi
   sleep 2
done

# Install ReconFTW
log "${YELLOW}Installing ReconFTW and dependencies...${NC}"
pct exec $CONTAINER_ID -- bash -c "apt update && \
   DEBIAN_FRONTEND=noninteractive apt -y upgrade && \
   apt install -y git sudo python3 python3-pip && \
   cd /opt && \
   git clone --recursive https://github.com/six2dez/reconftw.git && \
   cd reconftw && \
   ./install.sh" || error_exit "Error installing ReconFTW"

# Show final information
log "${GREEN}Installation completed${NC}"
echo "Container information:"
echo "ID: $CONTAINER_ID"
echo "Hostname: $HOSTNAME"
echo "Password: $PASSWORD"
echo "Log file: $LOGFILE"