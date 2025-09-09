
set -o errexit
set -o nounset
set -o pipefail

# --- Script Metadata ---
readonly SCRIPT_VERSION="5.0.0"
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly GITHUB_REPO="Opselon/leviathan-script" # IMPORTANT: Set this!

# --- System & Application Paths ---
readonly BACKUP_DIR="/var/backups/leviathan/$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/var/log/leviathan.log"
readonly STATE_DIR="/var/lib/leviathan"
readonly SYSCTL_CONF="/etc/sysctl.conf"
readonly GRUB_CONF="/etc/default/grub"
readonly SSHD_CONF="/etc/ssh/sshd_config"
readonly FSTAB_FILE="/etc/fstab"
readonly HOSTS_FILE="/etc/hosts"

# --- State Variables ---
NEEDS_REBOOT=false
declare -gA HW_INFO # Associative array for hardware info
SPINNER_PID=""      # Global PID for the spinner process

# --- SECTION 2: CORE UTILITY & BOOTSTRAP FUNCTIONS ---

# -----------------------------------------------------------------------------
# Function: cleanup()
# Description: Gracefully exits on error or interrupt (SIGINT, SIGTERM).
#              This function is registered with 'trap' to ensure it's always
#              called on script exit. It kills any running spinner process,
#              restores the terminal cursor, and prints a concluding message.
# Parameters: None
# Returns: None (exits the script)
# -----------------------------------------------------------------------------
trap 'cleanup' EXIT INT TERM
cleanup() {
    local exit_code=$?
    if [[ -n "$SPINNER_PID" && -e "/proc/$SPINNER_PID" ]]; then
        kill "$SPINNER_PID" >/dev/null 2>&1
        wait "$SPINNER_PID" 2>/dev/null
    fi
    tput cnorm # Restore cursor visibility
    echo -e "\n\n${C_YELLOW}[*] Leviathan script has concluded its operation.${C_RESET}"
    if [[ "$NEEDS_REBOOT" == true ]]; then
        echo -e "${C_YELLOW}    A system reboot is highly recommended to apply all critical changes.${C_RESET}"
    fi
    exit "$exit_code"
}

# -----------------------------------------------------------------------------
# Function: check_root()
# Description: Verifies that the script is being executed with root privileges
#              (EUID 0). Exits with a fatal error if it's not.
# Parameters: None
# Returns: None (or exits with status 1)
# -----------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "\e[1;31m[✘] FATAL ERROR: This script demands root privileges to command the system. Invoke with 'sudo'.\e[0m" >&2
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Function: setup_environment()
# Description: Creates necessary directories for script operation, such as
#              log and state directories, ensuring they exist before use.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
setup_environment() {
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$STATE_DIR"
    touch "$LOG_FILE"
}

# -----------------------------------------------------------------------------
# Function: log_action()
# Description: A robust logging function that writes timestamped messages to
#              the global log file. It also implements log rotation to prevent
#              the log file from growing indefinitely.
# Parameters:
#   $1: log_level - The severity level (e.g., INFO, ERROR, FATAL).
#   $2: message - The log message string.
# Returns: None
# -----------------------------------------------------------------------------
log_action() {
    local log_level="$1"
    local message="$2"
    # Rotate log if it exceeds 4MB
    if [[ -f "$LOG_FILE" ]] && (( $(stat -c%s "$LOG_FILE") > 4194304 )); then
        mv -f "$LOG_FILE" "${LOG_FILE}.1"
        touch "$LOG_FILE"
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [${log_level^^}] - $message" >> "$LOG_FILE"
}

# -----------------------------------------------------------------------------
# Function: ask_yes_no()
# Description: A universal Yes/No prompt that standardizes user confirmation.
#              It defaults to 'No' if the user just presses Enter.
# Parameters:
#   $1: prompt - The question to ask the user.
# Returns:
#   0 (true) if the user answers Yes.
#   1 (false) if the user answers No or provides no input.
# -----------------------------------------------------------------------------
ask_yes_no() {
    local prompt="$1"
    while true; do
        read -rp "$(echo -e "${C_MAGENTA}$prompt ${C_RESET}[y/N]: ")" choice
        case "$choice" in
            [Yy]* ) return 0;;
            [Nn]*|"" ) return 1;;
            * ) echo "Please respond with 'y' for yes or 'n' for no.";;
        esac
    done
}

# -----------------------------------------------------------------------------
# Function: check_dependencies()
# Description: Checks for all required command-line tools. If any are missing,
#              it prompts the user to install them automatically.
# Parameters: None
# Returns: None (or exits if dependencies can't be installed)
# -----------------------------------------------------------------------------
check_dependencies() {
    local missing_deps=()
    # Expanded list for all new and existing modules
    local required_commands=(
        "curl" "git" "rsync" "ufw" "nproc" "lsblk" "lspci" "dmidecode"
        "smartctl" "lynis" "fail2ban" "chkrootkit" "docker" "qemu-system-x86"
        "virsh" "openssl" "aircrack-ng" "gparted" "testdisk" "binwalk"
        "ghidra" "wireshark-cli" "nmap" "netstat" "nload" "lm-sensors" "bc"
        "figlet" "xmlstarlet"
    )

    print_info "Checking for required system commands..."
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "The following dependencies are missing: ${missing_deps[*]}"
        if ask_yes_no "Shall I attempt to install them now?"; then
            (
                apt-get update
                apt-get install -y "${missing_deps[@]}"
            ) &> /dev/null & spinner $! "Installing missing dependencies..."
            print_success "Dependencies installed."
        else
            print_fatal "Cannot continue without required dependencies. Aborting."
        fi
    fi
}

# -----------------------------------------------------------------------------
# Function: backup_file()
# Description: Creates a secure, timestamped backup of a given file before
#              modification. Uses rsync to preserve metadata.
# Parameters:
#   $1: file_to_backup - The full path to the file.
# Returns: None
# -----------------------------------------------------------------------------
backup_file() {
    local file_to_backup="$1"
    if [[ -f "$file_to_backup" ]]; then
        local backup_filename
        backup_filename=$(basename "$file_to_backup")
        local timestamp
        timestamp=$(date +%Y%m%d_%H%M%S)
        rsync -a "$file_to_backup" "${BACKUP_DIR}/${backup_filename}.${timestamp}.bak"
        log_action "BACKUP" "Created backup of '$file_to_backup' in '$BACKUP_DIR/'."
    fi
}

# -----------------------------------------------------------------------------
# Function: modify_config()
# Description: Safely modifies a configuration file by changing a key-value pair.
#              It first backs up the file, then uses 'sed' to replace an existing
#              line or appends the new key-value pair if it doesn't exist.
# Parameters:
#   $1: file - The configuration file to modify.
#   $2: key - The configuration key (parameter name).
#   $3: value - The new value for the key.
# Returns: None
# -----------------------------------------------------------------------------
modify_config() {
    local file="$1"
    local key="$2"
    local value="$3"
    local separator="${4:- }" # Optional fourth argument for separator, defaults to space

    backup_file "$file"

    # Check if the key exists (commented or not) and replace it.
    if grep -q -E "^\s*#?\s*${key}" "$file"; then
        sed -i -E "s|^\s*#?\s*${key}.*|${key}${separator}${value}|" "$file"
    else
        # If the key doesn't exist, append it to the end of the file.
        echo "${key}${separator}${value}" >> "$file"
    fi
    log_action "CONFIG" "Set '$key' to '$value' in '$file'."
}

# --- SECTION 3: UI & THEMING LIBRARY ---

# --- Color Constants ---
readonly C_RESET='\e[0m'
readonly C_RED='\e[1;31m';     readonly C_RED_BG='\e[41m'
readonly C_GREEN='\e[1;32m';   readonly C_GREEN_BG='\e[42m'
readonly C_YELLOW='\e[1;33m';  readonly C_YELLOW_BG='\e[43m'
readonly C_BLUE='\e[1;34m';    readonly C_BLUE_BG='\e[44m'
readonly C_MAGENTA='\e[1;35m'; readonly C_MAGENTA_BG='\e[45m'
readonly C_CYAN='\e[1;36m';    readonly C_CYAN_BG='\e[46m'
readonly C_WHITE='\e[1;37m';   readonly C_WHITE_BG='\e[47m'
readonly C_GRAY='\e[0;90m'

# --- Formatted Output Functions ---
print_info()    { echo -e "${C_BLUE}[i]${C_RESET} $1"; log_action "INFO" "$1"; }
print_success() { echo -e "${C_GREEN}[✔]${C_RESET} $1"; log_action "SUCCESS" "$1"; }
print_warning() { echo -e "${C_YELLOW}[!]${C_RESET} $1"; log_action "WARNING" "$1"; }
print_error()   { echo -e "${C_RED}[✘]${C_RESET} $1"; log_action "ERROR" "$1"; }
print_fatal()   { echo -e "${C_RED_BG}${C_WHITE}[FATAL]${C_RESET} $1"; log_action "FATAL" "$1"; exit 1; }
print_header()  { echo -e "\n${C_CYAN}══════════════════════════════════════════════════════════════════════════════${C_RESET}"; echo -e "${C_CYAN}:: ${1} ::${C_RESET}"; echo -e "${C_CYAN}══════════════════════════════════════════════════════════════════════════════${C_RESET}"; }
print_subheader() { echo -e "\n${C_MAGENTA}>>> ${1}${C_RESET}"; }
print_suggestion() { echo -e "${C_MAGENTA}[?] Suggestion:${C_RESET} $1"; }

# -----------------------------------------------------------------------------
# Function: press_enter_to_continue()
# Description: Pauses script execution and waits for the user to press Enter.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
press_enter_to_continue() {
    echo -e "\n${C_GRAY}Press [Enter] to continue...${C_RESET}"
    read -r
}

# -----------------------------------------------------------------------------
# Function: spinner()
# Description: Displays an animated spinner for long-running processes to
#              provide visual feedback to the user.
# Parameters:
#   $1: pid - The Process ID of the background command to monitor.
#   $2: message - The text to display next to the spinner.
# Returns:
#   The exit code of the background process.
# -----------------------------------------------------------------------------
spinner() {
    local pid=$1
    local message="${2:-Executing...}"
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    tput civis # Hide cursor
    echo -n "$message "
    while ps -p "$pid" > /dev/null; do
        local temp=${spinstr#?}
        printf "${C_CYAN}%c ${C_RESET}" "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
        printf "\b\b"
    done
    tput cnorm # Restore cursor
    wait "$pid"
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${C_GREEN}Done.${C_RESET}"
    else
        echo -e "${C_RED}Failed.${C_RESET}"
        log_action "ERROR" "Process '$message' (PID: $pid) failed with exit code $exit_code."
    fi
    return $exit_code
}

# -----------------------------------------------------------------------------
# Function: show_leviathan_banner()
# Description: Displays the main ASCII art banner for the script with an
#              animated, line-by-line reveal effect.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
show_leviathan_banner() {
    clear
    local banner_lines
    mapfile -t banner_lines < <(figlet -f slant "Leviathan")
    
    local colors=("$C_CYAN" "$C_BLUE" "$C_MAGENTA" "$C_CYAN" "$C_BLUE" "$C_MAGENTA")
    for i in "${!banner_lines[@]}"; do
        echo -e "${colors[$((i % ${#colors[@]}))]}${banner_lines[$i]}"
        sleep 0.05
    done
    
    echo -e "${C_WHITE} The Omega Edition :: Self Health & Future Planning :: v${SCRIPT_VERSION}${C_RESET}"
    echo -e "${C_GRAY}--------------------------------------------------------------------------------${C_RESET}"
}

# --- SECTION 4: HARDWARE & SYSTEM ANALYSIS LIBRARY ---

# -----------------------------------------------------------------------------
# Function: gather_system_info()
# Description: Collects a wide range of hardware and software information and
#              stores it in the global HW_INFO associative array.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
gather_system_info() {
    print_info "Gathering extensive system information..."
    (
        HW_INFO["cpu_model"]=$(lscpu | grep "Model name" | sed 's/Model name:\s*//' | sed 's/\s+/ /g')
        HW_INFO["cpu_cores"]=$(nproc)
        HW_INFO["ram_total_gb"]=$(free -g | awk '/^Mem:/{print $2}')
        HW_INFO["swap_total_gb"]=$(free -g | awk '/^Swap:/{print $2}')
        
        local disk_info=""
        mapfile -t disks < <(lsblk -d -n -o NAME,TYPE | awk '$2=="disk" {print $1}')
        for disk in "${disks[@]}"; do
            local model
            model=$(smartctl -i "/dev/$disk" 2>/dev/null | grep "Device Model" | awk '{$1=$2=""; print $0}' | sed 's/^\s*//' || echo "N/A")
            local size
            size=$(lsblk -d -n -o SIZE "/dev/$disk")
            local type
            type=$([[ $(cat "/sys/block/$disk/queue/rotational") -eq 0 ]] && echo "SSD" || echo "HDD")
            disk_info+="[$disk: $model ($size) - $type] "
        done
        HW_INFO["storage_devices"]="$disk_info"
        
        HW_INFO["os_distro"]=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
        HW_INFO["kernel_version"]=$(uname -r)
    ) &> /dev/null
    print_success "System analysis complete."
}

# -----------------------------------------------------------------------------
# Function: display_system_summary()
# Description: Formats and displays the information collected by
#              gather_system_info() in a human-readable summary.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
display_system_summary() {
    print_header "System Information Summary"
    echo -e "${C_CYAN}OS & Kernel:${C_RESET}"
    echo -e "  Distro: ${C_WHITE}${HW_INFO[os_distro]}${C_RESET}"
    echo -e "  Kernel: ${C_WHITE}${HW_INFO[kernel_version]}${C_RESET}"

    echo -e "${C_CYAN}CPU Information:${C_RESET}"
    echo -e "  Model: ${C_WHITE}${HW_INFO[cpu_model]}${C_RESET}"
    echo -e "  Cores: ${C_WHITE}${HW_INFO[cpu_cores]}${C_RESET}"

    echo -e "${C_CYAN}Memory (RAM):${C_RESET}"
    echo -e "  Total RAM: ${C_WHITE}${HW_INFO[ram_total_gb]}G${C_RESET}   Total Swap: ${C_WHITE}${HW_INFO[swap_total_gb]}G${C_RESET}"

    echo -e "${C_CYAN}Storage Devices:${C_RESET}"
    echo -e "  ${C_WHITE}${HW_INFO[storage_devices]}${C_RESET}"
}

# --- SECTION 5: MODULE - SYSTEM UPDATE & MAINTENANCE ---

# -----------------------------------------------------------------------------
# Function: run_system_update()
# Description: Performs a comprehensive system update process, including
#              refreshing package lists, upgrading packages, handling
#              distribution upgrades, and cleaning up old dependencies/caches.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
run_system_update() {
    print_header "Module: Intelligent System Update & Maintenance"
    if ! ask_yes_no "This will perform a full system upgrade. Continue?"; then
        print_warning "Update aborted by user."
        return
    fi
    (apt-get update -y) &> /tmp/leviathan_update.log & spinner $! "Updating package lists..."
    (apt-get upgrade -y) &>> /tmp/leviathan_update.log & spinner $! "Upgrading installed packages..."
    (apt-get full-upgrade -y) &>> /tmp/leviathan_update.log & spinner $! "Performing full distribution upgrade..."
    (apt-get autoremove -y) &>> /tmp/leviathan_update.log & spinner $! "Removing old dependencies..."
    (apt-get clean -y) &>> /tmp/leviathan_update.log & spinner $! "Cleaning package cache..."
    print_success "System update and maintenance completed successfully."
    NEEDS_REBOOT=true
}

# --- SECTION 6: MODULE - PERFORMANCE TUNING ---

# -----------------------------------------------------------------------------
# Function: performance_tuning_menu()
# Description: Provides a menu of options for tuning various system
#              performance parameters, such as CPU, memory, and networking.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
performance_tuning_menu() {
    print_header "Module: Performance Tuning"
    local options=("Tune CPU Governor" "Tune Memory & Swap" "Tune I/O Scheduler" "Enable TCP BBR Networking" "Back to Main Menu")
    select opt in "${options[@]}"; do
        case $opt in
            "Tune CPU Governor")
                print_subheader "CPU Governor Tuning"
                local available_govs
                available_govs=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors)
                read -rp "Select Governor [Available: $available_govs]: " gov_choice
                if [[ " $available_govs " =~ " $gov_choice " ]]; then
                    for cpu_dir in /sys/devices/system/cpu/cpu*/cpufreq/; do
                        echo "$gov_choice" > "${cpu_dir}scaling_governor"
                    done
                    print_success "CPU Governor temporarily set to '$gov_choice'. This will reset on reboot."
                else
                    print_error "Invalid governor selected."
                fi
                ;;
            "Tune Memory & Swap")
                print_subheader "Memory & Swappiness Tuning"
                local swappiness
                read -rp "Enter swappiness value (10=low swap usage, 60=default): " swappiness
                if [[ "$swappiness" -ge 0 && "$swappiness" -le 100 ]]; then
                    modify_config "$SYSCTL_CONF" "vm.swappiness" "$swappiness"
                    sysctl -p > /dev/null
                    print_success "Swappiness permanently set to '$swappiness'."
                else
                    print_error "Invalid swappiness value. Must be between 0 and 100."
                fi
                ;;
            "Tune I/O Scheduler")
                print_subheader "I/O Scheduler Tuning"
                print_info "Note: Modern kernels often use multi-queue schedulers (mq-deadline, kyber, bfq) which are generally optimal."
                # This is a complex operation and best left for advanced users to do manually.
                # The script will provide guidance instead of making direct changes.
                print_suggestion "To change the I/O scheduler, edit your GRUB config ('$GRUB_CONF') and add 'elevator=<scheduler>' to GRUB_CMDLINE_LINUX_DEFAULT, then run 'update-grub'."
                print_suggestion "Example: GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash elevator=mq-deadline\""
                ;;
            "Enable TCP BBR Networking")
                print_subheader "TCP BBR Congestion Control"
                modify_config "$SYSCTL_CONF" "net.core.default_qdisc" "fq"
                modify_config "$SYSCTL_CONF" "net.ipv4.tcp_congestion_control" "bbr"
                sysctl -p > /dev/null
                print_success "TCP BBR enabled. Provides significant throughput improvements."
                NEEDS_REBOOT=true
                ;;
            "Back to Main Menu") break ;;
            *) print_error "Invalid option." ;;
        esac
    done
}

# --- SECTION 7: MODULE - SECURITY HARDENING ---

# -----------------------------------------------------------------------------
# Function: security_hardening_menu()
# Description: A menu for applying security best practices to the system,
#              including SSH hardening, firewall configuration, and auditing.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
security_hardening_menu() {
    print_header "Module: Security Hardening"
    local options=("Harden SSH Server (CIS Benchmark)" "Configure UFW Firewall" "Install & Configure Fail2Ban" "Run Lynis System Audit" "Back to Main Menu")
    select opt in "${options[@]}"; do
        case $opt in
            "Harden SSH Server (CIS Benchmark)")
                print_subheader "Applying CIS Benchmark SSH Hardening..."
                modify_config "$SSHD_CONF" "PermitRootLogin" "no"
                modify_config "$SSHD_CONF" "PasswordAuthentication" "no"
                modify_config "$SSHD_CONF" "PubkeyAuthentication" "yes"
                modify_config "$SSHD_CONF" "MaxAuthTries" "3"
                modify_config "$SSHD_CONF" "LoginGraceTime" "60"
                modify_config "$SSHD_CONF" "ClientAliveInterval" "300"
                modify_config "$SSHD_CONF" "ClientAliveCountMax" "0"
                (systemctl restart sshd) &> /dev/null & spinner $! "Restarting SSH service..."
                print_success "SSH server hardened. Ensure you have SSH keys set up before logging out!"
                ;;
            "Configure UFW Firewall")
                print_subheader "Configuring Uncomplicated Firewall (UFW)..."
                ufw default deny incoming &>/dev/null
                ufw default allow outgoing &>/dev/null
                ufw allow ssh &>/dev/null
                ufw limit ssh/tcp &>/dev/null
                ufw enable <<< "y" &> /dev/null
                print_success "UFW enabled with a strict default-deny policy. SSH is allowed."
                ufw status verbose
                ;;
            "Install & Configure Fail2Ban")
                print_subheader "Installing and Enabling Fail2Ban..."
                (apt-get install -y fail2ban) > /dev/null
                (systemctl enable --now fail2ban) &> /dev/null & spinner $! "Enabling and starting Fail2Ban..."
                print_success "Fail2Ban installed and enabled to protect against brute-force attacks."
                ;;
            "Run Lynis System Audit")
                print_subheader "Running Lynis Security Audit..."
                print_info "This may take several minutes. Results will be shown on screen."
                lynis audit system --quiet
                print_success "Lynis audit complete. Review the report in /var/log/lynis-report.dat and suggestions in /var/log/lynis.log"
                ;;
            "Back to Main Menu") break ;;
            *) print_error "Invalid option." ;;
        esac
    done
}

# --- SECTION 8: MODULE - SYSTEM CLEANUP ---

# -----------------------------------------------------------------------------
# Function: run_system_cleanup()
# Description: Performs a deep clean of the system, removing old log files,
#              package caches, temporary files, and other digital detritus.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
run_system_cleanup() {
    print_header "Module: Deep System Cleanup"
    if ! ask_yes_no "This will permanently remove old logs, caches, and temp files. Proceed?"; then
        print_warning "Cleanup aborted by user."
        return
    fi
    journalctl --vacuum-time=2weeks &> /dev/null & spinner $! "Cleaning systemd journal (keeping last 2 weeks)..."
    rm -rf ~/.cache/thumbnails/* &> /dev/null & spinner $! "Clearing user thumbnail cache..."
    (apt-get clean -y) &> /dev/null & spinner $! "Clearing APT package cache..."
    find /tmp -type f -delete &> /dev/null & spinner $! "Clearing /tmp directory..."
    print_success "Deep system cleanup complete."
}

# --- SECTION 9: MODULE - DIAGNOSTICS & REPAIR ---

# -----------------------------------------------------------------------------
# Function: run_diagnostics_repair()
# Description: Runs diagnostic checks for common system problems like broken
#              packages or failed services, and offers automated repair options.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
run_diagnostics_repair() {
    print_header "Module: Diagnostics & Repair"
    print_subheader "Checking for broken APT packages..."
    if apt-get check &> /tmp/apt_check.log; then
        print_success "No broken packages found."
    else
        print_error "Broken packages detected. Attempting to fix..."
        (dpkg --configure -a) &> /dev/null & spinner $! "Reconfiguring packages..."
        (apt-get install -f -y) &> /dev/null & spinner $! "Fixing broken dependencies..."
    fi

    print_subheader "Checking for failed systemd services..."
    if systemctl --failed --quiet; then
        print_error "Failed systemd services detected:"
        systemctl --failed --no-pager
        if ask_yes_no "Attempt to reset their failed state?"; then
            systemctl reset-failed
            print_success "Failed states reset. You may need to manually restart services."
        fi
    else
        print_success "No failed systemd services found."
    fi
}

# --- SECTION 10: MODULE - NETWORK TOOLS ---

# -----------------------------------------------------------------------------
# Function: network_tools_menu()
# Description: Provides a collection of useful command-line network utilities.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
network_tools_menu() {
    print_header "Module: Network Tools"
    local options=(
        "Show Active Connections (netstat)"
        "Live Bandwidth Monitoring (nload)"
        "Run a Speed Test (speedtest-cli)"
        "Scan Local Network for Hosts (nmap)"
        "Back to Main Menu"
    )
    select opt in "${options[@]}"; do
        case $opt in
            "Show Active Connections (netstat)")
                print_subheader "Active TCP/UDP Connections"
                netstat -tulnp
                ;;
            "Live Bandwidth Monitoring (nload)")
                print_info "Starting nload. Press Ctrl+C to exit."
                nload
                ;;
            "Run a Speed Test (speedtest-cli)")
                print_subheader "Running Internet Speed Test"
                curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python3 -
                ;;
            "Scan Local Network for Hosts (nmap)")
                print_subheader "Nmap Host Discovery Scan"
                local ip_range
                local default_range
                default_range=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -n1 | sed 's/\.[0-9]\+\/[0-9]\+$/.0\/24/')
                read -rp "Enter IP range to scan (e.g., 192.168.1.0/24) [default: $default_range]: " ip_range
                ip_range=${ip_range:-$default_range}
                nmap -sn "$ip_range"
                ;;
            "Back to Main Menu") break ;;
            *) print_error "Invalid option." ;;
        esac
    done
}


# --- SECTION 11: MODULE - REPORTING ENGINE ---

# -----------------------------------------------------------------------------
# Function: generate_system_report()
# Description: Generates a comprehensive HTML report containing system summary,
#              disk usage, and security audit findings.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
generate_system_report() {
    print_header "Module: Reporting Engine"
    local report_file="/root/leviathan_report_$(date +%Y%m%d).html"
    print_info "Generating comprehensive system report to $report_file..."
    
    # Generate report content in the background
    (
        # Simple HTML report structure with a dark theme
        {
            echo '<!DOCTYPE html><html lang="en"><head><title>Leviathan System Report</title>'
            echo '<meta charset="UTF-8"><style>body{font-family: "Courier New", monospace; background-color: #1e1e1e; color: #d4d4d4; margin: 20px;} h1,h2{color: #4ec9b0;} pre {background: #252526; border: 1px solid #333; padding: 10px; white-space: pre-wrap; word-wrap: break-word;}</style>'
            echo '</head><body>'
            echo "<h1>Leviathan System Report - $(date)</h1>"
            
            echo "<h2>System Summary</h2><pre>"
            # Temporarily redirect display_system_summary output to a variable, stripping color codes
            summary_output=$(display_system_summary | sed 's/\x1b\[[0-9;]*m//g')
            echo "$summary_output"
            echo "</pre>"
            
            echo "<h2>Disk Usage (df -h)</h2><pre>$(df -h)</pre>"
            echo "<h2>Memory Usage (free -h)</h2><pre>$(free -h)</pre>"
            echo "<h2>Top 10 Processes by CPU</h2><pre>$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 11)</pre>"
            echo "<h2>Top 10 Processes by Memory</h2><pre>$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 11)</pre>"
            echo "<h2>Lynis Security Audit Summary</h2><pre>$(lynis audit system --quiet | grep -E '(\[|Suggestion|Warning|Vulnerable)')</pre>"
            echo "</body></html>"
        } > "$report_file"
    ) & spinner $! "Generating HTML report..."
    
    print_success "Report saved successfully: $report_file"
}

# --- SECTION 12: MODULE - SELF-UPDATE & INTEGRITY CHECK ---

# -----------------------------------------------------------------------------
# Function: run_self_update()
# Description: Checks the configured GitHub repository for a newer version
#              of the script and offers to download and replace the current one.
# Parameters: None
# Returns: None (or exits if update is performed)
# -----------------------------------------------------------------------------
run_self_update() {
    print_header "Module: Self-Update & Integrity Check"
    if [[ "$GITHUB_REPO" == "YOUR_GITHUB_USERNAME/leviathan-script" ]]; then
        print_warning "GitHub repository is not configured in the script. Cannot check for updates."
        return
    fi
    print_info "Fetching latest version from GitHub..."
    local remote_version
    remote_version=$(curl -s "https://raw.githubusercontent.com/$GITHUB_REPO/main/$SCRIPT_NAME" | grep -m 1 'SCRIPT_VERSION=' | cut -d'"' -f2)

    if [[ -z "$remote_version" ]]; then
        print_error "Could not fetch remote version. Check network connection or repository URL."
        return
    fi

    if [[ "$SCRIPT_VERSION" != "$remote_version" ]]; then
        print_success "New version available: $remote_version (Current: $SCRIPT_VERSION)"
        if ask_yes_no "Do you want to update now?"; then
            local tmp_file="${SCRIPT_DIR}/${SCRIPT_NAME}.tmp"
            curl -s "https://raw.githubusercontent.com/$GITHUB_REPO/main/$SCRIPT_NAME" -o "$tmp_file"
            if [[ $? -eq 0 && -s "$tmp_file" ]]; then
                # Basic integrity check: does it look like a bash script?
                if head -n 1 "$tmp_file" | grep -q "bash"; then
                    mv "$tmp_file" "${SCRIPT_DIR}/${SCRIPT_NAME}"
                    chmod +x "${SCRIPT_DIR}/${SCRIPT_NAME}"
                    print_success "Update complete. Please restart the script to use the new version."
                    exit 0
                else
                    print_error "Downloaded file failed integrity check. Aborting update."
                    rm "$tmp_file"
                fi
            else
                print_error "Failed to download the new version."
                [[ -f "$tmp_file" ]] && rm "$tmp_file"
            fi
        fi
    else
        print_success "You are running the latest version of Leviathan ($SCRIPT_VERSION)."
    fi
}

# --- SECTION 13: MODULE - BACKUP & RECOVERY ---

# -----------------------------------------------------------------------------
# Function: backup_recovery_menu()
# Description: Provides options for system backup, currently featuring a full
#              system archive using tar.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
backup_recovery_menu() {
    print_header "Module: Backup & Recovery"
    print_subheader "Create a full system backup (excluding temp/cache dirs)"
    print_warning "This is a resource-intensive operation and can create a very large file."
    if ask_yes_no "This will create a compressed tarball (.tar.gz) of your root filesystem. Continue?"; then
        local backup_file="/root/full_system_backup_$(date +%Y%m%d).tar.gz"
        print_info "Backup started. This will take a VERY long time. The process is running in the background."
        
        # Exclusions list for a cleaner backup
        local exclusions=(
            "--exclude=/proc"
            "--exclude=/tmp"
            "--exclude=/mnt"
            "--exclude=/dev"
            "--exclude=/sys"
            "--exclude=/run"
            "--exclude=/media"
            "--exclude=/var/cache"
            "--exclude=/var/log"
            "--exclude-caches-all"
            "--exclude=${backup_file}"
        )
        
        (tar -cvpzf "$backup_file" "${exclusions[@]}" /) &> /dev/null &
        spinner $! "Creating full system backup..."
        
        if [[ -f "$backup_file" ]]; then
            print_success "Full system backup created at $backup_file"
        else
            print_error "Backup operation failed."
        fi
    fi
}

# --- SECTION 14: MODULE - CONTAINER MANAGEMENT (DOCKER) ---

# -----------------------------------------------------------------------------
# Function: container_management_menu()
# Description: A simple interface for managing Docker containers, including
#              pruning resources and viewing logs.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
container_management_menu() {
    print_header "Module: Container Management (Docker)"
    docker ps -a
    local options=("Prune unused containers/images/volumes" "View logs of a container" "Back to Main Menu")
    select opt in "${options[@]}"; do
        case $opt in
            "Prune unused containers/images/volumes")
                docker system prune -af
                print_success "Docker system pruned."
                ;;
            "View logs of a container")
                read -rp "Enter container ID or name: " container_id
                docker logs -f "$container_id"
                ;;
            "Back to Main Menu") break ;;
            *) print_error "Invalid option." ;;
        esac
    done
}

# --- SECTION 15: NEW THEME - SELF HEALTH & MORE FUTURES ---

# -----------------------------------------------------------------------------
# This entire section is dedicated to the new theme. It contains modules for
# monitoring system and personal health, and for planning future tasks and goals.
# -----------------------------------------------------------------------------

# --- SUB-SECTION 15.1: MODULE - SYSTEM & PERSONAL HEALTH ---

# -----------------------------------------------------------------------------
# Function: display_health_dashboard()
# Description: Shows a real-time snapshot of the system's vital signs, including
#              temperatures, disk health, memory usage, and critical logs.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
display_health_dashboard() {
    print_header "System Health Dashboard"
    
    # 1. CPU Temperature and Fan Speeds
    print_subheader "CPU Temperatures & Fan Speeds"
    if command -v sensors &> /dev/null; then
        sensors | grep -E 'Core|fan' --color=never || echo "lm-sensors not configured. Run 'sensors-detect'."
    else
        print_warning "lm-sensors not installed. Cannot display temperatures."
    fi

    # 2. SMART Disk Health Status
    print_subheader "S.M.A.R.T. Disk Health"
    mapfile -t disks < <(lsblk -d -n -o NAME,TYPE | awk '$2=="disk" {print "/dev/"$1}')
    for disk in "${disks[@]}"; do
        local status
        status=$(smartctl -H "$disk" | grep "test result" | awk '{print $NF}')
        if [[ "$status" == "PASSED" ]]; then
            echo -e "  $disk: ${C_GREEN}$status${C_RESET}"
        elif [[ -z "$status" ]]; then
            echo -e "  $disk: ${C_YELLOW}SMART status not available${C_RESET}"
        else
            echo -e "  $disk: ${C_RED}$status${C_RESET}"
        fi
    done

    # 3. Memory and Swap Usage
    print_subheader "Memory & Swap Usage"
    free -h

    # 4. Critical System Logs
    print_subheader "Last 10 Critical System Log Entries"
    journalctl -p 3 -n 10 --no-pager

    # 5. Uptime and Load Average
    print_subheader "Uptime & Load Average"
    uptime
}

# -----------------------------------------------------------------------------
# Function: run_pomodoro_timer()
# Description: A simple Pomodoro timer to encourage focused work sessions
#              followed by short breaks.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
run_pomodoro_timer() {
    print_subheader "Pomodoro Focus Timer"
    local work_minutes=25
    local break_minutes=5
    
    echo "Starting a ${work_minutes}-minute focus session."
    echo "Press Ctrl+C to interrupt."
    
    for (( i=work_minutes*60; i>0; i-- )); do
        printf "\rTime remaining: %02d:%02d" $((i/60)) $((i%60))
        sleep 1
    done
    
    echo -e "\n${C_GREEN}Work session complete! Time for a ${break_minutes}-minute break.${C_RESET}"
    # Terminal bell
    echo -e '\a'
    
    for (( i=break_minutes*60; i>0; i-- )); do
        printf "\rBreak remaining: %02d:%02d" $((i/60)) $((i%60))
        sleep 1
    done
    
    echo -e "\n${C_YELLOW}Break over! Time to get back to it.${C_RESET}"
    echo -e '\a'
}

# -----------------------------------------------------------------------------
# Function: manage_focus_mode()
# Description: Toggles a "focus mode" by blocking a list of distracting
#              websites using the /etc/hosts file.
# Parameters:
#   $1: action - "on" or "off"
# Returns: None
# -----------------------------------------------------------------------------
manage_focus_mode() {
    local action=$1
    local distracting_sites=(
        "www.facebook.com" "facebook.com"
        "www.twitter.com" "twitter.com"
        "www.instagram.com" "instagram.com"
        "www.reddit.com" "reddit.com"
        "www.youtube.com" "youtube.com"
    )
    local focus_marker="# LEVIATHAN_FOCUS_BLOCK"
    
    backup_file "$HOSTS_FILE"
    
    if [[ "$action" == "on" ]]; then
        print_info "Activating Focus Mode..."
        # Remove any previous blocks first to prevent duplicates
        sed -i "/$focus_marker/d" "$HOSTS_FILE"
        # Add new blocks
        for site in "${distracting_sites[@]}"; do
            echo "127.0.0.1 $site $focus_marker" >> "$HOSTS_FILE"
        done
        print_success "Focus Mode is ON. Distracting sites are blocked."
    else
        print_info "Deactivating Focus Mode..."
        sed -i "/$focus_marker/d" "$HOSTS_FILE"
        print_success "Focus Mode is OFF. Sites are accessible again."
    fi
}

# -----------------------------------------------------------------------------
# Function: health_menu()
# Description: The main menu for the "Self Health" theme, providing access
#              to system health tools and personal wellness features.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
health_menu() {
    print_header "Module: System & Personal Health"
    local options=(
        "View System Health Dashboard"
        "Start Pomodoro Focus Timer"
        "Activate Focus Mode (Block Distractions)"
        "Deactivate Focus Mode"
        "Back to Main Menu"
    )
    select opt in "${options[@]}"; do
        case $opt in
            "View System Health Dashboard") display_health_dashboard ;;
            "Start Pomodoro Focus Timer") run_pomodoro_timer ;;
            "Activate Focus Mode (Block Distractions)") manage_focus_mode "on" ;;
            "Deactivate Focus Mode") manage_focus_mode "off" ;;
            "Back to Main Menu") break ;;
            *) print_error "Invalid option." ;;
        esac
    done
}


# --- SUB-SECTION 15.2: MODULE - FUTURES & PLANNING ---

# -----------------------------------------------------------------------------
# Function: manage_scheduled_tasks()
# Description: A user-friendly front-end for 'cron' to schedule common
#              administrative tasks provided by Leviathan.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
manage_scheduled_tasks() {
    print_subheader "Cron Task Scheduler"
    local cron_file="/etc/cron.d/leviathan"
    
    local options=(
        "Schedule Weekly System Update"
        "Schedule Daily System Cleanup"
        "Schedule Weekly Full Backup"
        "List Scheduled Leviathan Tasks"
        "Remove All Leviathan Tasks"
        "Back"
    )
    select opt in "${options[@]}"; do
        case $opt in
            "Schedule Weekly System Update")
                echo "0 4 * * 0 root ${SCRIPT_DIR}/${SCRIPT_NAME} --non-interactive --update" > "$cron_file"
                print_success "System update scheduled for every Sunday at 4 AM."
                ;;
            "Schedule Daily System Cleanup")
                echo "0 5 * * * root ${SCRIPT_DIR}/${SCRIPT_NAME} --non-interactive --cleanup" >> "$cron_file"
                print_success "System cleanup scheduled for 5 AM daily."
                ;;
            "Schedule Weekly Full Backup")
                echo "0 2 * * 6 root ${SCRIPT_DIR}/${SCRIPT_NAME} --non-interactive --backup" >> "$cron_file"
                print_success "Full system backup scheduled for every Saturday at 2 AM."
                ;;
            "List Scheduled Leviathan Tasks")
                if [[ -f "$cron_file" ]]; then
                    cat "$cron_file"
                else
                    print_info "No Leviathan tasks are currently scheduled."
                fi
                ;;
            "Remove All Leviathan Tasks")
                if [[ -f "$cron_file" ]]; then
                    rm "$cron_file"
                    print_success "All scheduled Leviathan tasks have been removed."
                else
                    print_info "No tasks to remove."
                fi
                ;;
            "Back") break ;;
            *) print_error "Invalid option." ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Function: forecast_disk_usage()
# Description: A simple forecasting tool that estimates when a disk partition
#              might run out of space based on recent usage trends.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
forecast_disk_usage() {
    print_subheader "Disk Usage Forecasting"
    local history_file="${STATE_DIR}/disk_usage.log"
    local days_to_analyze=7
    local threshold=90 # Percentage
    
    # Record today's usage
    df -B1 | grep '^/dev/' | awk '{print $1, $3}' >> "$history_file"
    
    print_info "Analyzing usage data for the last $days_to_analyze days..."
    
    # Process each partition
    df -H | grep '^/dev/' | while read -r line; do
        local partition=$(echo "$line" | awk '{print $1}')
        local mount_point=$(echo "$line" | awk '{print $6}')
        local total_space=$(df -B1 "$partition" | tail -n1 | awk '{print $2}')
        local current_usage=$(df -B1 "$partition" | tail -n1 | awk '{print $3}')
        local current_percent=$(echo "$line" | awk '{print $5}' | tr -d '%')
        
        # Get historical data for this partition
        local historical_data
        historical_data=$(grep "$partition" "$history_file" | tail -n $days_to_analyze)
        
        if [[ $(echo "$historical_data" | wc -l) -lt 2 ]]; then
            echo -e "${C_YELLOW}Partition $mount_point: Not enough historical data to forecast.${C_RESET}"
            continue
        fi
        
        local first_usage; first_usage=$(echo "$historical_data" | head -n1 | awk '{print $2}')
        local daily_avg_growth; daily_avg_growth=$(echo "($current_usage - $first_usage) / $days_to_analyze" | bc)
        
        if (( daily_avg_growth <= 0 )); then
            echo -e "${C_GREEN}Partition $mount_point: Usage is stable or decreasing. No risk detected.${C_RESET}"
            continue
        fi
        
        local space_to_threshold; space_to_threshold=$(echo "($total_space * $threshold / 100) - $current_usage" | bc)
        local days_to_full; days_to_full=$(echo "$space_to_threshold / $daily_avg_growth" | bc)
        
        if (( days_to_full < 30 )); then
            echo -e "${C_RED}Partition $mount_point: DANGER! Estimated to reach ${threshold}% capacity in approximately ${days_to_full} days.${C_RESET}"
        elif (( days_to_full < 90 )); then
            echo -e "${C_YELLOW}Partition $mount_point: WARNING. Estimated to reach ${threshold}% capacity in approximately ${days_to_full} days.${C_RESET}"
        else
            echo -e "${C_GREEN}Partition $mount_point: OK. Estimated ${days_to_full} days until ${threshold}% capacity is reached.${C_RESET}"
        fi
    done
    
    # Prune old history
    tail -n 1000 "$history_file" > "${history_file}.tmp" && mv "${history_file}.tmp" "$history_file"
}

# -----------------------------------------------------------------------------
# Function: fetch_tech_news()
# Description: Fetches and displays the latest headlines from a technology
#              news RSS feed to keep the user informed.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
fetch_tech_news() {
    print_subheader "Latest Tech News from Hacker News"
    local feed_url="https://news.ycombinator.com/rss"
    print_info "Fetching headlines..."
    
    # Using curl and xmlstarlet to parse the RSS feed
    local headlines
    headlines=$(curl -s "$feed_url" | xmlstarlet sel -t -m "//item" -v "title" -n 2>/dev/null || echo "Error")
    
    if [[ "$headlines" == "Error" || -z "$headlines" ]]; then
        print_error "Could not fetch news. Please check network or xmlstarlet installation."
        return
    fi
    
    # Print the top 10 headlines
    echo "$headlines" | head -n 10 | while IFS= read -r line; do
        echo -e "  - ${C_WHITE}$line${C_RESET}"
    done
}

# -----------------------------------------------------------------------------
# Function: futures_menu()
# Description: The main menu for the "More Futures" theme, providing tools
#              for scheduling, forecasting, and staying informed.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
futures_menu() {
    print_header "Module: Futures & Planning"
    local options=(
        "Manage Scheduled Tasks (Cron)"
        "Forecast Disk Usage"
        "Fetch Latest Tech News"
        "Back to Main Menu"
    )
    select opt in "${options[@]}"; do
        case $opt in
            "Manage Scheduled Tasks (Cron)") manage_scheduled_tasks ;;
            "Forecast Disk Usage") forecast_disk_usage ;;
            "Fetch Latest Tech News") fetch_tech_news ;;
            "Back to Main Menu") break ;;
            *) print_error "Invalid option." ;;
        esac
    done
}

# --- SECTION 16: MAIN MENU & EXECUTION FLOW ---

# -----------------------------------------------------------------------------
# Function: main_menu()
# Description: The main entry point of the script's interactive interface.
#              It displays all available modules and handles user input
#              to navigate to the corresponding functions.
# Parameters: None
# Returns: None
# -----------------------------------------------------------------------------
main_menu() {
    local choice
    while true; do
        show_leviathan_banner
        echo -e "${C_CYAN}Core System Administration:${C_RESET}"
        echo -e "  1. System Update & Maintenance      2. Performance Tuning       3. Security Hardening"
        echo -e "  4. Deep System Cleanup              5. Diagnostics & Repair     6. Backup & Recovery"

        echo -e "${C_GREEN}Health & Futures Planning:${C_RESET}"
        echo -e "  7. System & Personal Health         8. Futures & Planning"

        echo -e "${C_MAGENTA}Tools & Utilities:${C_RESET}"
        echo -e "  9. Network Tools                   10. Reporting Engine        11. Container Management (Docker)"

        echo -e "${C_WHITE}Script Management:${C_RESET}"
        echo -e " 12. Self-Update Leviathan"

        echo -e "${C_GRAY}--------------------------------------------------------------------------------${C_RESET}"
        echo -e "  S. Display System Information       Q. Quit"
        echo

        read -rp "$(echo -e ${C_YELLOW}"Select a module to run: "${C_RESET})" choice

        case "$choice" in
            1) run_system_update ;;
            2) performance_tuning_menu ;;
            3) security_hardening_menu ;;
            4) run_system_cleanup ;;
            5) run_diagnostics_repair ;;
            6) backup_recovery_menu ;;
            7) health_menu ;;
            8) futures_menu ;;
            9) network_tools_menu ;;
            10) generate_system_report ;;
            11) container_management_menu ;;
            12) run_self_update ;;
            [sS]) display_system_summary; press_enter_to_continue ;;
            [qQ]) cleanup ;;
            *) print_error "Invalid selection." ;;
        esac
        
        # Pause after a module runs, unless it was a quick display or quit
        if [[ "$choice" != [qQ] && "$choice" != [sS] ]]; then
            press_enter_to_continue
        fi
    done
}

# --- SCRIPT ENTRY POINT ---

# -----------------------------------------------------------------------------
# Main execution block. This is where the script officially begins.
# It checks for root, sets up the environment, checks dependencies,
# gathers initial system info, and then launches the main menu.
# -----------------------------------------------------------------------------
main() {
    check_root
    setup_environment
    check_dependencies
    gather_system_info # Initial analysis
    main_menu
}

main "$@"

# This exit is for safety; the script should only exit via the cleanup trap.
# It ensures that even if the main loop is broken unexpectedly, the script
# exits cleanly.
exit 0