#!/bin/bash

# FakeAP - Optimized script to create a wireless access point
# Usage: sudo bash FakeAP.sh

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" 
    exit 1
fi

# Check for required dependencies
for cmd in hostapd udhcpd ifconfig iptables dnsmasq; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed."
        read -p "Install dependencies now? (y/n): " dep
        if [ "$dep" = "y" ]; then
            sudo apt install hostapd udhcpd dnsmasq -y
        else
            exit 1
        fi
    fi
done

# Initialize variables
hostapd_pid=""
udhcpd_pid=""
dnsmasq_pid=""
interface=""
source_interface=""
oct="10"

# Function to handle cleanup on script exit
cleanup() {
    echo -e "\nStopping services and cleaning up..."
    # Stop services
    [ -n "$hostapd_pid" ] && sudo kill $hostapd_pid 2>/dev/null
    [ -n "$udhcpd_pid" ] && sudo kill $udhcpd_pid 2>/dev/null
    [ -n "$dnsmasq_pid" ] && sudo kill $dnsmasq_pid 2>/dev/null
    sudo pkill hostapd
    sudo pkill udhcpd
    sudo pkill tshark
    sudo pkill dnsmasq
    sudo systemctl stop dnsmasq
    
    # Clean IP Forwarding rules
    sudo sysctl -w net.ipv4.ip_forward=0
    
    if [ -n "$source_interface" ]; then
        sudo iptables -t nat -D POSTROUTING -o $source_interface -j MASQUERADE 2>/dev/null
        sudo iptables -D FORWARD -i $source_interface -o $interface -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
        sudo iptables -D FORWARD -i $interface -o $source_interface -j ACCEPT 2>/dev/null
    fi
    
    # Return interface to managed mode
    if [ -n "$interface" ]; then
        sudo ifconfig $interface down
        sudo iwconfig $interface mode managed 2>/dev/null
        sudo ifconfig $interface up
        sudo nmcli device set $interface managed yes 2>/dev/null
    fi
    
    # Restart NetworkManager
    sudo systemctl restart NetworkManager

    echo "Cleanup complete. Exiting."
    exit
}

# Trap SIGINT (Ctrl+C) and SIGTERM to call the cleanup function
trap cleanup SIGINT SIGTERM EXIT

# Remove existing config files and create new ones
sudo rm -f Config/udhcpd.conf Config/hostapd.conf capture.pcap
touch Config/udhcpd.conf Config/hostapd.conf
sudo touch capture.pcap
sudo chmod 666 capture.pcap
sudo pkill dnsmasq
sudo systemctl stop dnsmasq

# Display default configuration at startup
show_default_config() {
    echo "============================================"
    echo "        FakeAP Access Point Creator         "
    echo "============================================"
    echo
    echo "DEFAULT CONFIGURATIONS:"
    echo "======================="
    echo
    echo "HOSTAPD CONFIGURATION (WiFi Access Point):"
    echo "-----------------------------------------"
    # Extract and display default hostapd settings
    local default_ssid=$(grep "ssid=" Config/hostapd_def.conf | cut -d'=' -f2)
    local default_channel=$(grep "channel=" Config/hostapd_def.conf | cut -d'=' -f2)
    echo "SSID (Network Name): $default_ssid"
    echo "WiFi Channel: $default_channel"
    echo "Security: Open (no password)"
    echo
    echo "UDHCPD CONFIGURATION (DHCP Server):"
    echo "-----------------------------------"
    # Extract and display default udhcpd settings
    local default_start=$(grep "start" Config/udhcpd_def.conf | awk '{print $2}')
    local default_end=$(grep "end" Config/udhcpd_def.conf | awk '{print $2}')
    local default_dns=$(grep "opt dns" Config/udhcpd_def.conf | awk '{print $3}')
    echo "IP Range: $default_start - $default_end"
    echo "Gateway/Router: $(echo $default_start | cut -d'.' -f1-3).1"
    echo "DNS Server: $default_dns"
    echo
    echo "DNS Spoofing: Disabled by default"
    echo "Internet Sharing: Disabled by default"
    echo "============================================"
    echo
}

# Function to select from a list of options
select_from_list() {
    local options=("$@")
    local count=${#options[@]}
    
    if [ "$count" -eq 0 ]; then
        echo "Error: No options available to select from."
        exit 1
    fi
    
    # Display options with numbers
    for ((i=0; i<count; i++)); do
        echo "[$((i+1))] ${options[i]}"
    done
    
    # Get user selection
    local valid=false
    local selection
    
    while [ "$valid" = false ]; do
        read -p "Enter selection number (1-$count): " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "$count" ]; then
            valid=true
        else
            echo "Invalid selection. Please enter a number between 1 and $count."
        fi
    done
    
    # Return the selected option
    echo "${options[$((selection-1))]}"
}

# Function to validate MAC address format
validate_mac() {
    local mac=$1
    if [[ ! $mac =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        echo "Invalid MAC address format. Please use format: 00:11:22:33:44:55"
        return 1
    fi
    return 0
}

# Function to configure hostapd.conf
configure_hostapd() {
    echo -e "\n=== Access Point Configuration ==="
    
    # Display options first
    echo "Select configuration mode:"
    echo "[1] Default config (use settings from Config/hostapd_def.conf)"
    echo "[2] Custom config (customize SSID, channel, security)"
    
    # Then ask for input
    read -p "Enter selection (1-2) [1]: " h_ans
    h_ans=${h_ans:-1}
    
    # Get available wireless interfaces
    echo -e "\nDetecting wireless interfaces..."
    mapfile -t wireless_interfaces < <(iw dev | grep Interface | awk '{print $2}')
    
    if [ ${#wireless_interfaces[@]} -eq 0 ]; then
        echo "Error: No wireless interfaces found."
        exit 1
    fi
    
    # Display interface options
    echo -e "\nAvailable wireless interfaces for the access point:"
    for ((i=0; i<${#wireless_interfaces[@]}; i++)); do
        echo "[$((i+1))] ${wireless_interfaces[i]}"
    done
    
    # Get user selection
    local valid=false
    local selection
    
    while [ "$valid" = false ]; do
        read -p "Enter selection number (1-${#wireless_interfaces[@]}): " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#wireless_interfaces[@]}" ]; then
            valid=true
        else
            echo "Invalid selection. Please enter a number between 1 and ${#wireless_interfaces[@]}."
        fi
    done
    
    interface="${wireless_interfaces[$((selection-1))]}"
    
    # Check if interface supports AP mode
    if ! iw list | grep -q "AP"; then
        echo "Warning: Your wireless card/driver might not support Access Point mode."
        echo "The script will continue, but it might not work properly."
    fi
    
    if [ "$h_ans" = "2" ]; then
        # Custom configuration
        read -p "SSID (network name): " ssid
        ssid=${ssid:-"FakeAP"}
        
        # Display channel options
        echo -e "\nAvailable WiFi channels:"
        channels=("1 (2.412 GHz)" "2 (2.417 GHz)" "3 (2.422 GHz)" "4 (2.427 GHz)" "5 (2.432 GHz)" 
                 "6 (2.437 GHz) - Default" "7 (2.442 GHz)" "8 (2.447 GHz)" "9 (2.452 GHz)" "10 (2.457 GHz)" "11 (2.462 GHz)")
        
        for ((i=0; i<${#channels[@]}; i++)); do
            echo "[$((i+1))] ${channels[i]}"
        done
        
        # Get channel selection
        valid=false
        
        while [ "$valid" = false ]; do
            read -p "Enter channel selection (1-${#channels[@]}) [6]: " selection
            selection=${selection:-6}
            if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#channels[@]}" ]; then
                valid=true
            else
                echo "Invalid selection. Please enter a number between 1 and ${#channels[@]}."
            fi
        done
        
        selected_ch="${channels[$((selection-1))]}"
        ch=$(echo $selected_ch | cut -d' ' -f1)
        
        # MAC address options
        echo -e "\nSet custom MAC address? (Advanced)"
        echo "[1] No - Use default MAC address"
        echo "[2] Yes - Specify custom MAC address"
        read -p "Enter selection (1-2) [1]: " mac_choice
        mac_choice=${mac_choice:-1}
        ans1="n"
        if [ "$mac_choice" = "2" ]; then
            ans1="y"
        fi
        
        # Security options
        echo -e "\nSet WiFi security:"
        echo "[1] Open network - No password"
        echo "[2] WPA2-PSK - Password protected"
        read -p "Enter selection (1-2) [1]: " pwd_choice
        pwd_choice=${pwd_choice:-1}
        ans2="n"
        if [ "$pwd_choice" = "2" ]; then
            ans2="y"
        fi
        
        # Create hostapd configuration
        HostapdCode="interface=$interface\ndriver=nl80211\nssid=$ssid\nchannel=$ch\nhw_mode=g\nwme_enabled=1\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0"

        if [ "$ans1" = "y" ]; then
            read -p "Enter custom BSSID (MAC address, e.g., 00:11:22:33:44:55): " bssid
            # Validate MAC address format
            while ! validate_mac "$bssid"; do
                read -p "Enter valid MAC address (e.g., 00:11:22:33:44:55): " bssid
            done
            HostapdCode+="\nbssid=$bssid"
        fi

        if [ "$ans2" = "y" ]; then
            read -p "Password (min 8 chars): " pwd
            HostapdCode+="\nwpa=2\nwpa_passphrase=$pwd\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\nrsn_pairwise=CCMP"
        else
            HostapdCode+="\nwpa_pairwise=TKIP\nrsn_pairwise=CCMP"
        fi

        echo -e "$HostapdCode" | sudo tee Config/hostapd.conf > /dev/null
        hostapd_conf="Config/hostapd.conf"
        echo "Custom hostapd configuration created successfully."
    else
        # Default configuration
        sed -i "/interface/c interface=$interface" Config/hostapd_def.conf
        hostapd_conf="Config/hostapd_def.conf"
        echo "Using default hostapd configuration with interface $interface."
    fi
    
    return 0
}

# Function to configure udhcpd.conf
configure_udhcpd() {
    echo -e "\n=== DHCP Server Configuration ==="
    echo "The DHCP server assigns IP addresses to devices connecting to your access point."
    echo
    
    # Display options first
    echo "Select configuration mode:"
    echo "[1] Default config (use settings from Config/udhcpd_def.conf)"
    echo "[2] Custom config (customize subnet, DNS server)"
    
    # Then ask for input
    read -p "Enter selection (1-2) [1]: " u_ans
    u_ans=${u_ans:-1}

    if [ "$u_ans" = "2" ]; then
        read -p "Enter subnet: " subnet
        oct=$(echo $subnet | cut -d' ' -f1)
        
        # First display DNS options
        echo -e "\nAvailable DNS servers:"
        dns_options=("8.8.8.8 (Google)" "1.1.1.1 (Cloudflare)" "9.9.9.9 (Quad9)" "208.67.222.222 (OpenDNS)" "Local (192.168.$oct.1)" "Custom")
        
        for ((i=0; i<${#dns_options[@]}; i++)); do
            echo "[$((i+1))] ${dns_options[i]}"
        done
        
        # Then ask for selection
        valid=false
        
        while [ "$valid" = false ]; do
            read -p "Enter DNS selection (1-${#dns_options[@]}) [1]: " selection
            selection=${selection:-1}
            if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#dns_options[@]}" ]; then
                valid=true
            else
                echo "Invalid selection. Please enter a number between 1 and ${#dns_options[@]}."
            fi
        done
        
        selected_dns="${dns_options[$((selection-1))]}"
        
        if [[ "$selected_dns" == "Custom" ]]; then
            read -p "Enter custom DNS server IP: " dns
        elif [[ "$selected_dns" == "Local (192.168.$oct.1)" ]]; then
            dns="192.168.$oct.1"
        else
            dns=$(echo $selected_dns | cut -d' ' -f1)
        fi
        
        # Create DHCP server config
        UdhcpdCode="start 192.168.$oct.2\nend 192.168.$oct.254\ninterface $interface\nopt dns $dns\noption subnet 255.255.255.0\noption router 192.168.$oct.1\noption lease 864000"
        echo -e "$UdhcpdCode" | sudo tee Config/udhcpd.conf > /dev/null
        udhcpd_conf="Config/udhcpd.conf"
        echo "Custom udhcpd configuration created successfully."
    else
        # Default configuration
        sed -i "/interface/c interface $interface" Config/udhcpd_def.conf
        oct="10"  # Default value from original script
        udhcpd_conf="Config/udhcpd_def.conf"
        echo "Using default udhcpd configuration with interface $interface."
    fi
    
    return 0
}

# Function to configure Internet sharing
configure_internet_sharing() {
    echo -e "\n=== Internet Sharing Setup ==="
    echo "Internet sharing allows clients connected to your access point to"
    echo "access the internet through another network interface on this device."
    echo
    
    # Display options first
    echo "Select option:"
    echo "[1] No internet sharing (access point only)"
    echo "[2] Enable internet sharing"
    
    # Then ask for input
    read -p "Enter selection (1-2) [1]: " inet_choice
    inet_choice=${inet_choice:-1}
    
    if [[ $inet_choice == "2" ]]; then
        # Get available interfaces excluding the AP interface
        mapfile -t interfaces < <(ip -o link show | grep -v lo | grep -v $interface | awk -F': ' '{print $2}')
        
        if [ ${#interfaces[@]} -eq 0 ]; then
            echo "No other network interfaces found for internet sharing."
            return
        fi
        
        # First display interfaces
        echo -e "\nAvailable interfaces for internet sharing (the interface connected to internet):"
        for ((i=0; i<${#interfaces[@]}; i++)); do
            echo "[$((i+1))] ${interfaces[i]}"
        done
        
        # Then ask for selection
        local valid=false
        local selection
        
        while [ "$valid" = false ]; do
            read -p "Enter selection number (1-${#interfaces[@]}): " selection
            if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#interfaces[@]}" ]; then
                valid=true
            else
                echo "Invalid selection. Please enter a number between 1 and ${#interfaces[@]}."
            fi
        done
        
        source_interface="${interfaces[$((selection-1))]}"
        
        echo "Enabling IP forwarding..."
        sudo sysctl -w net.ipv4.ip_forward=1 &>/dev/null
        
        echo "Setting up iptables rules for NAT..."
        sudo iptables -t nat -A POSTROUTING -o $source_interface -j MASQUERADE
        sudo iptables -A FORWARD -i $source_interface -o $interface -m state --state RELATED,ESTABLISHED -j ACCEPT
        sudo iptables -A FORWARD -i $interface -o $source_interface -j ACCEPT
        
        echo "Internet sharing enabled from $source_interface to $interface"
    else
        source_interface=""
        echo "Internet sharing disabled."
    fi
}

# Function to configure DNS Spoofing
configure_dns_spoofing() {
  echo -e "\n=== DNS Spoofing Configuration ==="
  echo "DNS spoofing redirects specific domain requests to your specified IP address."
  echo
  # Display options first
  echo "Select option:"
  echo "[1] No DNS spoofing"
  echo "[2] Enable DNS spoofing"
  # Then ask for input
  read -p "Enter selection (1-2) [1]: " dns_choice
  dns_choice=${dns_choice:-1}
  
  if [[ $dns_choice == "2" ]]; then
    echo "Using local DNS server (dnsmasq) for DNS spoofing"
    sed -i "/opt dns/c opt dns 192.168.${oct}.1" Config/dnsmasq.conf
    
    # Check for existing configuration
    if grep -q "address=" Config/dnsmasq.conf; then
      echo -e "\nCurrent DNS spoofing configuration:"
      grep "address=" Config/dnsmasq.conf
      echo
      read -p "Use this configuration? (y/n) [y]: " use_existing
      use_existing=${use_existing:-y}
      
      if [[ $use_existing != "y" ]]; then
        # Create new configuration from scratch
        echo "server=8.8.8.8" > Config/dnsmasq.conf
        
        # Support multiple entries
        echo "Enter domain and IP pairs for spoofing (enter '/' when finished)"
        while true; do
          read -p "Enter domain to spoof (e.g., .example.com) or '/' to finish: " spoof_domain
          if [[ $spoof_domain == "/" ]]; then
            break
          fi
          read -p "Enter IP address to redirect to: " spoof_ip
          # Add to dnsmasq.conf
          echo "address=/${spoof_domain}/${spoof_ip}" >> Config/dnsmasq.conf
          echo "Added: ${spoof_domain} -> ${spoof_ip}"
        done
      fi
    else
      # No existing config, create new one
      echo "server=8.8.8.8" > Config/dnsmasq.conf
      
      # Support multiple entries
      echo "Enter domain and IP pairs for spoofing (enter '/' when finished)"
      while true; do
        read -p "Enter domain to spoof (e.g., .example.com) or '/' to finish: " spoof_domain
        if [[ $spoof_domain == "/" ]]; then
          break
        fi
        read -p "Enter IP address to redirect to: " spoof_ip
        # Add to dnsmasq.conf
        echo "address=/${spoof_domain}/${spoof_ip}" >> Config/dnsmasq.conf
        echo "Added: ${spoof_domain} -> ${spoof_ip}"
      done
    fi
    return 0
  else
    echo "DNS spoofing disabled."
    return 1
  fi
}

# Function to configure packet capture
configure_packet_capture() {
    echo -e "\n=== Packet Capture Configuration ==="
    echo "Packet capture allows you to record network traffic for analysis."
    echo
    
    # Check if tshark is installed
    if ! command -v tshark &> /dev/null; then
        echo "Error: tshark is required for packet capture but not installed."
        read -p "Install tshark now? (y/n): " install_tshark
        if [ "$install_tshark" = "y" ]; then
            sudo apt install tshark -y
        else
            echo "Packet capture disabled."
            return 1
        fi
    fi
    
    # Display options first
    echo "Select option:"
    echo "[1] No packet capture"
    echo "[2] Enable packet capture"
    
    # Then ask for input
    read -p "Enter selection (1-2) [1]: " capture_choice
    capture_choice=${capture_choice:-1}
    
    if [[ $capture_choice == "2" ]]; then
        echo "Packet capture will be saved to capture.pcap"
        return 0
    else
        echo "Packet capture disabled."
        return 1
    fi
}

# Function to configure monitor mode
configure_monitor_mode() {
    echo -e "\n=== Monitor Mode Configuration ==="
    echo "Monitor mode allows the interface to capture packets without being associated with an AP."
    echo "Note: This is generally not needed for a functioning access point."
    echo
    
    # Display options first
    echo "Select option:"
    echo "[1] No monitor mode (recommended for AP functionality)"
    echo "[2] Enable monitor mode"
    
    # Then ask for input
    read -p "Enter selection (1-2) [1]: " monitor_choice
    monitor_choice=${monitor_choice:-1}
    
    if [[ $monitor_choice == "2" ]]; then
        echo "Warning: Enabling monitor mode may interfere with AP functionality."
        read -p "Continue? (y/n) [n]: " confirm
        confirm=${confirm:-n}
        
        if [[ $confirm == "y" ]]; then
            echo "Setting $interface to monitor mode..."
            sudo ifconfig $interface down
            sudo iwconfig $interface mode monitor
            sudo ifconfig $interface up
            echo "Monitor mode enabled on $interface."
            return 0
        fi
    fi
    
    echo "Monitor mode disabled."
    return 1
}

# Main script execution
show_default_config

# Configure the wireless access point
configure_hostapd

# Configure the DHCP server
configure_udhcpd

# Configure optional features
dns_spoofing=0
packet_capture=0
monitor_mode=0

# Configure monitor mode (this should be first as it changes interface mode)
configure_monitor_mode
monitor_mode=$?

# Configure DNS spoofing
configure_dns_spoofing
dns_spoofing=$?

# Configure packet capture
configure_packet_capture
packet_capture=$?

# Configure internet sharing
configure_internet_sharing

# Configure the interface
echo -e "\n=== Configuring Interface ==="
echo "Setting up interface $interface with IP address 192.168.$oct.1"
sudo ifconfig $interface down
sudo nmcli device set $interface managed no 2>/dev/null
sudo ifconfig $interface 192.168.$oct.1 up

if [ $? -ne 0 ]; then
    echo "Error: Failed to configure interface $interface"
    exit 1
fi

# Start services
echo -e "\n=== Starting Services ==="
echo "Starting hostapd (Access Point)..."
sudo hostapd -B $hostapd_conf
if [ $? -ne 0 ]; then
    echo "Error: Failed to start hostapd. Check configuration."
    exit 1
fi
hostapd_pid=$(pgrep -f "hostapd $hostapd_conf")

echo "Starting udhcpd (DHCP server)..."
sudo udhcpd -f $udhcpd_conf &
if [ $? -ne 0 ]; then
    echo "Error: Failed to start udhcpd. Check configuration."
    sudo kill $hostapd_pid
    exit 1
fi
udhcpd_pid=$!

# Start packet capture if enabled
if [ $packet_capture -eq 0 ]; then
    echo "Starting packet capture..."
    tshark -i $interface -w capture.pcap > /dev/null 2>&1 &
fi

# Start DNS spoofing if enabled
if [ $dns_spoofing -eq 0 ]; then
    echo "Starting dnsmasq (DNS spoofing)..."
    sudo dnsmasq -C Config/dnsmasq.conf &
    dnsmasq_pid=$!
fi

# Display summary of configuration
ssid=$(grep "ssid=" $hostapd_conf | cut -d'=' -f2)
password_set=$(grep "wpa_passphrase" $hostapd_conf)

echo -e "\n=== SUMMARY: Access Point Active ==="
echo "Interface: $interface"
echo "SSID: $ssid"
echo "IP Address: 192.168.$oct.1"

if [ -n "$password_set" ]; then
    pwd=$(grep "wpa_passphrase" $hostapd_conf | cut -d'=' -f2)
    echo "Security: WPA2-PSK (Password-protected)"
    echo "Password: $pwd"
else
    echo "Security: Open (No password)"
fi

if [ -n "$source_interface" ]; then
    echo "Internet sharing: Enabled (from $source_interface)"
else
    echo "Internet sharing: Disabled"
fi

echo -e "\nClients will get IPs in range: 192.168.$oct.2 - 192.168.$oct.254"
echo "DNS Server: $(grep "opt dns" $udhcpd_conf | awk '{print $3}')"

if [ $dns_spoofing -eq 0 ]; then
    echo "DNS Spoofing: Enabled"
    echo "Spoofed domains: $(grep "address=" Config/dnsmasq.conf | cut -d'=' -f2 | cut -d'/' -f2)"
else
    echo "DNS Spoofing: Disabled"
fi

if [ $packet_capture -eq 0 ]; then
    echo "Packet Capture: Enabled (saving to capture.pcap)"
else
    echo "Packet Capture: Disabled"
fi

if [ $monitor_mode -eq 0 ]; then
    echo "Monitor Mode: Enabled"
else
    echo "Monitor Mode: Disabled"
fi

echo -e "\nServices running. Press Ctrl+C to stop."

# Wait for the udhcpd process to finish - this will run until Ctrl+C is pressed
wait $udhcpd_pid