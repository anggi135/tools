#!/bin/bash

# Warna
RED="\e[91m"
GREEN="\e[92m"
YELLOW="\e[93m"
BLUE="\e[94m"
MAGENTA="\e[95m"
CYAN="\e[96m"
RESET="\e[0m"
BOLD="\e[1m"

# Argument parsing
url=""
wordlist=""
random_agent=false

usage() {
    echo -e "${YELLOW}Usage:${RESET} $0 [-u <url>] [-w <wordlist.txt>] [--random-agent]"
    exit 1
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -u) url="$2"; shift ;;
        -w) wordlist="$2"; shift ;;
        --random-agent) random_agent=true ;;
        *) usage ;;
    esac
    shift
done

if [[ -z "$url" && -z "$wordlist" ]]; then
    echo -e "${RED}[ERROR]${RESET} Anda harus menggunakan -u <url> atau -w <wordlist.txt>"
    usage
fi

# Fungsi pemindai
scan_host() {
    local host="$1"
    local useragent="Mozilla/5.0"
    if $random_agent; then
        useragent=$(curl -s 'https://fake-useragent.deno.dev/random')
    fi

    # Ping
    ping -c 1 -W 2 "$host" &>/dev/null
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[×] $host TIDAK responsif (down), dilewati.${RESET}"
        return
    fi

    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${BLUE}[+] Host: $host${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"

    # Teknologi Web
    if echo "$open_ports" | grep -q -E '80|443|8080'; then
        echo -e "${MAGENTA}🛠️  Teknologi Web:${RESET}"
        whatweb_out=$(whatweb -U "$useragent" "$host" 2>/dev/null)
        techs=$(echo "$whatweb_out" | cut -d " " -f 2-)
        echo -e "  ➜ ${GREEN}$techs${RESET}"
    fi

    # Deteksi WAF
    echo -e "${MAGENTA}🛡️  Deteksi WAF:${RESET}"
    waf=$(wafw00f "$host" 2>/dev/null | grep -i "is behind" || echo "  ➜ ${YELLOW}Tidak terdeteksi WAF${RESET}")
    echo -e "  ➜ $waf"

    # Parameter URL
    echo -e "${MAGENTA}🔍 Parameter URL yang ditemukan:${RESET}"
    urls=$(curl -sL "$host" | grep -Eo 'https?://[^"]+\?[^"]+' | sed 's/&/\n  &/g' | sort -u)
    if [[ -z "$urls" ]]; then
        echo -e "  ➜ ${YELLOW}Tidak ada URL parameter ditemukan.${RESET}"
    else
        echo "$urls" | sed 's/^/  ➜ /'
    fi
}

# Main
if [[ -n "$url" ]]; then
    scan_host "$url"
elif [[ -n "$wordlist" ]]; then
    while read -r domain; do
        [[ -z "$domain" ]] && continue
        scan_host "$domain"
    done < "$wordlist"
fi
