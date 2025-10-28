#!/bin/bash

# TimeScope - Advanced Historical Subdomain Enumeration Tool
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║             TimeScope               ║"
echo "║    Historical Subdomain Hunter      ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# Check if domain is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <domain>${NC}"
    echo -e "${YELLOW}Example: $0 example.com${NC}"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="timescope-$DOMAIN-$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}[+] Starting TimeScope for: $DOMAIN${NC}"
echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${NC}"

# Function to check dependencies
check_dependencies() {
    local deps=("curl" "jq" "dig" "whois" "waybackurls" "gau" "subfinder" "assetfinder")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}[!] Install with:"
        echo "    sudo apt install curl jq dnsutils whois"
        echo "    go install github.com/tomnomnom/waybackurls@latest"
        echo "    go install github.com/lc/gau/v2/cmd/gau@latest"
        echo "    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "    go install github.com/tomnomnom/assetfinder@latest${NC}"
        exit 1
    fi
}

# Historical DNS Records from multiple sources
historical_dns() {
    echo -e "${BLUE}[1] Searching Historical DNS Records...${NC}"
    
    # SecurityTrails API (free tier)
    if [ -n "$SECURITYTRAILS_API" ]; then
        echo -e "${YELLOW}    ↳ Querying SecurityTrails...${NC}"
        curl -s "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" \
            -H "APIKEY: $SECURITYTRAILS_API" | jq -r '.records[].values[].ip' 2>/dev/null | sort -u > "$OUTPUT_DIR/historical_ips.txt"
    fi
    
    # ViewDNS.info historical data
    echo -e "${YELLOW}    ↳ Checking ViewDNS.info...${NC}"
    curl -s "https://api.viewdns.info/history/?domain=$DOMAIN&apikey=your_key&output=json" | jq -r '.response.records[].ip' 2>/dev/null >> "$OUTPUT_DIR/historical_ips.txt"
}

# Wayback Machine Analysis
wayback_analysis() {
    echo -e "${BLUE}[2] Analyzing Wayback Machine Archives...${NC}"
    
    echo -e "${YELLOW}    ↳ Extracting URLs from Wayback Machine...${NC}"
    waybackurls "$DOMAIN" | tee "$OUTPUT_DIR/wayback_urls.txt"
    
    echo -e "${YELLOW}    ↳ Extracting from Common Crawl...${NC}"
    gau "$DOMAIN" | tee "$OUTPUT_DIR/gau_urls.txt"
    
    # Extract subdomains from URLs
    cat "$OUTPUT_DIR/wayback_urls.txt" "$OUTPUT_DIR/gau_urls.txt" | \
    grep -oE "[a-zA-Z0-9.-]+\.$DOMAIN" | \
    sort -u > "$OUTPUT_DIR/historical_subs.txt"
}

# TLS Certificate History
certificate_history() {
    echo -e "${BLUE}[3] Analyzing TLS Certificate History...${NC}"
    
    # Crtsh - Certificate Transparency
    echo -e "${YELLOW}    ↳ Querying crt.sh...${NC}"
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | \
    sed 's/\*\.//g' | sort -u > "$OUTPUT_DIR/cert_subs.txt"
    
    # Cert Spotter
    echo -e "${YELLOW}    ↳ Checking Cert Spotter...${NC}"
    curl -s "https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names" | \
    jq -r '.[].dns_names[]' | sed 's/\*\.//g' | sort -u >> "$OUTPUT_DIR/cert_subs.txt"
}

# DNS Archive Services
dns_archives() {
    echo -e "${BLUE}[4] Checking DNS Archives...${NC}"
    
    # DNSDumpster
    echo -e "${YELLOW}    ↳ Querying DNSDumpster...${NC}"
    curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" | \
    cut -d',' -f1 | sort -u > "$OUTPUT_DIR/dnsdumpster_subs.txt"
    
    # AlienVault OTX
    echo -e "${YELLOW}    ↳ Checking AlienVault OTX...${NC}"
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" | \
    jq -r '.passive_dns[].hostname' | sort -u > "$OUTPUT_DIR/otx_subs.txt"
}

# Traditional Enumeration (for comparison)
traditional_enum() {
    echo -e "${BLUE}[5] Running Traditional Enumeration...${NC}"
    
    echo -e "${YELLOW}    ↳ Running SubFinder...${NC}"
    subfinder -d "$DOMAIN" -silent > "$OUTPUT_DIR/subfinder_subs.txt"
    
    echo -e "${YELLOW}    ↳ Running AssetFinder...${NC}"
    assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/assetfinder_subs.txt"
}

# DNS Record Analysis
dns_analysis() {
    echo -e "${BLUE}[6] Deep DNS Record Analysis...${NC}"
    
    # Check for TLSA records specifically
    echo -e "${YELLOW}    ↳ Analyzing TLSA Records...${NC}"
    dig +short _443._tcp.$DOMAIN TLSA > "$OUTPUT_DIR/tlsa_records.txt"
    
    # Comprehensive DNS queries
    local record_types=("A" "AAAA" "MX" "TXT" "CNAME" "NS" "SOA" "SRV" "CAA" "DS" "DNSKEY")
    
    for record in "${record_types[@]}"; do
        echo -e "${PURPLE}    ↳ Querying $record records...${NC}"
        dig +short "$DOMAIN" "$record" >> "$OUTPUT_DIR/all_dns_records.txt"
    done
}

# Data Correlation and Analysis
correlate_data() {
    echo -e "${BLUE}[7] Correlating and Analyzing Data...${NC}"
    
    # Combine all subdomains
    cat "$OUTPUT_DIR/historical_subs.txt" \
        "$OUTPUT_DIR/cert_subs.txt" \
        "$OUTPUT_DIR/dnsdumpster_subs.txt" \
        "$OUTPUT_DIR/otx_subs.txt" \
        "$OUTPUT_DIR/subfinder_subs.txt" \
        "$OUTPUT_DIR/assetfinder_subs.txt" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/all_subdomains.txt"
    
    # Remove invalid entries and clean up
    grep -E "^[a-zA-Z0-9.-]+\.$DOMAIN$" "$OUTPUT_DIR/all_subdomains.txt" | \
    sort -u > "$OUTPUT_DIR/valid_subdomains.txt"
    
    # Count statistics
    local total=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt")
    local valid=$(wc -l < "$OUTPUT_DIR/valid_subdomains.txt")
    
    echo -e "${GREEN}[+] Found $total total subdomains${NC}"
    echo -e "${GREEN}[+] $valid valid subdomains after cleanup${NC}"
}

# Generate Report
generate_report() {
    echo -e "${BLUE}[8] Generating Final Report...${NC}"
    
    cat > "$OUTPUT_DIR/report.md" << EOF
# TimeScope Report for $DOMAIN
**Generated:** $(date)

## Summary
- **Total Subdomains Found:** $(wc -l < "$OUTPUT_DIR/all_subdomains.txt")
- **Valid Subdomains:** $(wc -l < "$OUTPUT_DIR/valid_subdomains.txt")
- **Historical IPs:** $(wc -l < "$OUTPUT_DIR/historical_ips.txt" 2>/dev/null || echo "0")

## Sources
- Wayback Machine: $(wc -l < "$OUTPUT_DIR/wayback_urls.txt")
- Certificate Transparency: $(wc -l < "$OUTPUT_DIR/cert_subs.txt")
- DNS Archives: $(wc -l < "$OUTPUT_DIR/dnsdumpster_subs.txt")
- Traditional Enumeration: $(wc -l < "$OUTPUT_DIR/subfinder_subs.txt")

## Unique Findings
### Historical Subdomains
$(comm -23 "$OUTPUT_DIR/historical_subs.txt" "$OUTPUT_DIR/subfinder_subs.txt" 2>/dev/null | head -20)

### Certificate-Only Subdomains  
$(comm -23 "$OUTPUT_DIR/cert_subs.txt" "$OUTPUT_DIR/subfinder_subs.txt" 2>/dev/null | head -20)

## Recommendations
- Investigate historical subdomains for forgotten infrastructure
- Check TLS certificates for exposed internal systems
- Monitor for reappearance of archived subdomains

EOF

    echo -e "${GREEN}[+] Report saved to: $OUTPUT_DIR/report.md${NC}"
}

# Main execution
main() {
    check_dependencies
    
    echo -e "${CYAN}[+] Starting Deep Historical Recon...${NC}"
    
    historical_dns
    wayback_analysis
    certificate_history
    dns_archives
    traditional_enum
    dns_analysis
    correlate_data
    generate_report
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════╗"
    echo "║           Scan Complete!            ║"
    echo "║    Check $OUTPUT_DIR for results   ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Show unique historical findings
    echo -e "${YELLOW}[!] Unique Historical Subdomains Found:${NC}"
    comm -23 "$OUTPUT_DIR/historical_subs.txt" "$OUTPUT_DIR/subfinder_subs.txt" 2>/dev/null | head -10
}

# Run main function
main "$@"
