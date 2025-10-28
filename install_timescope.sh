#!/bin/bash

echo "Installing TimeScope Dependencies..."

# System packages
sudo apt update
sudo apt install -y curl jq dnsutils whois git

# Go tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest

# Copy to PATH
sudo cp timescope.sh /usr/local/bin/timescope
sudo chmod +x /usr/local/bin/timescope

echo "Installation complete!"
echo "Get a free SecurityTrails API key and set it as:"
echo "export SECURITYTRAILS_API=your_api_key_here"
