# 🚀 Complete Recon Automation Framework

A comprehensive reconnaissance automation framework for bug bounty hunting and security research. This tool orchestrates multiple security tools to perform thorough reconnaissance on target domains.

## 📋 Features

### 🔍 **Reconnaissance Capabilities**
- **Service Discovery**: HTTP/HTTPS service detection with httpx
- **Subdomain Enumeration**: Multiple tools (subfinder, assetfinder, amass, shuffledns, crt.sh)
- **Vulnerability Scanning**: 
  - XSS detection (kxss, dalfox)
  - SQL injection (sqlmap)
  - LFI/RFI detection (ffuf with payloads)
  - CORS misconfiguration (Corsy)
  - Open redirect detection (OpenRedireX)
  - Nuclei templates scanning
- **Pattern Analysis**: GF patterns for various vulnerability types
- **Wordlist Generation**: Custom wordlists from target URLs
- **Subdomain Takeover**: Detection with subzy and subjack

### 🎯 **Two Reconnaissance Modes**
1. **Single Target**: Focused reconnaissance on a single domain
2. **Massive Recon**: Complete reconnaissance including subdomain enumeration

### ⚙️ **Modular Design**
- Disable specific scan types with `--no-*` flags
- Comprehensive logging support
- Organized output structure
- Progress tracking and timing

## 🛠️ Installation

### Prerequisites
```bash
# Required base tools
sudo apt update
sudo apt install -y git curl wget python3 python3-pip golang-go
```

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/baarai/recon-bug-hunting.git
cd recon-bug-hunting

# Make scripts executable
chmod +x install.sh script.sh

# Run the installer
./install.sh
```

### Manual Installation
The installer will automatically install and configure:
- **Go tools**: assetfinder, gau, qsreplace, gf, subfinder, nuclei, httpx, ffuf, dalfox, kxss
- **Python tools**: Corsy, OpenRedireX, ParamSpider, Arjun
- **System tools**: amass, sqlmap, jq, seclists
- **DNS tools**: massdns, shuffledns, dnsvalidator
- **Takeover tools**: subzy, subjack

## 🚀 Usage

### Basic Usage
```bash
# Interactive menu
./script.sh

# Single target reconnaissance
./script.sh --no-xss --no-nuclei

# With logging
./script.sh --log recon.log
```

### Command Line Options
```bash
./script.sh [options]

Options:
  --log file.log         Log all output to file.log
  --help                Display help and exit
  --no-xss              Disable XSS detection
  --no-sqli             Disable SQLi detection
  --no-lfi              Disable LFI detection
  --no-nuclei           Disable Nuclei scan
  --no-cors             Disable CORS misconfig detection
  --no-openredirect     Disable Open Redirect detection
  --no-gf               Disable Gf patterns analysis
  --no-ffuf             Disable FFUF scan
  --no-wordlist         Disable target wordlist generation
  --no-service          Disable service detection (httpx)
  --no-urls             Disable URL collection (gau)
```

### Examples
```bash
# Quick scan (skip heavy tools)
./script.sh --no-xss --no-sqli --no-nuclei

# Full reconnaissance with logging
./script.sh --log full_recon.log

# Only service discovery and CORS
./script.sh --no-ffuf --no-gf --no-xss --no-sqli --no-lfi --no-nuclei --no-openredirect
```

## 📁 Output Structure

```
target_domain/
├── httpx.txt                    # Live services
├── summary.txt                  # Scan summary
├── vulnerabilities/
│   ├── cors/
│   │   └── cors_misconfig.txt
│   ├── xss_scan/
│   │   ├── kxss.txt
│   │   ├── dalfoxss.txt
│   │   └── vulnxss.txt
│   ├── sqli/
│   │   └── sqlmap.txt
│   ├── LFI/
│   │   └── lfi.txt
│   └── openredirect/
│       └── confirmopenred.txt
├── nuclei_scan/
│   └── all.txt
├── gf/
│   ├── xss.txt
│   ├── sqli.txt
│   ├── lfi.txt
│   └── redirect.txt
├── target_wordlist/
│   ├── paths.txt
│   └── params.txt
└── domain_enum/                 # Massive recon only
    ├── subfinder.txt
    ├── assetfinder.txt
    ├── amass.txt
    └── all.txt
```

## 🔧 Configuration

### Tool Paths
The script uses the following default paths:
```bash
TOOLS_DIR="$HOME/tools"
CORSY="$TOOLS_DIR/Corsy/corsy.py"
OPENREDIREX="$TOOLS_DIR/OpenRedireX/openredirex.py"
LFI_PAYLOADS="$TOOLS_DIR/lfipayloads.txt"
RESOLVERS="$TOOLS_DIR/resolvers/resolver.txt"
NUCLEI_TEMPLATES="$TOOLS_DIR/nuclei-templates/"
```

### Customization
Edit the configuration variables at the top of `script.sh` to modify:
- Tool paths
- Thread counts
- Timeout values
- Output directories

## 🛡️ Security Considerations

### Legal Usage
- **Only use on authorized targets**
- **Respect scope and rules of engagement**
- **Follow responsible disclosure practices**
- **Comply with local laws and regulations**

### Best Practices
- Run in isolated environments
- Use dedicated VMs for testing
- Monitor network activity
- Keep tools updated
- Review findings before reporting

## 🐛 Troubleshooting

### Common Issues

**Missing Dependencies**
```bash
# Re-run installer
./install.sh

# Check specific tool
which httpx
which nuclei
```

**Permission Errors**
```bash
# Fix permissions
chmod +x install.sh script.sh
sudo chown -R $USER:$USER ~/tools
```

**Go Path Issues**
```bash
# Add to PATH
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

**Empty Results**
- Check if target is accessible
- Verify DNS resolution
- Review tool configurations
- Check firewall settings

### Debug Mode
```bash
# Enable verbose output
bash -x ./script.sh
```

## 📊 Performance Tips

### Optimization
- Use `--no-*` flags to skip unnecessary scans
- Run heavy scans separately
- Use SSD storage for better I/O
- Increase system resources for large targets

### Resource Management
- Monitor CPU/memory usage
- Use appropriate thread counts
- Clean up temporary files
- Limit concurrent scans

## 🤝 Contributing

### Development
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Bug Reports
- Include error messages
- Provide reproduction steps
- Specify environment details
- Attach relevant logs

### Feature Requests
- Describe the use case
- Explain the benefit
- Consider implementation complexity
- Provide examples

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **ProjectDiscovery** for nuclei and httpx
- **Tomnomnom** for assetfinder, gau, and gf
- **S0md3v** for Corsy and Arjun
- **Devanshbatham** for OpenRedireX and ParamSpider
- **Hahwul** for dalfox
- **Swisskyrepo** for PayloadsAllTheThings

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/recon-bug-hunting/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/recon-bug-hunting/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/recon-bug-hunting/wiki)

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.
