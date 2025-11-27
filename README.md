# detect-shai-hulud

A bash security scanner that detects indicators of compromise from the malicious "shai-hulud" NPM package attack.

## What does it do?

This script scans your system for evidence of a malicious NPM package attack that:
- Installs malicious `bun_environment.js` files in node_modules
- Downloads Trufflehog binaries to scan for secrets
- Creates hidden `.truffler-cache` directories
- Potentially runs destructive commands on your system

## Requirements

- Linux or macOS
- Bash shell
- Standard Unix utilities (find, grep, ps)

## Usage

### Basic scan (current directory)

```bash
chmod +x detect_iocs.sh
./detect_iocs.sh
```

### Scan a specific directory

```bash
SCAN_PATH=/path/to/your/projects ./detect_iocs.sh
```

### Skip additional checks (faster scan)

```bash
SKIP_ADDITIONAL=1 ./detect_iocs.sh
```

## What it scans for

1. **Malicious files** - `bun_environment.js` post-install scripts in node_modules
2. **Hidden directories** - `.truffler-cache` folders storing attack tools
3. **Malicious binaries** - Trufflehog executables in common locations
4. **Suspicious processes** - Running destructive commands or secret scanners
5. **Command history** - Evidence of malicious commands in bash/zsh history
6. **System logs** - Log entries indicating suspicious activity

## Results

- **Green (OK)**: No indicators found
- **Yellow (WARNING)**: Potential issues detected
- **Red (CRITICAL)**: Definite indicators of compromise found

If the script finds any indicators of compromise (exit code 1), follow the recommended actions displayed at the end of the scan.

## Recommended actions if compromised

1. Immediately disconnect from the network
2. Run a full antivirus scan
3. Rotate all credentials and API keys
4. Review recent npm package installations
5. Reinstall npm packages from clean sources
6. Monitor system for unusual activity
7. Report to your security team

## Author

Original script by [Bram Kaashoek](https://github.com/BramKaashoek)

Updated by [Sander Korf](https://github.com/sanderkorf)

## License

MIT License - See [LICENSE](./LICENSE) file for details