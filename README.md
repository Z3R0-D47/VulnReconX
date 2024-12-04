# VulnReconX
VulnReconX is a network vulnerability scanning tool that allows users to scan IP addresses or networks for open ports, services, and vulnerabilities. It provides detailed scan results, vulnerability information, recommendations for securing services, and support for notifications. This tool uses `nmap` for network scanning and stores recommendations and vulnerabilities in a local `SQLite` database.

## Features

- Scan IP addresses or entire networks
- Verbose mode for detailed scanning output
- OS detection and service version detection
- Color-coded vulnerability severity (High, Medium, Low)
- Integration with a local database for vulnerability recommendations and further investigation details
- Notifications on scan completion
- Save scan results to a file

## Requirements

- Python 3.x
- Dependencies:
  - `nmap` (installed separately)
  - `psutil` (for network interface detection)
  - `plyer` (for desktop notifications)
  - `sqlite3` (included with Python)
  - `pywin32` (enables Windows-specific functionalities)

  
You can install the dependencies using `pip`:

```bash
pip install psutil plyer pywin32
```

Ensure that `nmap` is installed on your system. For installation instructions, refer to [nmap official site](https://nmap.org/).

## Setup
1. Clone this repository:
```bash
git clone https://github.com/Z3R0-D47/VulnReconX.git
cd VulnReconX
```

2. Run the main.py or equivalent script to start the GUI:
```bash
python main.py
```
Ensure that `nmap` is available in your system's PATH.

## Usage
- **Scan a Target**: Enter an IP address or network in the input field and click "Scan Target IP".
- **Scan Your Own IP**: Click the "Scan Own IP" button to automatically scan your machine's IP address.
- **Configure Scan Options**: Choose additional scan options (verbose mode, OS detection, service version detection) through the "Configure Scan" button.
- **Save Results**: After the scan is complete, you can save the results to a file by clicking the "Save Results" button.

## Limitations
1. Operating System Compatibility: The database is only compatible with Windows environments, limiting its use across diverse systems like Linux and macOS.
2. Local Storage for Recommendations: The tool relies on local storage for storing vulnerability recommendations, which may affect efficiency and scalability when handling large datasets.
3. Dependency on Nmap: The tool heavily relies on Nmap for vulnerability scanning, which may not detect vulnerabilities in specialized or custom systems that require more detailed, customized assessments.

## Contributing
1. Fork the repository
2. Create your feature branch `(git checkout -b feature-name)`
3. Commit your changes `(git commit -am 'Add feature')`
4. Push to the branch `(git push origin feature-name)`
5. Create a new Pull Request
