# IoT Device Security Scanner

An automated tool for discovering IoT devices on a local network and performing security assessments using Nmap and Flask.

## Features
- **Network Discovery**: Scans IP ranges to find active devices.
- **Security Assessment**: Detailed port scanning and OS detection.
- **Risk Analysis**: Heuristic-based risk levels (Low/Medium/High) for open services.
- **History**: Save scan results to a MySQL/XAMPP database for later review.

## Setup
1. **Prerequisites**: 
   - Install [Nmap](https://nmap.org/download.html).
   - MySQL/XAMPP server running.
2. **Installation**:
   pip install -r requirements.txt
