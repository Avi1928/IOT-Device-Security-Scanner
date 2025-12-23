from flask import Flask, render_template, request, jsonify
import nmap
import socket
import threading
import psutil
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import re
import platform
import mysql.connector
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Database Configuration ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'iot_scanner',
    'password': 'password123',
    'database': 'iot_security_scanner'
}

# XAMPP Default Configuration
XAMPP_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'iot_security_scanner'
}

def get_db_connection():
    """Create and return database connection with fallback to XAMPP defaults"""
    configs_to_try = [DB_CONFIG, XAMPP_CONFIG]
    
    for config in configs_to_try:
        try:
            conn = mysql.connector.connect(**config)
            return conn
        except mysql.connector.Error as e:
            # If database doesn't exist (Error 1049), try to create it using this config
            if e.errno == 1049:
                try:
                    temp_config = config.copy()
                    temp_config.pop('database')
                    temp_conn = mysql.connector.connect(**temp_config)
                    cursor = temp_conn.cursor()
                    cursor.execute(f"CREATE DATABASE {config['database']}")
                    cursor.close()
                    temp_conn.close()
                    logger.info(f"Created database {config['database']} using user {config['user']}")
                    # Retry connection with database
                    return mysql.connector.connect(**config)
                except Exception as create_error:
                    logger.warning(f"Failed to create database with user {config['user']}: {create_error}")
            else:
                logger.warning(f"Connection failed for user {config['user']}: {e}")
    
    logger.error("All database connection attempts failed.")
    return None

def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    target_range VARCHAR(255) NOT NULL,
                    scan_type ENUM('discovery', 'detailed') NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    devices_found INT DEFAULT 0,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME NULL,
                    duration_seconds INT DEFAULT 0,
                    saved_result BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Create devices table with IoT-specific fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id INT,
                    ip_address VARCHAR(45) NOT NULL,
                    hostname VARCHAR(255),
                    mac_address VARCHAR(17),
                    vendor VARCHAR(255),
                    os_info TEXT,
                    status ENUM('up', 'down', 'unknown') DEFAULT 'unknown',
                    device_type VARCHAR(50),
                    iot_category VARCHAR(50),
                    security_risk ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
                    vulnerabilities_found INT DEFAULT 0,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    INDEX idx_ip (ip_address),
                    INDEX idx_scan (scan_id)
                )
            ''')
            
            # Create ports table with IoT-specific fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    device_id INT,
                    port_number INT NOT NULL,
                    protocol VARCHAR(10) DEFAULT 'tcp',
                    state VARCHAR(20),
                    service_name VARCHAR(100),
                    service_version TEXT,
                    banner TEXT,
                    iot_service BOOLEAN DEFAULT FALSE,
                    security_issues TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
                    INDEX idx_device (device_id),
                    INDEX idx_port (port_number)
                )
            ''')
            
            conn.commit()
            logger.info("Database tables initialized successfully")
            
        except mysql.connector.Error as e:
            logger.error(f"Database initialization error: {e}")
        finally:
            cursor.close()
            conn.close()

# Initialize database on startup
init_database()

# --- Global State Management ---
scan_data = {}
scan_lock = threading.Lock()

detailed_scans = {}
detailed_lock = threading.Lock()

current_scan_id = None
active_scan_thread = None

def reset_scan_data():
    global scan_data, current_scan_id, active_scan_thread
    with scan_lock:
        scan_data.update({
            "status": "idle", 
            "progress": 0, 
            "phase": "Idle", 
            "results": {"devices": []},
            "current_device": "", 
            "scanned_devices": 0, 
            "total_devices": 0,
            "scan_id": None,
            "last_update": time.time()
        })
        current_scan_id = None
        active_scan_thread = None

reset_scan_data()

# --- Database Operations ---
def save_scan_session(target_range, scan_type, status, devices_found=0, duration=0):
    """Save scan session to database and return scan_id"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (target_range, scan_type, status, devices_found, duration_seconds)
            VALUES (%s, %s, %s, %s, %s)
        ''', (target_range, scan_type, status, devices_found, duration))
        
        scan_id = cursor.lastrowid
        conn.commit()
        logger.info(f"Saved scan session {scan_id} for target {target_range}")
        return scan_id
    except mysql.connector.Error as e:
        logger.error(f"Error saving scan session: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def mark_scan_as_saved(scan_id):
    """Mark a scan as saved in database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scans SET saved_result = TRUE WHERE id = %s
        ''', (scan_id,))
        conn.commit()
        return True
    except mysql.connector.Error as e:
        logger.error(f"Error marking scan as saved: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def update_scan_session(scan_id, status, devices_found=None, duration=None):
    """Update scan session status"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        if devices_found is not None and duration is not None:
            cursor.execute('''
                UPDATE scans SET status=%s, devices_found=%s, duration_seconds=%s, end_time=NOW()
                WHERE id=%s
            ''', (status, devices_found, duration, scan_id))
        else:
            cursor.execute('''
                UPDATE scans SET status=%s WHERE id=%s
            ''', (status, scan_id))
        
        conn.commit()
    except mysql.connector.Error as e:
        logger.error(f"Error updating scan session: {e}")
    finally:
        cursor.close()
        conn.close()

def save_device_discovery(scan_id, devices_list):
    """Save discovered devices to database"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        for device in devices_list:
            cursor.execute('''
                INSERT INTO devices (scan_id, ip_address, status, last_seen)
                VALUES (%s, %s, 'up', NOW())
                ON DUPLICATE KEY UPDATE status='up', last_seen=NOW()
            ''', (scan_id, device))
        
        conn.commit()
        logger.info(f"Saved {len(devices_list)} devices for scan {scan_id}")
    except mysql.connector.Error as e:
        logger.error(f"Error saving devices: {e}")
    finally:
        cursor.close()
        conn.close()

# --- Core Nmap Executor with Timeout ---
def run_nmap_with_timeout(hosts, arguments, timeout=120):
    """Executes Nmap as a subprocess with a strict timeout."""
    try:
        command = ['nmap', '-oX', '-'] + arguments.split() + [hosts]
        logger.info(f"Running command: {' '.join(command)}")
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        
        if proc.returncode != 0:
            logger.warning(f"Nmap returned non-zero exit code: {proc.returncode}")
            logger.warning(f"Stderr: {proc.stderr}")
            
        if "command not found" in proc.stderr.lower() or "not recognized" in proc.stderr.lower():
            logger.error("Nmap command not found")
            return "NOT_FOUND"
        
        if not proc.stdout:
            logger.error(f"No output from nmap for {hosts}")
            return "ERROR"
        
        scanner = nmap.PortScanner()
        scanner.analyse_nmap_xml_scan(proc.stdout)
        return scanner
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap scan timed out for host {hosts} with args '{arguments}'")
        return "TIMEOUT"
    except Exception as e:
        logger.error(f"Unexpected error in run_nmap_with_timeout: {e}")
        return "ERROR"

# --- Helper & Utility Functions ---
def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        for iface, addr_list in psutil.net_if_addrs().items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    netmask = addr.netmask
                    ip_interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
                    return str(ip_interface.network)
    except Exception as e:
        logger.error(f"Error getting local network: {e}")
        return "192.168.1.0/24"

def get_default_gateway():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("ipconfig", shell=True).decode()
            match = re.search(r"Default Gateway.*: ([\d.]+)", result)
            if match:
                return match.group(1)
        else:
            result = subprocess.check_output(["ip", "route"]).decode()
            match = re.search(r"default via ([\d.]+)", result)
            if match:
                return match.group(1)
    except Exception as e:
        logger.error(f"Error getting gateway: {e}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except:
            return "192.168.1.1"

def detect_iot_device_type(os_info, services):
    """Enhanced IoT device detection"""
    if not os_info:
        return "unknown", "general", "low"
    
    os_str = str(os_info).lower()
    services_str = str(services).lower()
    
    # IoT Device Categories
    if any(x in os_str for x in ['camera', 'dvr', 'nvr', 'surveillance']):
        return "security_camera", "surveillance", "high"
    elif any(x in os_str for x in ['router', 'gateway', 'access point']):
        return "router", "networking", "high"
    elif any(x in os_str for x in ['smart tv', 'roku', 'fire tv', 'android tv']):
        return "smart_tv", "entertainment", "medium"
    elif any(x in os_str for x in ['printer', 'epson', 'canon', 'hp']):
        return "printer", "office", "medium"
    elif any(x in os_str for x in ['thermostat', 'nest', 'ecobee']):
        return "thermostat", "home_automation", "high"
    elif any(x in os_str for x in ['light', 'bulb', 'philips hue']):
        return "smart_light", "home_automation", "low"
    elif any(x in os_str for x in ['speaker', 'alexa', 'google home']):
        return "smart_speaker", "entertainment", "medium"
    elif any(x in os_str for x in ['plug', 'outlet', 'switch']):
        return "smart_plug", "home_automation", "medium"
    elif any(x in os_str for x in ['sensor', 'motion', 'door', 'window']):
        return "sensor", "security", "high"
    elif any(x in services_str for x in ['upnp', 'ssdp', 'iot']):
        return "iot_device", "general", "medium"
    else:
        return "network_device", "general", "low"

def scan_single_device_fast(device):
    """Fast single device scan with optimized settings"""
    try:
        logger.info(f"Scanning device: {device}")
        # Use the subprocess method for better reliability
        scanner = run_nmap_with_timeout(device, '-sn -T4 --max-retries 1 --host-timeout 5s', timeout=10)
        
        if scanner == "TIMEOUT" or scanner == "ERROR":
            return device, False
            
        if isinstance(scanner, nmap.PortScanner):
            is_up = device in scanner.all_hosts()
            logger.info(f"Device {device} is {'up' if is_up else 'down'}")
            return device, is_up
        else:
            return device, False
            
    except Exception as e:
        logger.error(f"Error scanning device {device}: {e}")
        return device, False

# --- Background Scan Logic ---
def perform_discovery_scan(target):
    """Worker for initial device discovery with database saving"""
    global current_scan_id, active_scan_thread
    
    logger.info(f"Starting discovery scan for target: {target}")
    scan_start_time = time.time()
    
    # Reset scan data first
    reset_scan_data()
    
    # Create scan session
    current_scan_id = save_scan_session(target, 'discovery', 'running')
    if not current_scan_id:
        logger.warning("Failed to create scan session - continuing without database logging")
    
    with scan_lock:
        scan_data.update({
            "status": "running", 
            "phase": "Device Discovery", 
            "scan_id": current_scan_id,
            "progress": 0,
            "results": {"devices": []},
            "last_update": time.time()
        })
    
    try:
        # Handle single IP addresses as well as ranges
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                all_devices = [str(ip) for ip in network.hosts()]
                logger.info(f"Scanning network range: {target} with {len(all_devices)} devices")
            else:
                # Single IP address
                all_devices = [target]
                logger.info(f"Scanning single device: {target}")
        except ValueError as e:
            logger.error(f"Invalid target format {target}: {e}")
            # If it's a hostname or invalid format, treat as single target
            all_devices = [target]
            
        # Limit scan size for performance
        if len(all_devices) > 254:
            all_devices = all_devices[:254]
            logger.info(f"Limited scan to 254 devices")
            
        with scan_lock:
            scan_data["total_devices"] = len(all_devices)
        
        if not all_devices:
            logger.warning("No devices to scan")
            with scan_lock:
                scan_data["status"] = "done"
                scan_data["progress"] = 100
                scan_data["last_update"] = time.time()
            if current_scan_id:
                update_scan_session(current_scan_id, 'completed', 0, int(time.time() - scan_start_time))
            return

        discovered_devices = []
        
        # Use a more reliable scanning method with fewer workers
        logger.info(f"Starting scan with {len(all_devices)} devices")
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_device = {executor.submit(scan_single_device_fast, device): device for device in all_devices}
            
            for i, future in enumerate(as_completed(future_to_device)):
                device = future_to_device[future]
                try:
                    scanned_device, is_up = future.result()
                    if is_up:
                        discovered_devices.append(scanned_device)
                        # Update results in real-time
                        with scan_lock:
                            scan_data["results"]["devices"] = discovered_devices.copy()
                except Exception as e:
                    logger.error(f"Error processing device {device}: {e}")
                
                # Update progress with smooth increments
                progress = min(100, int(((i + 1) / len(all_devices)) * 100))
                with scan_lock:
                    scan_data["scanned_devices"] = i + 1
                    scan_data["progress"] = progress
                    scan_data["current_device"] = f"Scanning: {device}"
                    scan_data["last_update"] = time.time()

                logger.info(f"Progress: {progress}% - Scanned {i+1}/{len(all_devices)} devices")

        # Save discovered devices to database
        if current_scan_id and discovered_devices:
            save_device_discovery(current_scan_id, discovered_devices)
            duration = int(time.time() - scan_start_time)
            update_scan_session(current_scan_id, 'completed', len(discovered_devices), duration)
            logger.info(f"Scan completed: Found {len(discovered_devices)} devices in {duration} seconds")
        else:
            logger.info("No devices discovered")

        with scan_lock:
            scan_data["results"]["devices"] = discovered_devices.copy()
            scan_data["progress"] = 100
            scan_data["current_device"] = f"Found {len(discovered_devices)} devices"
            scan_data["status"] = "done"
            scan_data["last_update"] = time.time()

    except Exception as e:
        logger.error(f"Discovery scan error: {e}")
        with scan_lock: 
            scan_data["status"] = f"error: {e}"
            scan_data["progress"] = 0
            scan_data["last_update"] = time.time()
        if current_scan_id:
            update_scan_session(current_scan_id, f'error: {e}')
    finally:
        global active_scan_thread
        active_scan_thread = None
        logger.info("Discovery scan thread finished")

def perform_detailed_scan(ip):
    """Worker for the intensive per-device scan"""
    def update_status(phase, progress, result=None, error=None):
        with detailed_lock:
            scan_state = detailed_scans.get(ip, {})
            scan_state.update({"phase": phase, "progress": progress})
            if result:
                existing_result = scan_state.get("result", {})
                existing_result.update(result)
                scan_state["result"] = existing_result
            if error:
                scan_state["error"] = error
            detailed_scans[ip] = scan_state
    
    try:
        logger.info(f"Starting detailed scan for {ip}")
        
        # Step 1: Ping device to ensure it's online
        update_status("Pinging device...", 10)
        scanner = run_nmap_with_timeout(ip, '-sn -T4', timeout=20)
        if scanner == "TIMEOUT":
            raise ValueError("Device ping timed out.")
        if not isinstance(scanner, nmap.PortScanner) or ip not in scanner.all_hosts():
            raise ValueError("Device is down or not responding.")

        # Step 2: Scan for open ports and services
        update_status("Scanning for open ports and services...", 30)
        # Increased timeout to 300s and added fallback logic
        # Added -R --system-dns for better hostname resolution
        scanner = run_nmap_with_timeout(ip, '-sV -T4 -R --system-dns --top-ports 50', timeout=300)
        
        if scanner == "TIMEOUT":
            logger.warning(f"Aggressive scan timed out for {ip}, retrying with lighter scan...")
            update_status("Aggressive scan timed out. Retrying with standard timing...", 40)
            # Fallback: Lighter scan (T3 default, fewer ports or same ports but more time)
            scanner = run_nmap_with_timeout(ip, '-sV -R --system-dns --top-ports 50', timeout=300)
            
            if scanner == "TIMEOUT":
                raise ValueError("Service scan timed out even after retry.")
        
        if not isinstance(scanner, nmap.PortScanner):
            raise ValueError("Service scan failed.")

        # Store results
        result = {
            "state": scanner[ip].state(),
            "hostnames": scanner[ip].hostnames(),
            "tcp": scanner[ip].get('tcp', {}),
            "osmatch": []
        }
        # Do NOT send result at 80%, or the frontend will stop polling too early
        update_status("Service scan complete. Attempting OS detection...", 80)

        # Step 3: Attempt OS Detection
        os_scanner = run_nmap_with_timeout(ip, '-O -T4 --osscan-limit --max-os-tries 1', timeout=60)
        if isinstance(os_scanner, nmap.PortScanner) and ip in os_scanner.all_hosts():
            result["osmatch"] = os_scanner[ip].get('osmatch', [])
        else:
            logger.warning(f"OS detection failed for {ip}")

        # Final update
        update_status("Complete", 100, result=result)
        logger.info(f"Detailed scan completed for {ip}")

    except Exception as e:
        logger.error(f"Detailed scan error for {ip}: {e}")
        update_status(f"Error: {e}", 100, error=str(e))

# --- Flask Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan_device/<ip>")
def scan_device(ip):
    saved_data = get_latest_device_details(ip)
    return render_template("device.html", ip=ip, saved_data=json.dumps(saved_data) if saved_data else None)

@app.route("/saved_scan/<int:scan_id>")
def view_saved_scan(scan_id):
    """Route to view saved scan details"""
    scan_details = get_scan_details(scan_id)
    if scan_details:
        return render_template("saved_scan.html", scan=scan_details)
    else:
        return "Scan not found", 404

# --- API Routes ---
@app.route("/api/scan", methods=["POST"])
def scan():
    global active_scan_thread
    
    # Check if a scan is already running
    with scan_lock:
        if scan_data["status"] == "running" and active_scan_thread and active_scan_thread.is_alive():
            return jsonify({"status": "error", "message": "A scan is already in progress"}), 409
    
    data = request.get_json()
    target = data.get("target")
    
    if not target:
        return jsonify({"status": "error", "message": "No target specified"}), 400
    
    # Start scan in background thread
    active_scan_thread = threading.Thread(target=perform_discovery_scan, args=(target,), daemon=True)
    active_scan_thread.start()
    
    return jsonify({"status": "started", "message": "Discovery scan started"})

@app.route("/api/detailed_scan/<ip>", methods=["POST"])
def start_detailed_scan(ip):
    """Start a detailed scan for a specific device"""
    with detailed_lock:
        if detailed_scans.get(ip, {}).get("phase") not in [None, "Complete", "Error"]:
            if "result" not in detailed_scans[ip] and "error" not in detailed_scans[ip]:
                return jsonify({"status": "Scan already in progress"}), 409
    
    threading.Thread(target=perform_detailed_scan, args=(ip,), daemon=True).start()
    return jsonify({"status": "Detailed scan initiated"})

@app.route("/api/detailed_progress/<ip>")
def get_detailed_status(ip):
    """Get progress of detailed scan"""
    with detailed_lock:
        return jsonify(detailed_scans.get(ip, {"phase": "Not Started", "progress": 0}))

@app.route("/api/status")
def status():
    with scan_lock:
        # Make sure we return a copy to avoid thread issues
        status_data = scan_data.copy()
        return jsonify(status_data)

@app.route("/api/reset_scan", methods=["POST"])
def api_reset_scan():
    reset_scan_data()
    return jsonify({"status": "reset"})

@app.route("/api/localrange")
def localrange():
    return jsonify({"range": get_local_network()})

@app.route("/api/gateway")
def gateway():
    return jsonify({"gateway": get_default_gateway()})

# --- Database API Routes ---
@app.route("/api/save_current_scan", methods=["POST"])
def save_current_scan():
    """Save the current scan results to database"""
    global current_scan_id
    if not current_scan_id:
        return jsonify({"status": "error", "message": "No active scan to save"})
    
    if mark_scan_as_saved(current_scan_id):
        return jsonify({"status": "success", "message": "Scan saved successfully", "scan_id": current_scan_id})
    else:
        return jsonify({"status": "error", "message": "Failed to save scan"})

def get_scan_details(scan_id):
    """Get detailed scan information including devices"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get scan basic info
        cursor.execute('''
            SELECT * FROM scans WHERE id = %s
        ''', (scan_id,))
        scan_info = cursor.fetchone()
        
        if not scan_info:
            return None
        
        # Get devices for this scan
        cursor.execute('''
            SELECT * FROM devices WHERE scan_id = %s
        ''', (scan_id,))
        devices = cursor.fetchall()
        
        scan_info['devices'] = devices
        
        return scan_info
    except mysql.connector.Error as e:
        logger.error(f"Error retrieving scan details: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_saved_scans(scan_type=None):
    """Get all saved scans from database"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        if scan_type:
            cursor.execute('''
                SELECT id, target_range, scan_type, status, devices_found, 
                       start_time, end_time, duration_seconds
                FROM scans 
                WHERE saved_result = TRUE AND scan_type = %s
                ORDER BY start_time DESC
            ''', (scan_type,))
        else:
            cursor.execute('''
                SELECT id, target_range, scan_type, status, devices_found, 
                       start_time, end_time, duration_seconds
                FROM scans 
                WHERE saved_result = TRUE
                ORDER BY start_time DESC
            ''')
        
        return cursor.fetchall()
    except mysql.connector.Error as e:
        logger.error(f"Error retrieving saved scans: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

def delete_scan(scan_id):
    """Delete a scan and all associated data"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Delete scan (cascade will delete devices and ports)
        cursor.execute('DELETE FROM scans WHERE id = %s', (scan_id,))
        
        conn.commit()
        logger.info(f"Deleted scan {scan_id} from database")
        return True
    except mysql.connector.Error as e:
        logger.error(f"Error deleting scan: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def save_detailed_scan_results(scan_id, ip, detailed_results):
    """Save detailed port scan results to database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Get or create device entry
        cursor.execute('''
            SELECT id FROM devices WHERE scan_id = %s AND ip_address = %s
        ''', (scan_id, ip))
        result = cursor.fetchone()
        
        if result:
            device_id = result[0]
            # Update existing device with OS info
            cursor.execute('''
                UPDATE devices SET os_info = %s, device_type = %s 
                WHERE id = %s
            ''', (
                detailed_results.get('os_info', ''),
                detailed_results.get('device_type', 'unknown'),
                device_id
            ))
        else:
            # Create new device entry
            cursor.execute('''
                INSERT INTO devices (scan_id, ip_address, hostname, os_info, status, device_type)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                scan_id,
                ip,
                detailed_results.get('hostname', ''),
                detailed_results.get('os_info', ''),
                detailed_results.get('state', 'up'),
                detailed_results.get('device_type', 'unknown')
            ))
            device_id = cursor.lastrowid
        
        # Save port information
        for port_info in detailed_results.get('ports', []):
            cursor.execute('''
                INSERT INTO ports (device_id, port_number, protocol, state, service_name, service_version, banner)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                state = VALUES(state),
                service_name = VALUES(service_name),
                service_version = VALUES(service_version),
                banner = VALUES(banner)
            ''', (
                device_id,
                port_info.get('port'),
                port_info.get('protocol', 'tcp'),
                port_info.get('state'),
                port_info.get('service'),
                port_info.get('version'),
                port_info.get('banner')
            ))
        
        conn.commit()
        logger.info(f"Saved detailed scan results for {ip} in scan {scan_id}")
        return True
        
    except mysql.connector.Error as e:
        logger.error(f"Error saving detailed scan results: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def create_detailed_scan_session(ip):
    """Create a new scan session for detailed port scan"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (target_range, scan_type, status, devices_found)
            VALUES (%s, 'detailed', 'completed', 1)
        ''', (ip,))
        
        scan_id = cursor.lastrowid
        conn.commit()
        logger.info(f"Created detailed scan session {scan_id} for {ip}")
        return scan_id
    except mysql.connector.Error as e:
        logger.error(f"Error creating detailed scan session: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_latest_device_details(ip):
    """Retrieve the latest scan results for a specific IP"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        # Get the most recent device entry for this IP
        cursor.execute('''
            SELECT * FROM devices 
            WHERE ip_address = %s 
            ORDER BY last_seen DESC 
            LIMIT 1
        ''', (ip,))
        device = cursor.fetchone()
        
        if not device:
            return None
            
        # Get ports for this device
        cursor.execute('''
            SELECT * FROM ports WHERE device_id = %s
        ''', (device['id'],))
        ports = cursor.fetchall()
        
        # Construct the result object to match the format expected by the frontend
        result = {
            "state": device['status'],
            "hostnames": [{"name": device['hostname'], "type": ""}] if device['hostname'] else [],
            "osmatch": [{"name": device['os_info'], "accuracy": "100"}] if device['os_info'] else [],
            "tcp": {}
        }
        
        for port in ports:
            result['tcp'][str(port['port_number'])] = {
                "name": port['service_name'],
                "product": port['service_version'], # Assuming version contains product info or simple mapping
                "version": "", # Already mixed in service_version usually
                "state": port['state']
            }
            
        return result
        
    except mysql.connector.Error as e:
        logger.error(f"Error retrieving device details: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

@app.route("/api/saved_scans")
def get_saved_scans_api():
    """Get all saved scans"""
    scan_type = request.args.get('type')
    scans = get_saved_scans(scan_type)
    return jsonify({"status": "success", "scans": scans})

@app.route("/api/saved_scan/<int:scan_id>")
def get_saved_scan_details(scan_id):
    """Get detailed information for a saved scan"""
    scan_details = get_scan_details(scan_id)
    if scan_details:
        return jsonify({"status": "success", "scan": scan_details})
    else:
        return jsonify({"status": "error", "message": "Scan not found"})

@app.route("/api/delete_scan/<int:scan_id>", methods=["DELETE"])
def delete_scan_api(scan_id):
    """Delete a saved scan"""
    if delete_scan(scan_id):
        return jsonify({"status": "success", "message": "Scan deleted successfully"})
    else:
        return jsonify({"status": "error", "message": "Failed to delete scan"})

# --- New API Route for Saving Detailed Scans ---
@app.route("/api/save_detailed_scan/<ip>", methods=["POST"])
def save_detailed_scan(ip):
    """Save detailed port scan results to database"""
    data = request.get_json()
    
    if not data or 'results' not in data:
        return jsonify({"status": "error", "message": "No results data provided"})
    
    # Create a new scan session for this detailed scan
    scan_id = create_detailed_scan_session(ip)
    if not scan_id:
        return jsonify({"status": "error", "message": "Failed to create scan session"})
    
    # Prepare detailed results
    detailed_results = {
        'hostname': data.get('hostname', ''),
        'os_info': data.get('os_info', ''),
        'state': data.get('state', 'up'),
        'device_type': data.get('device_type', 'unknown'),
        'ports': []
    }
    
    # Convert port data to the required format
    if 'tcp' in data['results']:
        for port, info in data['results']['tcp'].items():
            detailed_results['ports'].append({
                'port': int(port),
                'protocol': 'tcp',
                'state': info.get('state', ''),
                'service': info.get('name', ''),
                'version': f"{info.get('product', '')} {info.get('version', '')}".strip(),
                'banner': info.get('extrainfo', '')
            })
    
    # Save to database
    if save_detailed_scan_results(scan_id, ip, detailed_results):
        mark_scan_as_saved(scan_id)
        return jsonify({
            "status": "success", 
            "message": "Detailed scan saved successfully",
            "scan_id": scan_id
        })
    else:
        return jsonify({"status": "error", "message": "Failed to save detailed scan results"})

if __name__ == "__main__":
    logger.info("Starting IoT Device Security Scanner application...")
    app.run(debug=True, host='0.0.0.0')