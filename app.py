from flask import Flask, request, jsonify, render_template
import os
import json
import time
import threading
from scapy.all import IP, TCP, UDP, ICMP, Raw, send

app = Flask(__name__)

# Ensure necessary directories exist
os.makedirs('logs', exist_ok=True)
os.makedirs('pcaps', exist_ok=True)
os.makedirs('data', exist_ok=True)  # Directory for persistent data

# Load attack logs from file if it exists
def load_attack_logs():
    try:
        if os.path.exists('data/attack_logs.json'):
            with open('data/attack_logs.json', 'r') as f:
                return json.load(f)
    except Exception as e:
        app.logger.error(f"Error loading attack logs: {str(e)}")
    
    # Default empty logs
    return {
        "port_scan": [],
        "dos_attack": [],
        "bruteforce": [],
        "data_exfil": []
    }

# Save attack logs to file
def save_attack_logs():
    try:
        with open('data/attack_logs.json', 'w') as f:
            json.dump(attack_logs, f)
    except Exception as e:
        app.logger.error(f"Error saving attack logs: {str(e)}")

# Simulated attack logs
attack_logs = load_attack_logs()

# Simulation status
simulation_active = False

# Function to generate timestamp
def get_timestamp():
    return int(time.time())

# Simulate different types of attacks
def simulate_port_scan(target_ip, scan_type="SYN"):
    """Simulate a port scan attack"""
    timestamp = get_timestamp()
    
    # Create log entry
    log_entry = {
        "timestamp": timestamp,
        "src_ip": "192.168.1.50",  # Simulated source
        "dst_ip": target_ip,
        "scan_type": scan_type,
        "ports": [22, 23, 25, 53, 80, 443, 8080],
        "detection": "Port Scanning Detected"
    }
    
    # Add to logs
    attack_logs["port_scan"].append(log_entry)
    save_attack_logs()
    
    # Generate Zeek-like log file
    with open(os.path.join('logs', 'port_scan.log'), 'a') as f:
        f.write(f"# Fields: ts uid id.orig_h id.resp_p proto scan_attempts anomaly_type severity\n")
        f.write(f"{timestamp}.67890 XdJhQW7Q9T 192.168.1.50 80 tcp 15 Port_Scanning Medium\n")
        f.write(f"# Alert: Multiple connection attempts from 192.168.1.50 to different ports\n")
    
    # Generate Snort-like log file
    with open(os.path.join('logs', 'snort_alerts.log'), 'a') as f:
        f.write(f"[**] [1:2000002:1] SNORT ALERT - Port Scanning Detected [**]\n")
        f.write(f"[Classification: Attempted Information Leak] [Priority: 3]\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))} UTC\n")
        f.write(f"SRC IP: 192.168.1.50\n")
        f.write(f"Target Ports: 22, 23, 25, 53, 80, 443, 8080\n")
        f.write(f"Threshold: 10 ports in 5 seconds\n\n")
    
    # Simulate packet sending with Scapy (commented out to avoid actual packet sending)
    # for port in [22, 23, 25, 53, 80, 443, 8080]:
    #     packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    #     send(packet, verbose=0)
    #     time.sleep(0.1)
    
    return {"status": "success", "message": f"{scan_type} port scan simulated to {target_ip}"}

def simulate_dos_attack(target_ip, count=10):
    """Simulate a simple DoS attack"""
    timestamp = get_timestamp()
    
    # Create log entry
    log_entry = {
        "timestamp": timestamp,
        "src_ip": "192.168.1.100",  # Simulated source
        "dst_ip": target_ip,
        "attack_type": "SYN Flood",
        "packet_count": count,
        "detection": "SYN Flood Attack Detected"
    }
    
    # Add to logs
    attack_logs["dos_attack"].append(log_entry)
    save_attack_logs()
    
    # Generate Zeek-like log file
    with open(os.path.join('logs', 'syn_flood.log'), 'a') as f:
        f.write(f"# Fields: ts uid id.orig_h id.resp_h proto syn_count anomaly_type severity\n")
        f.write(f"{timestamp}.24567 Zeek456Yh 192.168.1.100 {target_ip} tcp {count} SYN_Flood Critical\n")
        f.write(f"# Alert: SYN packet flood detected from 192.168.1.100\n")
    
    # Generate Snort-like log file
    with open(os.path.join('logs', 'snort_alerts.log'), 'a') as f:
        f.write(f"[**] [1:2000003:1] SNORT ALERT - SYN Flood Attack [**]\n")
        f.write(f"[Classification: Denial of Service] [Priority: 1]\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))} UTC\n")
        f.write(f"SRC IP: 192.168.1.100 DST IP: {target_ip}\n")
        f.write(f"SYN Count: {count} SYNs in 1 second\n\n")
    
    # Simulate packet sending with Scapy (commented out to avoid actual packet sending)
    # for _ in range(count):
    #     packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
    #     send(packet, verbose=0)
    #     time.sleep(0.05)
    
    return {"status": "success", "message": f"DoS attack simulated to {target_ip} with {count} packets"}

def simulate_bruteforce(target_ip, service="ssh"):
    """Simulate a brute force attack"""
    timestamp = get_timestamp()
    port = 22 if service == "ssh" else 21  # SSH or FTP
    
    # Create log entry
    log_entry = {
        "timestamp": timestamp,
        "src_ip": "192.168.1.75",  # Simulated source
        "dst_ip": target_ip,
        "service": service,
        "port": port,
        "attempts": 5,
        "detection": "Brute Force Attack Detected"
    }
    
    # Add to logs
    attack_logs["bruteforce"].append(log_entry)
    save_attack_logs()
    
    # Generate Zeek-like log file
    with open(os.path.join('logs', 'auth_failure.log'), 'a') as f:
        f.write(f"# Fields: ts uid id.orig_h id.resp_h proto service auth_attempts anomaly_type severity\n")
        for i in range(5):
            f.write(f"{timestamp + i}.12345 Auth{i}XYZ 192.168.1.75 {target_ip} tcp {service} failed Brute_Force High\n")
        f.write(f"# Alert: Multiple authentication failures from 192.168.1.75\n")
    
    # Generate Snort-like log file
    with open(os.path.join('logs', 'snort_alerts.log'), 'a') as f:
        f.write(f"[**] [1:2000009:1] SNORT ALERT - Potential Brute Force Attack [**]\n")
        f.write(f"[Classification: Attempted Administrator Privilege Gain] [Priority: 1]\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))} UTC\n")
        f.write(f"SRC IP: 192.168.1.75 DST IP: {target_ip}\n")
        f.write(f"Service: {service.upper()} (Port {port})\n")
        f.write(f"Auth Failures: 5 attempts in 30 seconds\n\n")
    
    # Simulate packet sending with Scapy (commented out to avoid actual packet sending)
    # for _ in range(5):
    #     packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    #     send(packet, verbose=0)
    #     time.sleep(0.2)
    #     auth_packet = IP(dst=target_ip)/TCP(dport=port)/Raw(load=b"USER admin\nPASS test123\n")
    #     send(auth_packet, verbose=0)
    #     time.sleep(0.2)
    
    return {"status": "success", "message": f"Brute force attack simulated to {target_ip} on {service}"}

def simulate_data_exfiltration(target_ip):
    """Simulate data exfiltration"""
    timestamp = get_timestamp()
    
    # Create log entry
    log_entry = {
        "timestamp": timestamp,
        "src_ip": "192.168.1.60",  # Simulated source
        "dst_ip": target_ip,
        "protocol": "DNS",
        "data_size": 1000,  # bytes
        "detection": "Data Exfiltration Detected"
    }
    
    # Add to logs
    attack_logs["data_exfil"].append(log_entry)
    save_attack_logs()
    
    # Generate Zeek-like log file
    with open(os.path.join('logs', 'data_exfil.log'), 'a') as f:
        f.write(f"# Fields: ts uid id.orig_h id.resp_h proto size anomaly_type severity\n")
        f.write(f"{timestamp}.98765 DataEx123 192.168.1.60 {target_ip} udp 1000 Data_Exfiltration High\n")
        f.write(f"# Alert: Suspicious data transfer detected from 192.168.1.60 using DNS tunneling\n")
    
    # Generate Snort-like log file
    with open(os.path.join('logs', 'snort_alerts.log'), 'a') as f:
        f.write(f"[**] [1:2000010:1] SNORT ALERT - Potential Data Exfiltration [**]\n")
        f.write(f"[Classification: Potential Corporate Data Exfiltration] [Priority: 1]\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))} UTC\n")
        f.write(f"SRC IP: 192.168.1.60 DST IP: {target_ip}\n")
        f.write(f"Protocol: DNS\n")
        f.write(f"Data Size: 1000 bytes\n")
        f.write(f"Suspicion: DNS tunneling detected\n\n")
    
    # Simulate packet sending with Scapy (commented out to avoid actual packet sending)
    # large_data = b"CONFIDENTIAL_DATA" * 100
    # for i in range(5):
    #     data_chunk = large_data[i*200:(i+1)*200]
    #     packet = IP(dst=target_ip)/UDP(dport=53)/Raw(load=data_chunk)
    #     send(packet, verbose=0)
    #     time.sleep(0.3)
    
    return {"status": "success", "message": f"Data exfiltration simulated to {target_ip}"}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start_simulation', methods=['POST'])
def api_start_simulation():
    global simulation_active
    simulation_active = True
    
    # Clean previous log files
    for file in os.listdir('logs'):
        if file.endswith('.log'):
            os.remove(os.path.join('logs', file))
    
    return jsonify({"status": "success", "message": "Simulation started"})

@app.route('/api/stop_simulation', methods=['POST'])
def api_stop_simulation():
    global simulation_active
    simulation_active = False
    return jsonify({"status": "success", "message": "Simulation stopped"})

@app.route('/api/simulate_attack', methods=['POST'])
def api_simulate_attack():
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "No JSON data received"}), 400
            
        attack_type = data.get('type')
        if not attack_type:
            return jsonify({"status": "error", "message": "Attack type not specified"}), 400
            
        target_ip = data.get('target_ip', '127.0.0.1')
        
        result = {"status": "error", "message": "Invalid attack type"}
        
        if attack_type == "port_scan":
            scan_type = data.get('scan_type', 'SYN')
            result = simulate_port_scan(target_ip, scan_type)
        elif attack_type == "dos":
            count = int(data.get('count', 10))
            result = simulate_dos_attack(target_ip, count)
        elif attack_type == "bruteforce":
            service = data.get('service', 'ssh')
            result = simulate_bruteforce(target_ip, service)
        elif attack_type == "data_exfil":
            result = simulate_data_exfiltration(target_ip)
        else:
            return jsonify({"status": "error", "message": f"Unknown attack type: {attack_type}"}), 400
        
        # Add additional information to the result for better UI display
        result["attack_type"] = attack_type
        result["target_ip"] = target_ip
        result["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error in simulate_attack: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/api/get_logs', methods=['GET'])
def get_logs():
    time_interval = request.args.get('time_interval', '5')  # Default to 5 minutes
    try:
        time_interval = int(time_interval)
    except ValueError:
        time_interval = 5  # Default if invalid input
    
    # Calculate the cutoff time based on the time interval
    cutoff_time = time.time() - (time_interval * 60)
    
    logs_dir = os.path.join(app.root_path, 'logs')
    log_files = []
    
    if os.path.exists(logs_dir):
        for file in os.listdir(logs_dir):
            if file.endswith('.log'):
                file_path = os.path.join(logs_dir, file)
                # Check if the file was created or modified within the time interval
                file_mtime = os.path.getmtime(file_path)
                if file_mtime >= cutoff_time:
                    log_files.append(file)
    
    return jsonify({'logs': sorted(log_files, reverse=True)})

@app.route('/api/analyze_detection')
def analyze_detection():
    # Analyze logs to provide insights on detected attacks
    detection_summary = {
        "port_scan": {
            "detected": len(attack_logs["port_scan"]) > 0,
            "count": len(attack_logs["port_scan"]),
            "details": [f"Port scan from {log['src_ip']} to {log['dst_ip']} ({log['scan_type']})" 
                      for log in attack_logs["port_scan"]]
        },
        "dos_attack": {
            "detected": len(attack_logs["dos_attack"]) > 0,
            "count": len(attack_logs["dos_attack"]),
            "details": [f"DoS attack from {log['src_ip']} to {log['dst_ip']} ({log['packet_count']} packets)" 
                      for log in attack_logs["dos_attack"]]
        },
        "bruteforce": {
            "detected": len(attack_logs["bruteforce"]) > 0,
            "count": len(attack_logs["bruteforce"]),
            "details": [f"Brute force attack on {log['service'].upper()} from {log['src_ip']} to {log['dst_ip']}" 
                      for log in attack_logs["bruteforce"]]
        },
        "data_exfil": {
            "detected": len(attack_logs["data_exfil"]) > 0,
            "count": len(attack_logs["data_exfil"]),
            "details": [f"Data exfiltration from {log['src_ip']} to {log['dst_ip']} ({log['data_size']} bytes)" 
                      for log in attack_logs["data_exfil"]]
        }
    }
    
    return jsonify(detection_summary)

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    global attack_logs
    
    # Clear in-memory logs
    attack_logs = {
        "port_scan": [],
        "dos_attack": [],
        "bruteforce": [],
        "data_exfil": []
    }
    save_attack_logs()
    
    # Clear log files
    for file in os.listdir('logs'):
        if file.endswith('.log'):
            os.remove(os.path.join('logs', file))
    
    return jsonify({"status": "success", "message": "Logs cleared"})

@app.route('/api/logs/<log_file>')
def get_log_content(log_file):
    log_path = os.path.join(app.root_path, 'logs', log_file)
    
    if not os.path.exists(log_path):
        return "Log file not found", 404
    
    try:
        with open(log_path, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return f"Error reading log file: {str(e)}", 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    time_interval = request.args.get('time_interval', '5')  # Default to 5 minutes
    try:
        time_interval = int(time_interval)
    except ValueError:
        time_interval = 5  # Default if invalid input
    
    # Calculate the cutoff time based on the time interval
    cutoff_time = time.time() - (time_interval * 60)
    
    logs_dir = os.path.join(app.root_path, 'logs')
    
    # Initialize counters
    stats = {
        'port_scan': 0,
        'dos': 0,
        'bruteforce': 0,
        'data_exfil': 0
    }
    
    if os.path.exists(logs_dir):
        for file in os.listdir(logs_dir):
            if file.endswith('.log'):
                file_path = os.path.join(logs_dir, file)
                # Check if the file was created or modified within the time interval
                file_mtime = os.path.getmtime(file_path)
                
                if file_mtime >= cutoff_time:
                    # Count by attack type
                    if 'port_scan' in file:
                        stats['port_scan'] += 1
                    elif 'dos' in file:
                        stats['dos'] += 1
                    elif 'bruteforce' in file:
                        stats['bruteforce'] += 1
                    elif 'data_exfil' in file:
                        stats['data_exfil'] += 1
    
    return jsonify(stats)

@app.route('/api/genai_summary', methods=['POST'])
def genai_summary():
    """Generate an AI-powered summary of attack data using a mock response for now."""
    data = request.json
    time_interval = data.get('time_interval', '5')
    
    # For now, we'll return a mock response
    # In a real implementation, this would call OpenAI API
    
    port_scan_count = int(data.get('port_scan', {}).get('count', 0))
    dos_count = int(data.get('dos', {}).get('count', 0))
    bruteforce_count = int(data.get('bruteforce', {}).get('count', 0))
    data_exfil_count = int(data.get('data_exfil', {}).get('count', 0))
    
    total_attacks = port_scan_count + dos_count + bruteforce_count + data_exfil_count
    
    if total_attacks == 0:
        return jsonify({
            "summary": "No attack activity detected in the selected time period.",
            "recommendations": "<ul><li>Continue monitoring network traffic</li><li>Ensure all security systems are up to date</li></ul>"
        })
    
    # Determine the most prevalent attack type
    attack_counts = {
        "Port Scan": port_scan_count,
        "DoS": dos_count,
        "Brute Force": bruteforce_count,
        "Data Exfiltration": data_exfil_count
    }
    
    most_common_attack = max(attack_counts.items(), key=lambda x: x[1])
    
    summary = f"""
    <p>Analysis of network traffic from the past {time_interval} minute(s) shows a total of <strong>{total_attacks} attack attempts</strong>.</p>
    
    <p>The most prevalent attack type was <strong>{most_common_attack[0]}</strong> with {most_common_attack[1]} attempts, 
    representing {round((most_common_attack[1]/total_attacks)*100)}% of all detected attacks.</p>
    
    <p>Attack distribution:</p>
    <ul>
        <li>Port Scans: {port_scan_count} ({round((port_scan_count/total_attacks)*100) if total_attacks > 0 else 0}%)</li>
        <li>DoS Attacks: {dos_count} ({round((dos_count/total_attacks)*100) if total_attacks > 0 else 0}%)</li>
        <li>Brute Force Attempts: {bruteforce_count} ({round((bruteforce_count/total_attacks)*100) if total_attacks > 0 else 0}%)</li>
        <li>Data Exfiltration: {data_exfil_count} ({round((data_exfil_count/total_attacks)*100) if total_attacks > 0 else 0}%)</li>
    </ul>
    """
    
    # Generate recommendations based on attack types
    recommendations = "<ul>"
    
    if port_scan_count > 0:
        recommendations += """
        <li>Port scan activity detected - Review firewall rules and consider implementing port knocking for sensitive services</li>
        <li>Ensure unnecessary ports are closed and only required services are exposed</li>
        """
    
    if dos_count > 0:
        recommendations += """
        <li>DoS activity detected - Consider implementing rate limiting and traffic filtering</li>
        <li>Review network capacity and consider DDoS protection services</li>
        """
    
    if bruteforce_count > 0:
        recommendations += """
        <li>Brute force attempts detected - Implement account lockout policies and strong password requirements</li>
        <li>Consider adding multi-factor authentication to sensitive systems</li>
        """
    
    if data_exfil_count > 0:
        recommendations += """
        <li>Data exfiltration detected - Review data loss prevention policies</li>
        <li>Monitor outbound traffic and implement egress filtering</li>
        """
    
    recommendations += "</ul>"
    
    return jsonify({
        "summary": summary,
        "recommendations": recommendations
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)