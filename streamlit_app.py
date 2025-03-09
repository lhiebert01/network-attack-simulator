import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import time
import os
import json
import subprocess
import sys
from datetime import datetime, timedelta
import random

# Page configuration
st.set_page_config(
    page_title="Network Attack Simulator",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #0D47A1;
        margin-bottom: 1rem;
    }
    .status-running {
        color: #4CAF50;
        font-weight: bold;
    }
    .status-stopped {
        color: #F44336;
        font-weight: bold;
    }
    .attack-card {
        background-color: var(--background-color, #f0f2f6);
        color: var(--text-color, #000000);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        border: 1px solid rgba(128, 128, 128, 0.2);
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .attack-title {
        font-size: 1.2rem;
        font-weight: bold;
        margin-bottom: 10px;
    }
    .footer-text {
        font-size: 0.8rem;
        color: #666;
        text-align: center;
        margin-top: 20px;
    }
    .author-info {
        display: flex;
        align-items: center;
        justify-content: center;
        margin-top: 10px;
    }
    .author-info img {
        width: 24px;
        height: 24px;
        margin-right: 5px;
    }
    
    html[data-theme="light"] .attack-card {
        background-color: #f0f2f6;
        color: #000000;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "simulation_active" not in st.session_state:
    st.session_state.simulation_active = False
if "attack_logs" not in st.session_state:
    st.session_state.attack_logs = []
if "last_update" not in st.session_state:
    st.session_state.last_update = datetime.now()
if "selected_time_range" not in st.session_state:
    st.session_state.selected_time_range = "15m"

# Header
st.markdown("<h1 class='main-header'>Network Attack Simulator</h1>", unsafe_allow_html=True)
st.markdown("Simulate and visualize common network attacks for educational purposes")

# Add author attribution with LinkedIn icon
st.markdown("""
<div class="author-info">
    <img src="https://cdn-icons-png.flaticon.com/512/174/174857.png" alt="LinkedIn">
    <span>Developed by <a href="https://www.linkedin.com/in/lindsayhiebert/" target="_blank">Lindsay Hiebert</a></span>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("<h2 class='sub-header'>Controls</h2>", unsafe_allow_html=True)
    
    # Network Log Analyzer Button - Moved higher in the sidebar
    if st.button("Open Network Log Analyzer", type="primary"):
        # Open in a new window automatically
        import webbrowser
        webbrowser.open_new_tab("http://localhost:8001")
        st.success("Network Log Analyzer opened in a new window")
    
    st.markdown("---")
    
    # Simulation controls
    if st.button("Start Simulation", type="primary", disabled=st.session_state.simulation_active):
        st.session_state.simulation_active = True
        st.session_state.last_update = datetime.now()
        st.session_state.attack_logs = []
        st.success("Simulation started successfully!")
        st.rerun()
    
    if st.button("Stop Simulation", type="secondary", disabled=not st.session_state.simulation_active):
        st.session_state.simulation_active = False
        st.warning("Simulation stopped")
        st.rerun()
    
    # Display simulation status
    status_text = "Running" if st.session_state.simulation_active else "Not Running"
    status_class = "status-running" if st.session_state.simulation_active else "status-stopped"
    st.markdown(f"<p>Status: <span class='{status_class}'>{status_text}</span></p>", unsafe_allow_html=True)
    
    # Time range filter
    st.markdown("---")
    st.markdown("<h3>Time Range Filter</h3>", unsafe_allow_html=True)
    time_range = st.radio(
        "Select time range for logs and statistics:",
        options=["1m", "5m", "15m", "30m", "1h", "2h"],
        index=2,  # Default to 15 minutes
    )
    
    if time_range != st.session_state.selected_time_range:
        st.session_state.selected_time_range = time_range
        st.rerun()
    
    # Display time range information
    time_values = {"1m": 1, "5m": 5, "15m": 15, "30m": 30, "1h": 60, "2h": 120}
    st.write(f"Showing data from the last {time_values[time_range]} minute(s)")
    
    # Link to documentation
    st.markdown("---")
    st.markdown("[View Attack Documentation](https://github.com/lhiebert01/network-attack-simulator/blob/main/README-ATTACKS.md)")
    st.markdown("[GitHub Repository](https://github.com/lhiebert01/network-attack-simulator)")

# Main content
# Define tabs - Added Network Log Analyzer tab
tab1, tab2, tab3, tab4, tab5 = st.tabs(["Dashboard", "Attack Logs", "Attack Explanations", "Network Log Analyzer", "Settings"])

# Tab 1: Dashboard
with tab1:
    st.markdown("<h2 class='sub-header'>Attack Simulation Dashboard</h2>", unsafe_allow_html=True)
    
    # Function to generate simulated attack data
    def generate_attack_data():
        """Generate simulated attack data"""
        current_time = datetime.now()
        time_range_map = {
            "1m": 1, "5m": 5, "15m": 15, "30m": 30,
            "1h": 60, "2h": 120
        }
        minutes = time_range_map[st.session_state.selected_time_range]
        start_time = current_time - timedelta(minutes=minutes)
        attack_types = ["Port Scan", "DoS", "Brute Force", "Data Exfiltration"]
        severities = ["Low", "Medium", "High", "Critical"]
        protocols = ["tcp", "udp", "icmp", "http"]
        services = ["http", "ssh", "ftp", "dns", "smtp"]
        
        # Create data points within the selected time range
        data_points = []
        for i in range(random.randint(5, 20)):
            attack_time = start_time + timedelta(minutes=random.randint(0, minutes))
            attack_type = random.choice(attack_types)
            severity = random.choice(severities)
            source_ip = f"192.168.1.{random.randint(100, 200)}"
            target_ip = f"192.168.1.{random.randint(1, 50)}"
            protocol = random.choice(protocols)
            target_port = random.randint(1, 65535)
            uid = f"Zeek{random.randint(100, 999)}{chr(random.randint(65, 90))}{chr(random.randint(97, 122))}"
            timestamp = attack_time.timestamp()
            
            # Create detailed log entry based on attack type
            if attack_type == "Port Scan":
                scan_attempts = random.randint(5, 30)
                anomaly_type = "Port_Scanning"
                log_format = f"# Fields: ts uid id.orig_h id.resp_p proto scan_attempts anomaly_type severity\n"
                log_entry = f"{timestamp:.5f} {uid} {source_ip} {target_port} {protocol} {scan_attempts} {anomaly_type} {severity}"
                alert = f"# Alert: Port scan detected from {source_ip} targeting multiple ports"
                
                details = {
                    "ts": timestamp,
                    "uid": uid,
                    "id.orig_h": source_ip,
                    "id.resp_p": target_port,
                    "proto": protocol,
                    "scan_attempts": scan_attempts,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "log_format": log_format,
                    "log_entry": log_entry,
                    "alert": alert
                }
                
            elif attack_type == "DoS":
                packets_count = random.randint(1000, 10000)
                anomaly_type = "SYN_Flood" if protocol == "tcp" else f"{protocol.upper()}_Flood"
                service = "http" if target_port == 80 else random.choice(services)
                
                log_format = f"# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service packets_count anomaly_type severity\n"
                log_entry = f"{timestamp:.5f} {uid} {source_ip} {target_ip} {target_port} {protocol} {service} {packets_count} {anomaly_type} {severity}"
                alert = f"# Alert: {anomaly_type} detected from {source_ip} targeting {target_ip}:{target_port}"
                
                details = {
                    "ts": timestamp,
                    "uid": uid,
                    "id.orig_h": source_ip,
                    "id.resp_h": target_ip,
                    "id.resp_p": target_port,
                    "proto": protocol,
                    "service": service,
                    "packets_count": packets_count,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "log_format": log_format,
                    "log_entry": log_entry,
                    "alert": alert
                }
                
            elif attack_type == "Brute Force":
                login_attempts = random.randint(3, 50)
                service = "ssh" if target_port == 22 else "ftp" if target_port == 21 else random.choice(["http", "smtp", "pop3"])
                users = ["admin", "root", "user", "administrator", "guest"]
                user = random.choice(users)
                anomaly_type = f"Brute_Force_{service.upper()}"
                
                log_format = f"# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service login_attempts user anomaly_type severity\n"
                log_entry = f"{timestamp:.5f} {uid} {source_ip} {target_ip} {target_port} {protocol} {service} {login_attempts} {user} {anomaly_type} {severity}"
                alert = f"# Alert: Brute force attack detected on {service} service targeting user '{user}' from {source_ip}"
                
                details = {
                    "ts": timestamp,
                    "uid": uid,
                    "id.orig_h": source_ip,
                    "id.resp_h": target_ip,
                    "id.resp_p": target_port,
                    "proto": protocol,
                    "service": service,
                    "login_attempts": login_attempts,
                    "user": user,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "log_format": log_format,
                    "log_entry": log_entry,
                    "alert": alert
                }
                
            else:  # Data Exfiltration
                data_size = random.randint(500, 10000)
                service = "dns" if target_port == 53 else "http" if target_port == 80 else random.choice(services)
                exfil_types = ["DNS_Exfiltration", "HTTP_Exfiltration", "ICMP_Tunneling", "Encrypted_Channel"]
                anomaly_type = random.choice(exfil_types)
                
                log_format = f"# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service data_size anomaly_type severity\n"
                log_entry = f"{timestamp:.5f} {uid} {source_ip} {target_ip} {target_port} {protocol} {service} {data_size} {anomaly_type} {severity}"
                alert = f"# Alert: Data exfiltration detected from {source_ip} to {target_ip} using {service} ({data_size} bytes)"
                
                details = {
                    "ts": timestamp,
                    "uid": uid,
                    "id.orig_h": source_ip,
                    "id.resp_h": target_ip,
                    "id.resp_p": target_port,
                    "proto": protocol,
                    "service": service,
                    "data_size": data_size,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "log_format": log_format,
                    "log_entry": log_entry,
                    "alert": alert
                }
            
            data_points.append({
                "timestamp": attack_time,
                "attack_type": attack_type,
                "severity": severity,
                "source_ip": source_ip,
                "target_ip": target_ip,
                "details": details
            })
        
        return sorted(data_points, key=lambda x: x["timestamp"])
    
    # Generate attack data if simulation is active
    if st.session_state.simulation_active:
        if (datetime.now() - st.session_state.last_update).seconds > 5:  # Update every 5 seconds
            st.session_state.attack_logs = generate_attack_data()
            st.session_state.last_update = datetime.now()
    
    # Display statistics
    if st.session_state.attack_logs:
        # Create metrics
        col1, col2, col3, col4 = st.columns(4)
        
        # Count attacks by type
        attack_counts = {}
        for log in st.session_state.attack_logs:
            attack_type = log["attack_type"]
            if attack_type in attack_counts:
                attack_counts[attack_type] += 1
            else:
                attack_counts[attack_type] = 1
        
        # Display metrics
        col1.metric("Total Attacks", len(st.session_state.attack_logs))
        
        # Display attack type counts
        for i, (attack_type, count) in enumerate(attack_counts.items()):
            if i == 0:
                col2.metric(attack_type, count)
            elif i == 1:
                col3.metric(attack_type, count)
            elif i == 2:
                col4.metric(attack_type, count)
        
        # Create attack distribution chart
        st.markdown("### Attack Distribution")
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Prepare data for the chart
        attack_types = list(attack_counts.keys())
        attack_values = list(attack_counts.values())
        
        # Create bar chart
        bars = ax.bar(attack_types, attack_values, color=['#1E88E5', '#FFC107', '#F44336', '#4CAF50'])
        
        # Add labels and title
        ax.set_xlabel('Attack Type')
        ax.set_ylabel('Count')
        ax.set_title('Distribution of Attack Types')
        
        # Add count labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        # Display the chart
        st.pyplot(fig)
        
        # Create severity distribution
        st.markdown("### Attack Severity")
        severity_counts = {}
        for log in st.session_state.attack_logs:
            severity = log["severity"]
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1
        
        # Prepare data for pie chart
        severities = list(severity_counts.keys())
        severity_values = list(severity_counts.values())
        colors = {'Low': '#4CAF50', 'Medium': '#FFC107', 'High': '#FF9800', 'Critical': '#F44336'}
        pie_colors = [colors[s] for s in severities]
        
        # Create pie chart
        fig2, ax2 = plt.subplots(figsize=(8, 8))
        ax2.pie(severity_values, labels=severities, autopct='%1.1f%%', startangle=90, colors=pie_colors)
        ax2.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        ax2.set_title('Attack Severity Distribution')
        
        # Display the chart
        st.pyplot(fig2)
    else:
        if st.session_state.simulation_active:
            st.info("Simulation running. Waiting for attack data...")
        else:
            st.warning("Simulation is not active. Start the simulation to see attack data.")

# Tab 2: Attack Logs
with tab2:
    st.markdown("<h2 class='sub-header'>Attack Logs</h2>", unsafe_allow_html=True)
    
    if st.session_state.attack_logs:
        # Convert logs to DataFrame for display
        logs_df = pd.DataFrame(st.session_state.attack_logs)
        logs_df['timestamp'] = logs_df['timestamp'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S'))
        
        # Display logs table
        st.dataframe(logs_df[['timestamp', 'attack_type', 'severity', 'source_ip', 'target_ip']], use_container_width=True)
        
        # Display detailed log information
        st.markdown("### Detailed Log Information")
        
        for i, log in enumerate(st.session_state.attack_logs):
            with st.expander(f"Log #{i+1}: {log['attack_type']} from {log['source_ip']} ({log['severity']})"):
                # Display the log format and entry in a code block
                st.code(log['details']['log_format'] + log['details']['log_entry'] + "\n" + log['details']['alert'], language="bash")
                
                # Create two columns for the details
                col1, col2 = st.columns(2)
                
                # Display field explanations based on attack type
                if log['attack_type'] == "Port Scan":
                    col1.markdown("**Field Explanations:**")
                    col1.markdown("- **ts**: Timestamp in UNIX epoch format")
                    col1.markdown("- **uid**: Unique identifier for the connection")
                    col1.markdown("- **id.orig_h**: Source IP address (the scanner)")
                    col1.markdown("- **id.resp_p**: Destination port")
                    col1.markdown("- **proto**: Protocol used (tcp, udp)")
                    col1.markdown("- **scan_attempts**: Number of scan attempts detected")
                    col1.markdown("- **anomaly_type**: Type of anomaly detected")
                    col1.markdown("- **severity**: Severity level of the detected anomaly")
                    
                    col2.markdown("**Detection Details:**")
                    col2.markdown(f"- Scanner IP: **{log['details']['id.orig_h']}**")
                    col2.markdown(f"- Protocol: **{log['details']['proto']}**")
                    col2.markdown(f"- Scan Attempts: **{log['details']['scan_attempts']}**")
                    col2.markdown(f"- Target Port: **{log['details']['id.resp_p']}**")
                    col2.markdown(f"- Severity: **{log['details']['severity']}**")
                
                elif log['attack_type'] == "DoS":
                    col1.markdown("**Field Explanations:**")
                    col1.markdown("- **ts**: Timestamp in UNIX epoch format")
                    col1.markdown("- **uid**: Unique identifier for the connection")
                    col1.markdown("- **id.orig_h**: Source IP address (attacker)")
                    col1.markdown("- **id.resp_h**: Destination IP address (target)")
                    col1.markdown("- **id.resp_p**: Destination port")
                    col1.markdown("- **proto**: Protocol used")
                    col1.markdown("- **service**: Service being targeted")
                    col1.markdown("- **packets_count**: Number of packets detected in the attack")
                    col1.markdown("- **anomaly_type**: Type of DoS attack detected")
                    col1.markdown("- **severity**: Severity level of the detected anomaly")
                    
                    col2.markdown("**Detection Details:**")
                    col2.markdown(f"- Attacker IP: **{log['details']['id.orig_h']}**")
                    col2.markdown(f"- Target IP: **{log['details']['id.resp_h']}**")
                    col2.markdown(f"- Target Port: **{log['details']['id.resp_p']}**")
                    col2.markdown(f"- Protocol: **{log['details']['proto']}**")
                    col2.markdown(f"- Service: **{log['details']['service']}**")
                    col2.markdown(f"- Packet Count: **{log['details']['packets_count']}**")
                    col2.markdown(f"- Attack Type: **{log['details']['anomaly_type']}**")
                    col2.markdown(f"- Severity: **{log['details']['severity']}**")
                
                elif log['attack_type'] == "Brute Force":
                    col1.markdown("**Field Explanations:**")
                    col1.markdown("- **ts**: Timestamp in UNIX epoch format")
                    col1.markdown("- **uid**: Unique identifier for the connection")
                    col1.markdown("- **id.orig_h**: Source IP address (attacker)")
                    col1.markdown("- **id.resp_h**: Destination IP address (target)")
                    col1.markdown("- **id.resp_p**: Destination port")
                    col1.markdown("- **proto**: Protocol used")
                    col1.markdown("- **service**: Service being targeted (ssh, ftp, etc.)")
                    col1.markdown("- **login_attempts**: Number of login attempts detected")
                    col1.markdown("- **user**: Username being targeted")
                    col1.markdown("- **anomaly_type**: Type of brute force attack detected")
                    col1.markdown("- **severity**: Severity level of the detected anomaly")
                    
                    col2.markdown("**Detection Details:**")
                    col2.markdown(f"- Attacker IP: **{log['details']['id.orig_h']}**")
                    col2.markdown(f"- Target IP: **{log['details']['id.resp_h']}**")
                    col2.markdown(f"- Target Port: **{log['details']['id.resp_p']}**")
                    col2.markdown(f"- Protocol: **{log['details']['proto']}**")
                    col2.markdown(f"- Service: **{log['details']['service']}**")
                    col2.markdown(f"- Login Attempts: **{log['details']['login_attempts']}**")
                    col2.markdown(f"- Target User: **{log['details']['user']}**")
                    col2.markdown(f"- Attack Type: **{log['details']['anomaly_type']}**")
                    col2.markdown(f"- Severity: **{log['details']['severity']}**")
                
                else:  # Data Exfiltration
                    col1.markdown("**Field Explanations:**")
                    col1.markdown("- **ts**: Timestamp in UNIX epoch format")
                    col1.markdown("- **uid**: Unique identifier for the connection")
                    col1.markdown("- **id.orig_h**: Source IP address (internal compromised host)")
                    col1.markdown("- **id.resp_h**: Destination IP address (external server)")
                    col1.markdown("- **id.resp_p**: Destination port")
                    col1.markdown("- **proto**: Protocol used")
                    col1.markdown("- **service**: Service being used for exfiltration")
                    col1.markdown("- **data_size**: Size of data being exfiltrated (in bytes)")
                    col1.markdown("- **anomaly_type**: Type of exfiltration detected")
                    col1.markdown("- **severity**: Severity level of the detected anomaly")
                    
                    col2.markdown("**Detection Details:**")
                    col2.markdown(f"- Source IP: **{log['details']['id.orig_h']}**")
                    col2.markdown(f"- Destination IP: **{log['details']['id.resp_h']}**")
                    col2.markdown(f"- Destination Port: **{log['details']['id.resp_p']}**")
                    col2.markdown(f"- Protocol: **{log['details']['proto']}**")
                    col2.markdown(f"- Service: **{log['details']['service']}**")
                    col2.markdown(f"- Data Size: **{log['details']['data_size']} bytes**")
                    col2.markdown(f"- Exfiltration Type: **{log['details']['anomaly_type']}**")
                    col2.markdown(f"- Severity: **{log['details']['severity']}**")
        
        # Export options
        csv = logs_df.to_csv(index=False)
        st.download_button(
            label="Download Logs as CSV",
            data=csv,
            file_name=f"attack_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        if st.session_state.simulation_active:
            st.info("Simulation running. Waiting for attack logs...")
        else:
            st.warning("Simulation is not active. Start the simulation to generate logs.")

# Tab 3: Attack Explanations
with tab3:
    st.markdown("<h2 class='sub-header'>Attack Explanations</h2>", unsafe_allow_html=True)
    
    # Port Scanning explanation
    with st.expander("Port Scanning", expanded=False):
        st.header("Port Scanning")
        
        st.subheader("What is a Port Scan?")
        st.write("A port scan is a technique used to identify open ports and services on a network host. Attackers use port scanning to discover services they can exploit.")
        
        st.subheader("How it Works")
        st.write("The attacker sends packets to a range of port addresses on a host, analyzing which ports respond and how. Common types include:")
        st.markdown("- **SYN Scan:** Sends SYN packets as if initiating a connection but never completes the handshake")
        st.markdown("- **TCP Connect:** Completes the full TCP handshake")
        st.markdown("- **UDP Scan:** Sends UDP packets to identify UDP services")
        
        st.subheader("Detection Method")
        st.write("Port scans are detected by monitoring for:")
        st.markdown("- Multiple connection attempts from a single source to different ports in a short time period")
        st.markdown("- Connection attempts to closed or unusual ports")
        st.markdown("- Incomplete TCP handshakes (in the case of SYN scans)")
        
        st.subheader("Log File Format")
        st.write("Example log entry:")
        st.code("# Fields: ts uid id.orig_h id.resp_p proto scan_attempts anomaly_type severity\n1741500372.67890 XdJhQW7Q9T 192.168.1.50 80 tcp 15 Port_Scanning Medium", language="bash")
        
        st.subheader("Field Explanations:")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("- **ts**: Timestamp in UNIX epoch format")
            st.markdown("- **uid**: Unique identifier for the connection")
            st.markdown("- **id.orig_h**: Source IP address (the scanner)")
            st.markdown("- **id.resp_p**: Destination port")
        with col2:
            st.markdown("- **proto**: Protocol used (tcp, udp)")
            st.markdown("- **scan_attempts**: Number of scan attempts detected")
            st.markdown("- **anomaly_type**: Type of anomaly detected")
            st.markdown("- **severity**: Severity level of the detected anomaly")
    
    # DoS Attack explanation
    with st.expander("DoS Attack", expanded=False):
        st.header("Denial of Service (DoS) Attack")
        
        st.subheader("What is a DoS Attack?")
        st.write("A Denial of Service attack aims to make a service unavailable by overwhelming it with traffic or exploiting vulnerabilities that cause the service to crash or become unresponsive.")
        
        st.subheader("How it Works")
        st.write("Common DoS techniques include:")
        st.markdown("- **SYN Flood:** Sending many SYN packets without completing handshakes, exhausting connection resources")
        st.markdown("- **UDP Flood:** Overwhelming a target with UDP packets")
        st.markdown("- **HTTP Flood:** Sending a high volume of HTTP requests to overwhelm a web server")
        
        st.subheader("Detection Method")
        st.write("DoS attacks are detected by monitoring for:")
        st.markdown("- Unusual spikes in traffic volume")
        st.markdown("- High number of connections from a single source")
        st.markdown("- Abnormal ratios of specific packet types (e.g., many SYN packets without ACKs)")
        st.markdown("- Resource exhaustion indicators (high CPU, memory usage, etc.)")
        
        st.subheader("Log File Format")
        st.write("Example log entry:")
        st.code("# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service packets_count anomaly_type severity\n1741500372.89012 CjhRZG3Tsa 192.168.1.100 192.168.1.10 80 tcp http 10000 SYN_Flood High", language="bash")
        
        st.subheader("Field Explanations:")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("- **ts**: Timestamp in UNIX epoch format")
            st.markdown("- **uid**: Unique identifier for the connection")
            st.markdown("- **id.orig_h**: Source IP address (attacker)")
            st.markdown("- **id.resp_h**: Destination IP address (target)")
            st.markdown("- **id.resp_p**: Destination port")
        with col2:
            st.markdown("- **proto**: Protocol used")
            st.markdown("- **service**: Service being targeted")
            st.markdown("- **packets_count**: Number of packets detected in the attack")
            st.markdown("- **anomaly_type**: Type of DoS attack detected")
            st.markdown("- **severity**: Severity level of the detected anomaly")
    
    # Brute Force explanation
    with st.expander("Brute Force Attack", expanded=False):
        st.header("Brute Force Attack")
        
        st.subheader("What is a Brute Force Attack?")
        st.write("A brute force attack attempts to gain unauthorized access to systems by systematically trying all possible combinations of passwords or encryption keys until the correct one is found.")
        
        st.subheader("How it Works")
        st.write("The attacker repeatedly attempts to log in to a service (like SSH, FTP, or a web application) using different password combinations. This can be done using:")
        st.markdown("- **Dictionary Attacks:** Using a list of common words and passwords")
        st.markdown("- **Pure Brute Force:** Trying every possible combination of characters")
        st.markdown("- **Credential Stuffing:** Using leaked username/password pairs from other breaches")
        
        st.subheader("Detection Method")
        st.write("Brute force attacks are detected by monitoring for:")
        st.markdown("- Multiple failed login attempts from the same source")
        st.markdown("- Login attempts occurring at unusual speeds (faster than human typing)")
        st.markdown("- Login attempts outside of normal hours or from unusual locations")
        st.markdown("- Sequential or patterned login attempts")
        
        st.subheader("Log File Format")
        st.write("Example log entry:")
        st.code("# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service login_attempts user anomaly_type severity\n1741500373.12345 Hj3bNm7Kl0 192.168.1.75 192.168.1.20 22 tcp ssh 5 admin Brute_Force_SSH High", language="bash")
        
        st.subheader("Field Explanations:")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("- **ts**: Timestamp in UNIX epoch format")
            st.markdown("- **uid**: Unique identifier for the connection")
            st.markdown("- **id.orig_h**: Source IP address (attacker)")
            st.markdown("- **id.resp_h**: Destination IP address (target)")
            st.markdown("- **id.resp_p**: Destination port")
            st.markdown("- **proto**: Protocol used")
        with col2:
            st.markdown("- **service**: Service being targeted (ssh, ftp, etc.)")
            st.markdown("- **login_attempts**: Number of login attempts detected")
            st.markdown("- **user**: Username being targeted")
            st.markdown("- **anomaly_type**: Type of brute force attack detected")
            st.markdown("- **severity**: Severity level of the detected anomaly")
    
    # Data Exfiltration explanation
    with st.expander("Data Exfiltration", expanded=False):
        st.header("Data Exfiltration Attack")
        
        st.subheader("What is Data Exfiltration?")
        st.write("Data exfiltration is the unauthorized transfer of sensitive data from a system. It's often the final stage of an attack after an attacker has gained access and located valuable data.")
        
        st.subheader("How it Works")
        st.write("Attackers use various techniques to extract data, including:")
        st.markdown("- **DNS Tunneling:** Hiding data in DNS queries")
        st.markdown("- **ICMP Tunneling:** Embedding data in ICMP packets")
        st.markdown("- **Encrypted Channels:** Using encrypted connections to hide data transfer")
        st.markdown("- **Steganography:** Hiding data within other files or protocols")
        
        st.subheader("Detection Method")
        st.write("Data exfiltration is detected by monitoring for:")
        st.markdown("- Unusual outbound traffic patterns or volumes")
        st.markdown("- Large file transfers to external destinations")
        st.markdown("- Unexpected protocol usage (e.g., DNS with unusually large payloads)")
        st.markdown("- Communications with known malicious domains or unusual destinations")
        st.markdown("- Data transfers occurring at unusual times")
        
        st.subheader("Log File Format")
        st.write("Example log entry:")
        st.code("# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service data_size anomaly_type severity\n1741500374.56789 Pq5rSt8Uv1 192.168.1.60 8.8.8.8 53 udp dns 1000 DNS_Exfiltration High", language="bash")
        
        st.subheader("Field Explanations:")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("- **ts**: Timestamp in UNIX epoch format")
            st.markdown("- **uid**: Unique identifier for the connection")
            st.markdown("- **id.orig_h**: Source IP address (internal compromised host)")
            st.markdown("- **id.resp_h**: Destination IP address (external server)")
            st.markdown("- **id.resp_p**: Destination port")
        with col2:
            st.markdown("- **proto**: Protocol used")
            st.markdown("- **service**: Service being used for exfiltration")
            st.markdown("- **data_size**: Size of data being exfiltrated (in bytes)")
            st.markdown("- **anomaly_type**: Type of exfiltration detected")
            st.markdown("- **severity**: Severity level of the detected anomaly")
        
# Tab 4: Network Log Analyzer
with tab4:
    st.markdown("<h2 class='sub-header'>Network Log Analyzer</h2>", unsafe_allow_html=True)
    
    st.markdown("""
    The Network Log Analyzer uses AI to analyze and explain network attack logs. 
    It can help you understand the nature of attacks, their severity, and recommended mitigations.
    """)
    
    # Add a button to open the Network Log Analyzer in a new window
    if st.button("Launch Network Log Analyzer", type="primary", key="launch_analyzer"):
        # Open in a new window automatically
        import webbrowser
        webbrowser.open_new_tab("http://localhost:8001")
        st.success("Network Log Analyzer opened in a new window")
    
    # Add some information about the analyzer
    st.markdown("### Features")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("- **AI-Powered Analysis**: Uses Gemini and OpenAI models")
        st.markdown("- **Detailed Explanations**: Explains attack types and techniques")
        st.markdown("- **Severity Assessment**: Evaluates the risk level of detected attacks")
    
    with col2:
        st.markdown("- **Mitigation Recommendations**: Suggests security measures")
        st.markdown("- **Multiple Model Support**: Choose between different AI models")
        st.markdown("- **User-Friendly Interface**: Easy to use for security analysis")
    
    # Add a sample log for users to try
    st.markdown("### Sample Log to Try")
    sample_log = """1741500373.12345 Hj3bNm7Kl0 192.168.1.75 192.168.1.20 22 tcp ssh 5 admin Brute_Force_SSH High"""
    st.code(sample_log, language="bash")
    st.markdown("Copy this sample log to test the Network Log Analyzer functionality.")

# Tab 5: Settings (previously Tab 4)
with tab5:
    st.markdown("<h2 class='sub-header'>Settings</h2>", unsafe_allow_html=True)
    
    # Simulation settings
    st.markdown("### Simulation Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.number_input("Simulation Speed (attacks per minute)", min_value=1, max_value=60, value=10)
        st.selectbox("Default Attack Type", ["Random", "Port Scan", "DoS Attack", "Brute Force", "Data Exfiltration"], index=0)
    
    with col2:
        st.selectbox("Default Severity Level", ["Random", "Low", "Medium", "High", "Critical"], index=0)
        st.checkbox("Include Detailed Logs", value=True)
    
    # Log Analyzer settings
    st.markdown("### Log Analyzer Settings")
    st.text_input("Log Analyzer URL", value="http://localhost:8001")
    
    # Save settings button
    if st.button("Save Settings"):
        st.success("Settings saved successfully!")

# Footer
st.markdown("---")
st.markdown("""
<div class="footer-text">
    Network Attack Simulator | Educational Tool | 2025<br>
    <div class="author-info">
        <img src="https://cdn-icons-png.flaticon.com/512/174/174857.png" alt="LinkedIn">
        <span>Designed and developed by <a href="https://www.linkedin.com/in/lindsayhiebert/" target="_blank">Lindsay Hiebert</a></span>
    </div>
    <div>Icons provided by <a href="https://www.flaticon.com/" target="_blank">Flaticon</a></div>
</div>
""", unsafe_allow_html=True)
