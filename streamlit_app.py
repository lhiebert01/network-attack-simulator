import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import time
import os
import json
import subprocess
import sys
from datetime import datetime, timedelta

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
        background-color: var(--background-color);
        color: var(--text-color);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        border: 1px solid rgba(128, 128, 128, 0.2);
    }
    .attack-title {
        font-size: 1.2rem;
        font-weight: bold;
        margin-bottom: 10px;
        color: #1E88E5;
    }
    
    /* Dark mode support */
    @media (prefers-color-scheme: dark) {
        :root {
            --background-color: #2b2b2b;
            --text-color: #ffffff;
        }
        .attack-card {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        .attack-card p, .attack-card ul, .attack-card li {
            color: #ffffff !important;
        }
    }
    
    /* Light mode support */
    @media (prefers-color-scheme: light) {
        :root {
            --background-color: #f0f2f6;
            --text-color: #000000;
        }
        .attack-card {
            background-color: #f0f2f6;
            color: #000000;
        }
        .attack-card p, .attack-card ul, .attack-card li {
            color: #000000 !important;
        }
    }
    
    /* Ensure text is always visible regardless of theme */
    .attack-card p, .attack-card ul, .attack-card li {
        color: inherit;
    }
    .attack-card strong {
        font-weight: bold;
        color: inherit;
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

# Sidebar
with st.sidebar:
    st.markdown("<h2 class='sub-header'>Controls</h2>", unsafe_allow_html=True)
    
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
        format_func=lambda x: {
            "1m": "1 minute", 
            "5m": "5 minutes", 
            "15m": "15 minutes", 
            "30m": "30 minutes", 
            "1h": "1 hour", 
            "2h": "2 hours"
        }[x]
    )
    st.session_state.selected_time_range = time_range
    
    # About section
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    This simulator demonstrates common network attacks:
    - Port Scanning
    - DoS Attacks
    - Brute Force Attacks
    - Data Exfiltration
    
    For educational purposes only.
    """)
    
    # Link to Log Analyzer
    st.markdown("---")
    if st.button("Open Log Analyzer", type="primary"):
        st.markdown("[Open Log Analyzer in new window](http://localhost:8001)")
        st.info("Log Analyzer opened in a new window")

# Main content area - Tabs
tab1, tab2, tab3, tab4 = st.tabs(["Dashboard", "Attack Logs", "Attack Explanations", "Settings"])

# Tab 1: Dashboard
with tab1:
    st.markdown("<h2 class='sub-header'>Attack Simulation Dashboard</h2>", unsafe_allow_html=True)
    
    # Function to generate simulated attack data
    def generate_attack_data():
        current_time = datetime.now()
        time_range_map = {
            "1m": 1, "5m": 5, "15m": 15, "30m": 30,
            "1h": 60, "2h": 120
        }
        minutes = time_range_map[st.session_state.selected_time_range]
        start_time = current_time - timedelta(minutes=minutes)
        
        # Generate random attack data
        import random
        attack_types = ["Port Scan", "DoS Attack", "Brute Force", "Data Exfiltration"]
        severities = ["Low", "Medium", "High", "Critical"]
        
        # Create data points within the selected time range
        data_points = []
        for i in range(random.randint(5, 20)):
            attack_time = start_time + timedelta(minutes=random.randint(0, minutes))
            attack_type = random.choice(attack_types)
            severity = random.choice(severities)
            source_ip = f"192.168.1.{random.randint(100, 200)}"
            target_ip = f"192.168.1.{random.randint(1, 50)}"
            
            data_points.append({
                "timestamp": attack_time,
                "attack_type": attack_type,
                "severity": severity,
                "source_ip": source_ip,
                "target_ip": target_ip,
                "details": f"Simulated {attack_type} from {source_ip} to {target_ip}"
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
        st.dataframe(logs_df, use_container_width=True)
        
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
        st.markdown("""
        <div class="attack-card">
            <div class="attack-title">Port Scanning</div>
            <p><strong>Description:</strong> Port scanning is a technique used to discover open ports and services on a network host.</p>
            <p><strong>How it works:</strong> Attackers send packets to a range of port addresses on a host, analyzing responses to identify open ports, services running, and potential vulnerabilities.</p>
            <p><strong>Common types:</strong></p>
            <ul>
                <li><strong>TCP SYN Scan:</strong> Sends SYN packets and analyzes responses</li>
                <li><strong>TCP Connect Scan:</strong> Completes the TCP three-way handshake</li>
                <li><strong>UDP Scan:</strong> Sends UDP packets to identify open UDP ports</li>
            </ul>
            <p><strong>Detection methods:</strong> Network monitoring tools can detect unusual patterns of connection attempts across multiple ports.</p>
            <p><strong>Mitigation:</strong> Firewalls, intrusion detection systems, and proper network segmentation.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # DoS Attack explanation
    with st.expander("DoS Attack", expanded=False):
        st.markdown("""
        <div class="attack-card">
            <div class="attack-title">Denial of Service (DoS) Attack</div>
            <p><strong>Description:</strong> An attack aimed at making a system, service, or network unavailable to legitimate users.</p>
            <p><strong>How it works:</strong> Attackers flood the target with excessive traffic or requests, consuming resources until the system can no longer process legitimate requests.</p>
            <p><strong>Common types:</strong></p>
            <ul>
                <li><strong>SYN Flood:</strong> Sends many SYN packets without completing handshakes</li>
                <li><strong>HTTP Flood:</strong> Overwhelms a web server with HTTP requests</li>
                <li><strong>Ping of Death:</strong> Sends malformed or oversized ping packets</li>
            </ul>
            <p><strong>Detection methods:</strong> Monitoring for unusual traffic spikes, connection patterns, or resource utilization.</p>
            <p><strong>Mitigation:</strong> Rate limiting, traffic filtering, load balancing, and DDoS protection services.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Brute Force explanation
    with st.expander("Brute Force Attack", expanded=False):
        st.markdown("""
        <div class="attack-card">
            <div class="attack-title">Brute Force Attack</div>
            <p><strong>Description:</strong> A trial-and-error method used to discover passwords, encryption keys, or hidden pages.</p>
            <p><strong>How it works:</strong> Attackers systematically check all possible passwords or keys until the correct one is found.</p>
            <p><strong>Common types:</strong></p>
            <ul>
                <li><strong>Dictionary Attack:</strong> Uses a list of common passwords</li>
                <li><strong>Credential Stuffing:</strong> Uses previously breached username/password pairs</li>
                <li><strong>Rainbow Table Attack:</strong> Uses precomputed hash values</li>
            </ul>
            <p><strong>Detection methods:</strong> Monitoring for multiple failed login attempts from the same source.</p>
            <p><strong>Mitigation:</strong> Account lockout policies, CAPTCHA, multi-factor authentication, and strong password requirements.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Data Exfiltration explanation
    with st.expander("Data Exfiltration", expanded=False):
        st.markdown("""
        <div class="attack-card">
            <div class="attack-title">Data Exfiltration</div>
            <p><strong>Description:</strong> The unauthorized transfer of data from a computer or network.</p>
            <p><strong>How it works:</strong> Attackers extract sensitive data from a compromised system using various covert channels.</p>
            <p><strong>Common types:</strong></p>
            <ul>
                <li><strong>DNS Tunneling:</strong> Hides data in DNS queries</li>
                <li><strong>ICMP Tunneling:</strong> Embeds data in ICMP packets</li>
                <li><strong>Steganography:</strong> Hides data within files or protocols</li>
            </ul>
            <p><strong>Detection methods:</strong> Monitoring for unusual outbound traffic patterns, large data transfers, or connections to suspicious domains.</p>
            <p><strong>Mitigation:</strong> Data Loss Prevention (DLP) solutions, egress filtering, and network monitoring.</p>
        </div>
        """, unsafe_allow_html=True)

# Tab 4: Settings
with tab4:
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
st.markdown("Network Attack Simulator | Educational Tool | 2025")
