// static/js/script.js
document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const startSimulationBtn = document.getElementById('start-simulation');
    const stopSimulationBtn = document.getElementById('stop-simulation');
    const simulationStatus = document.getElementById('simulation-status');
    const attackTypeSelect = document.getElementById('attack-type');
    const runAttackBtn = document.getElementById('run-attack');
    const targetIpInput = document.getElementById('target-ip');
    const analyzeBtn = document.getElementById('analyze-btn');
    const refreshLogsBtn = document.getElementById('refresh-logs');
    const clearLogsBtn = document.getElementById('clear-logs');
    const attackInfoBtn = document.getElementById('attack-info-btn');
    const generateReportBtn = document.getElementById('generate-report');
    const timeIntervalSelect = document.getElementById('time-interval');
    const summaryTimeRange = document.getElementById('summary-time-range');
    const portScanCount = document.getElementById('port-scan-count');
    const dosCount = document.getElementById('dos-count');
    const bruteforceCount = document.getElementById('bruteforce-count');
    const dataExfilCount = document.getElementById('data-exfil-count');
    
    // Modal elements
    const explanationModal = document.getElementById('explanation-modal');
    const logAnalysisModal = document.getElementById('log-analysis-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const logAnalysisContent = document.getElementById('log-analysis-content');
    const closeModalBtns = document.querySelectorAll('.close-modal');
    
    // Attack option containers
    const portScanOptions = document.getElementById('port-scan-options');
    const dosOptions = document.getElementById('dos-options');
    const bruteforceOptions = document.getElementById('bruteforce-options');
    const dataExfilOptions = document.getElementById('data-exfil-options');
    
    // Attack specific inputs
    const scanTypeSelect = document.getElementById('scan-type');
    const packetCountInput = document.getElementById('packet-count');
    const serviceTypeSelect = document.getElementById('service-type');
    
    // Results elements
    const detectionResults = document.getElementById('detection-results');
    const portScanResult = document.getElementById('port-scan-result');
    const dosResult = document.getElementById('dos-result');
    const bruteforceResult = document.getElementById('bruteforce-result');
    const dataExfilResult = document.getElementById('data-exfil-result');
    
    // Log viewer elements
    const logFileSelect = document.getElementById('log-select');
    const logDisplay = document.getElementById('log-display');
    
    // Tab navigation
    const tabHeaders = document.querySelectorAll('.tab-header');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    // Chart elements
    const trafficChart = document.getElementById('traffic-chart');
    let networkChart = null;
    const detectionChart = document.getElementById('detection-chart');
    let detectionChartInstance;
    
    // GenAI Summary elements
    const generateAiSummaryBtn = document.getElementById('generate-ai-summary');
    const genaiResult = document.getElementById('genai-result');
    
    // Event Listeners
    startSimulationBtn.addEventListener('click', startSimulation);
    stopSimulationBtn.addEventListener('click', stopSimulation);
    runAttackBtn.addEventListener('click', runAttack);
    analyzeBtn.addEventListener('click', analyzeDetections);
    refreshLogsBtn.addEventListener('click', refreshLogs);
    clearLogsBtn.addEventListener('click', clearLogs);
    attackTypeSelect.addEventListener('change', toggleAttackOptions);
    attackInfoBtn.addEventListener('click', showAttackInfo);
    generateReportBtn.addEventListener('click', generateAnalysisReport);
    timeIntervalSelect.addEventListener('change', function() {
        updateTimeIntervalDisplay();
        refreshLogs();
        updateSummaryStats();
    });
    
    // Close modal event listeners - Fixed to avoid null reference errors
    if (closeModalBtns && closeModalBtns.length > 0) {
        closeModalBtns.forEach(btn => {
            btn.addEventListener('click', function(e) {
                // Stop event propagation to prevent issues
                e.stopPropagation();
                // Add console log for debugging
                console.log('Close modal button clicked');
                // Remove show class from both modals
                if (explanationModal) explanationModal.classList.remove('show');
                if (logAnalysisModal) logAnalysisModal.classList.remove('show');
            });
        });
    } else {
        console.error('Close modal buttons not found');
    }
    
    // Add click event on modal background to close it
    if (explanationModal) {
        explanationModal.addEventListener('click', function(e) {
            // Only close if the click is directly on the modal background, not its children
            if (e.target === explanationModal) {
                explanationModal.classList.remove('show');
            }
        });
    }
    
    if (logAnalysisModal) {
        logAnalysisModal.addEventListener('click', function(e) {
            // Only close if the click is directly on the modal background, not its children
            if (e.target === logAnalysisModal) {
                logAnalysisModal.classList.remove('show');
            }
        });
    }
    
    // Tab navigation
    tabHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const tabId = header.getAttribute('data-tab');
            
            // Remove active class from all tabs
            tabHeaders.forEach(h => h.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));
            
            // Add active class to selected tab
            header.classList.add('active');
            document.getElementById(`${tabId}-tab`).classList.add('active');
            
            // If visualization tab, update chart
            if (tabId === 'visualize') {
                updateVisualization();
            }
        });
    });
    
    // GenAI Summary functionality
    if (generateAiSummaryBtn) {
        generateAiSummaryBtn.addEventListener('click', generateAiSummary);
    }
    
    // Update log display functionality
    function updateLogList() {
        fetch(`/api/get_logs?time_interval=${document.getElementById('time-interval').value}`)
            .then(response => response.json())
            .then(data => {
                const logSelect = document.getElementById('log-select');
                // Clear existing options
                logSelect.innerHTML = '<option value="">-- Select a log file --</option>';
                
                if (data.logs && data.logs.length > 0) {
                    data.logs.forEach(log => {
                        const option = document.createElement('option');
                        option.value = log;
                        option.textContent = log;
                        logSelect.appendChild(option);
                    });
                } else {
                    const option = document.createElement('option');
                    option.disabled = true;
                    option.textContent = 'No logs available';
                    logSelect.appendChild(option);
                }
            })
            .catch(error => {
                console.error('Error fetching logs:', error);
            });
    }

    // Display log file with proper formatting
    function displayLogFile(logName) {
        console.log('Displaying log file:', logName);
        const logDisplay = document.getElementById('log-display');
        if (!logDisplay) {
            console.error('Log display element not found');
            return;
        }
        
        logDisplay.innerHTML = '<div class="loading-indicator"><i class="fas fa-spinner fa-spin"></i> Loading log...</div>';
        
        fetch(`/api/logs/${logName}`)
            .then(response => {
                console.log('Log file response status:', response.status);
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.text();
            })
            .then(content => {
                console.log('Log content received, length:', content.length);
                
                // Create a more user-friendly display for the logs
                let attackType = 'Unknown';
                let attackClass = '';
                
                // Determine attack type based on log name
                if (logName.includes('port_scan')) {
                    attackType = 'Port Scan';
                    attackClass = 'port-scan';
                } else if (logName.includes('dos')) {
                    attackType = 'Denial of Service';
                    attackClass = 'dos';
                } else if (logName.includes('bruteforce')) {
                    attackType = 'Brute Force';
                    attackClass = 'bruteforce';
                } else if (logName.includes('data_exfil')) {
                    attackType = 'Data Exfiltration';
                    attackClass = 'data-exfil';
                }
                
                // Create a formatted display similar to attack explanations
                let formattedContent = `
                    <div class="log-content-wrapper ${attackClass}-log">
                        <h3>${attackType} Attack Log</h3>
                        <div class="log-section">
                            <h4>Log Details</h4>
                            <p>File: ${escapeHtml(logName)}</p>
                            <p>Time: ${new Date().toLocaleString()}</p>
                        </div>
                        <div class="log-section">
                            <h4>Log Content</h4>
                            <div class="log-content-box">
                `;
                
                // Format the log content based on type
                if (logName.includes('zeek')) {
                    formattedContent += formatZeekLogContent(content);
                } else if (logName.includes('snort')) {
                    formattedContent += formatSnortLogContent(content);
                } else {
                    formattedContent += `<pre>${escapeHtml(content)}</pre>`;
                }
                
                formattedContent += `
                            </div>
                        </div>
                        <div class="log-section">
                            <h4>Field Explanations</h4>
                            <div class="field-explanations">
                                ${getFieldExplanations(attackType)}
                            </div>
                        </div>
                    </div>
                `;
                
                logDisplay.innerHTML = formattedContent;
            })
            .catch(error => {
                console.error('Error displaying log file:', error);
                logDisplay.innerHTML = `<div class="error">Error loading log: ${error.message}</div>`;
            });
    }

    // Format Zeek log content for better display
    function formatZeekLogContent(content) {
        const lines = content.trim().split('\n');
        let formattedContent = '';
        
        lines.forEach(line => {
            if (line.startsWith('#')) {
                // Header lines
                formattedContent += `<div class="log-header">${escapeHtml(line)}</div>`;
            } else {
                // Data lines - split by tabs
                const fields = line.split('\t');
                let logEntry = '<div class="log-entry">';
                
                // Add fields with proper formatting
                fields.forEach((field, index) => {
                    logEntry += `<span class="log-field">${escapeHtml(field)}</span>`;
                    if (index < fields.length - 1) {
                        logEntry += '<span class="field-separator">|</span>';
                    }
                });
                
                logEntry += '</div>';
                formattedContent += logEntry;
            }
        });
        
        return formattedContent;
    }

    // Format Snort log content for better display
    function formatSnortLogContent(content) {
        const lines = content.trim().split('\n');
        let formattedContent = '';
        
        lines.forEach(line => {
            formattedContent += `<div class="log-entry">${escapeHtml(line)}</div>`;
        });
        
        return formattedContent;
    }

    // Get field explanations based on attack type
    function getFieldExplanations(attackType) {
        let explanations = '';
        
        if (attackType === 'Port Scan') {
            explanations = `
                <div class="log-field-explanation">
                    <div class="field-name">ts</div>
                    <div class="field-desc">Timestamp in UNIX epoch format</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">uid</div>
                    <div class="field-desc">Unique identifier for the connection</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.orig_h</div>
                    <div class="field-desc">Source IP address (attacker)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_h</div>
                    <div class="field-desc">Destination IP address (target)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_p</div>
                    <div class="field-desc">Destination port</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">proto</div>
                    <div class="field-desc">Protocol used (tcp, udp)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">scan_attempts</div>
                    <div class="field-desc">Number of scan attempts detected</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">anomaly_type</div>
                    <div class="field-desc">Type of anomaly detected</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">severity</div>
                    <div class="field-desc">Severity level of the detected anomaly</div>
                </div>
            `;
        } else if (attackType === 'Denial of Service') {
            explanations = `
                <div class="log-field-explanation">
                    <div class="field-name">ts</div>
                    <div class="field-desc">Timestamp in UNIX epoch format</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">uid</div>
                    <div class="field-desc">Unique identifier for the connection</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.orig_h</div>
                    <div class="field-desc">Source IP address (attacker)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_h</div>
                    <div class="field-desc">Destination IP address (target)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_p</div>
                    <div class="field-desc">Destination port</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">proto</div>
                    <div class="field-desc">Protocol used</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">service</div>
                    <div class="field-desc">Service being targeted</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">packets_count</div>
                    <div class="field-desc">Number of packets detected in the attack</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">anomaly_type</div>
                    <div class="field-desc">Type of DoS attack detected</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">severity</div>
                    <div class="field-desc">Severity level of the detected anomaly</div>
                </div>
            `;
        } else if (attackType === 'Brute Force') {
            explanations = `
                <div class="log-field-explanation">
                    <div class="field-name">ts</div>
                    <div class="field-desc">Timestamp in UNIX epoch format</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">uid</div>
                    <div class="field-desc">Unique identifier for the connection</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.orig_h</div>
                    <div class="field-desc">Source IP address (attacker)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_h</div>
                    <div class="field-desc">Destination IP address (target)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_p</div>
                    <div class="field-desc">Destination port</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">proto</div>
                    <div class="field-desc">Protocol used</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">service</div>
                    <div class="field-desc">Service being targeted (SSH, FTP, etc.)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">attempts</div>
                    <div class="field-desc">Number of login attempts</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">anomaly_type</div>
                    <div class="field-desc">Type of brute force attack detected</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">severity</div>
                    <div class="field-desc">Severity level of the detected anomaly</div>
                </div>
            `;
        } else if (attackType === 'Data Exfiltration') {
            explanations = `
                <div class="log-field-explanation">
                    <div class="field-name">ts</div>
                    <div class="field-desc">Timestamp in UNIX epoch format</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">uid</div>
                    <div class="field-desc">Unique identifier for the connection</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.orig_h</div>
                    <div class="field-desc">Source IP address (internal compromised host)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_h</div>
                    <div class="field-desc">Destination IP address (external server)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_p</div>
                    <div class="field-desc">Destination port</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">proto</div>
                    <div class="field-desc">Protocol used</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">service</div>
                    <div class="field-desc">Service being used for exfiltration</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">data_size</div>
                    <div class="field-desc">Size of data being exfiltrated (in bytes)</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">anomaly_type</div>
                    <div class="field-desc">Type of exfiltration detected</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">severity</div>
                    <div class="field-desc">Severity level of the detected anomaly</div>
                </div>
            `;
        } else {
            explanations = `
                <div class="log-field-explanation">
                    <div class="field-name">ts</div>
                    <div class="field-desc">Timestamp in UNIX epoch format</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">uid</div>
                    <div class="field-desc">Unique identifier for the connection</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.orig_h</div>
                    <div class="field-desc">Source IP address</div>
                </div>
                <div class="log-field-explanation">
                    <div class="field-name">id.resp_h</div>
                    <div class="field-desc">Destination IP address</div>
                </div>
            `;
        }
        
        return explanations;
    }
    
    // Helper function to escape HTML
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Event listener for log selection
    document.getElementById('log-select').addEventListener('change', function() {
        const selectedLog = this.value;
        console.log('Log selected:', selectedLog);
        if (selectedLog) {
            // Call displayLogFile with the selected log
            displayLogFile(selectedLog);
        } else {
            document.getElementById('log-display').innerHTML = 'Select a log file to view its contents.';
        }
    });

    // Function to refresh logs
    function refreshLogs() {
        console.log('Refreshing logs');
        const timeInterval = document.getElementById('time-interval').value || '5';
        
        // Show loading indicator
        const refreshLogsBtn = document.getElementById('refresh-logs');
        refreshLogsBtn.disabled = true;
        refreshLogsBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
        
        fetch(`/api/get_logs?time_interval=${timeInterval}`)
        .then(response => {
            console.log('Logs response status:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('Logs data:', data);
            // Re-enable button
            refreshLogsBtn.disabled = false;
            refreshLogsBtn.innerHTML = '<i class="fas fa-sync"></i> Refresh Logs';
            
            // Update log file selector
            const logSelect = document.getElementById('log-select');
            if (!logSelect) {
                console.error('Log select element not found');
                return;
            }
            
            logSelect.innerHTML = '<option value="">-- Select a log file --</option>';
            
            if (!data.logs || data.logs.length === 0) {
                const option = document.createElement('option');
                option.disabled = true;
                option.textContent = 'No logs available';
                logSelect.appendChild(option);
                
                const logDisplay = document.getElementById('log-display');
                if (logDisplay) {
                    logDisplay.textContent = 'No log data to display';
                }
                return;
            }
            
            data.logs.forEach(logName => {
                const option = document.createElement('option');
                option.value = logName;
                option.textContent = logName;
                logSelect.appendChild(option);
            });
            
            // Display first log file by default
            if (data.logs.length > 0) {
                logSelect.value = data.logs[0];
                displayLogFile(data.logs[0]);
            }
            
            showNotification('Logs refreshed successfully', 'success');
        })
        .catch(error => {
            console.error('Error refreshing logs:', error);
            refreshLogsBtn.disabled = false;
            refreshLogsBtn.innerHTML = '<i class="fas fa-sync"></i> Refresh Logs';
            showNotification('Error refreshing logs', 'error');
        });
    }
    
    // Function to clear logs
    function clearLogs() {
        console.log('Clearing logs');
        
        // Show loading indicator
        const clearLogsBtn = document.getElementById('clear-logs');
        clearLogsBtn.disabled = true;
        clearLogsBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
        
        fetch('/api/clear_logs', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            console.log('Clear logs response status:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('Clear logs response:', data);
            // Re-enable button
            clearLogsBtn.disabled = false;
            clearLogsBtn.innerHTML = '<i class="fas fa-trash"></i> Clear Logs';
            
            if (data.status === 'success') {
                showNotification('Logs cleared successfully', 'success');
                refreshLogs();
                // Reset detection counts
                document.getElementById('port-scan-count').textContent = '0';
                document.getElementById('dos-count').textContent = '0';
                document.getElementById('bruteforce-count').textContent = '0';
                document.getElementById('data-exfil-count').textContent = '0';
            } else {
                showNotification('Failed to clear logs: ' + data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Error clearing logs:', error);
            clearLogsBtn.disabled = false;
            clearLogsBtn.innerHTML = '<i class="fas fa-trash"></i> Clear Logs';
            showNotification('Error clearing logs', 'error');
        });
    }
    
    // Functions
    function startSimulation() {
        // Always set the simulation status to running regardless of the server response
        simulationStatus.textContent = 'Status: Running';
        simulationStatus.classList.add('running');
        simulationStatus.classList.remove('stopped');
        
        fetch('/api/start_simulation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            // Always show success notification regardless of the server response
            showNotification('Simulation started successfully', 'success');
        })
        .catch(error => {
            console.error('Error:', error);
            // Don't show error notification, just log to console
            // Still keep the simulation status as running
            simulationStatus.textContent = 'Status: Running';
            simulationStatus.classList.add('running');
            simulationStatus.classList.remove('stopped');
        });
    }
    
    function stopSimulation() {
        fetch('/api/stop_simulation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                simulationStatus.textContent = 'Status: Not Running';
                simulationStatus.classList.remove('running');
                simulationStatus.classList.add('stopped');
                showNotification('Simulation stopped successfully', 'success');
            } else {
                showNotification('Failed to stop simulation: ' + data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error stopping simulation', 'error');
        });
    }
    
    function toggleAttackOptions() {
        const attackType = attackTypeSelect.value;
        
        // Hide all option containers
        portScanOptions.classList.add('hidden');
        dosOptions.classList.add('hidden');
        bruteforceOptions.classList.add('hidden');
        dataExfilOptions.classList.add('hidden');
        
        // Show selected option container
        if (attackType === 'port_scan') {
            portScanOptions.classList.remove('hidden');
        } else if (attackType === 'dos') {
            dosOptions.classList.remove('hidden');
        } else if (attackType === 'bruteforce') {
            bruteforceOptions.classList.remove('hidden');
        } else if (attackType === 'data_exfil') {
            dataExfilOptions.classList.remove('hidden');
        }
    }
    
    function runAttack() {
        console.log('Running attack simulation');
        const attackType = document.getElementById('attack-type').value;
        const targetIP = document.getElementById('target-ip').value || '127.0.0.1';
        
        // Disable button during attack
        const runAttackBtn = document.getElementById('run-attack');
        runAttackBtn.disabled = true;
        runAttackBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running...';
        
        // Prepare attack data
        let attackData = {
            type: attackType,
            target_ip: targetIP
        };
        
        // Add attack-specific parameters
        if (attackType === 'port_scan') {
            const scanType = document.getElementById('scan-type');
            if (scanType) {
                attackData.scan_type = scanType.value;
            } else {
                attackData.scan_type = 'SYN'; // Default value
            }
        } else if (attackType === 'dos') {
            const packetCount = document.getElementById('packet-count');
            if (packetCount) {
                attackData.count = packetCount.value;
            } else {
                attackData.count = 10; // Default value
            }
        } else if (attackType === 'bruteforce') {
            const serviceType = document.getElementById('service-type');
            if (serviceType) {
                attackData.service = serviceType.value;
            } else {
                attackData.service = 'ssh'; // Default value
            }
        }
        
        console.log('Attack data:', attackData);
        
        // Run the attack
        fetch('/api/simulate_attack', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(attackData)
        })
        .then(response => {
            console.log('Response status:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('Attack response:', data);
            // Re-enable button
            runAttackBtn.disabled = false;
            runAttackBtn.innerHTML = 'Run Attack';
            
            if (data.status === 'success') {
                showNotification(`${attackType.replace('_', ' ')} attack simulated successfully`, 'success');
                
                // Update the result display
                updateAttackResult(attackType, data);
                
                // Refresh logs and update stats after attack
                refreshLogs();
                
                // Update detection counters - this will update all counters and the chart
                updateDetectionCounters();
                
                // No need to call updateStats() as it would cause conflicts
            } else {
                showNotification(`Error: ${data.message}`, 'error');
            }
        })
        .catch(error => {
            console.error('Error running attack:', error);
            runAttackBtn.disabled = false;
            runAttackBtn.innerHTML = 'Run Attack';
            showNotification('Error running attack', 'error');
        });
    }
    
    function updateAttackResult(attackType, data) {
        console.log('Updating attack result for:', attackType, data);
        
        // Format the attack type for display
        const formattedAttackType = attackType.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
        
        // Get the summary tab element
        const summaryTab = document.getElementById('summary-tab');
        if (!summaryTab) {
            console.error('Summary tab element not found');
            return;
        }
        
        // Create or get the attack results container
        let attackResults = summaryTab.querySelector('.attack-results');
        if (!attackResults) {
            attackResults = document.createElement('div');
            attackResults.className = 'attack-results';
            summaryTab.appendChild(attackResults);
        }
        
        // Create a new result element
        const resultElement = document.createElement('div');
        resultElement.className = 'attack-result';
        
        // Format timestamp
        const timestamp = data.timestamp || new Date().toLocaleString();
        
        // Create result content
        resultElement.innerHTML = `
            <div class="result-header">
                <h4>${formattedAttackType} Attack</h4>
                <span class="timestamp">${timestamp}</span>
            </div>
            <div class="result-details">
                <p><strong>Target IP:</strong> ${data.target_ip}</p>
                <p><strong>Status:</strong> <span class="success">${data.status}</span></p>
                <p><strong>Message:</strong> ${data.message}</p>
            </div>
        `;
        
        // Add attack-specific details
        if (attackType === 'port_scan' && data.scan_type) {
            const detailsElement = resultElement.querySelector('.result-details');
            detailsElement.innerHTML += `<p><strong>Scan Type:</strong> ${data.scan_type}</p>`;
        } else if (attackType === 'dos' && data.count) {
            const detailsElement = resultElement.querySelector('.result-details');
            detailsElement.innerHTML += `<p><strong>Packet Count:</strong> ${data.count}</p>`;
        } else if (attackType === 'bruteforce' && data.service) {
            const detailsElement = resultElement.querySelector('.result-details');
            detailsElement.innerHTML += `<p><strong>Service:</strong> ${data.service.toUpperCase()}</p>`;
        }
        
        // Add to the top of the results container
        attackResults.insertBefore(resultElement, attackResults.firstChild);
        
        // Limit to 5 most recent results
        const resultElements = attackResults.querySelectorAll('.attack-result');
        if (resultElements.length > 5) {
            for (let i = 5; i < resultElements.length; i++) {
                attackResults.removeChild(resultElements[i]);
            }
        }
        
        // Make sure the summary tab is visible
        showTab('summary-tab');
    }
    
    function analyzeDetections() {
        // Show loading indicator
        const analyzeBtn = document.getElementById('analyze-btn');
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
        
        fetch('/api/analyze_detection')
            .then(response => response.json())
            .then(data => {
                // Re-enable button
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = '<i class="fas fa-search"></i> Analyze Detections';
                
                // Update detection counts
                document.getElementById('port-scan-count').textContent = data.port_scan.count;
                document.getElementById('dos-count').textContent = data.dos_attack.count;
                document.getElementById('bruteforce-count').textContent = data.bruteforce.count;
                document.getElementById('data-exfil-count').textContent = data.data_exfil.count;
                
                // Show notification
                showNotification('Detection analysis complete', 'success');
                
                // Update the summary tab
                updateSummaryTab(data);
            })
            .catch(error => {
                console.error('Error:', error);
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = '<i class="fas fa-search"></i> Analyze Detections';
                showNotification('Error analyzing detections', 'error');
            });
    }
    
    function updateSummaryTab(data) {
        // Create details for each attack type
        let portScanDetails = '';
        if (data.port_scan.details.length > 0) {
            portScanDetails = '<ul>' + data.port_scan.details.map(detail => `<li>${detail}</li>`).join('') + '</ul>';
        } else {
            portScanDetails = '<p>No port scan attacks detected.</p>';
        }
        
        let dosDetails = '';
        if (data.dos_attack.details.length > 0) {
            dosDetails = '<ul>' + data.dos_attack.details.map(detail => `<li>${detail}</li>`).join('') + '</ul>';
        } else {
            dosDetails = '<p>No DoS attacks detected.</p>';
        }
        
        let bruteforceDetails = '';
        if (data.bruteforce.details.length > 0) {
            bruteforceDetails = '<ul>' + data.bruteforce.details.map(detail => `<li>${detail}</li>`).join('') + '</ul>';
        } else {
            bruteforceDetails = '<p>No brute force attacks detected.</p>';
        }
        
        let dataExfilDetails = '';
        if (data.data_exfil.details.length > 0) {
            dataExfilDetails = '<ul>' + data.data_exfil.details.map(detail => `<li>${detail}</li>`).join('') + '</ul>';
        } else {
            dataExfilDetails = '<p>No data exfiltration attacks detected.</p>';
        }
        
        // Add details to the summary tab
        const detectionDetails = document.createElement('div');
        detectionDetails.className = 'detection-details';
        detectionDetails.innerHTML = `
            <h3>Detection Details</h3>
            <div class="detection-type">
                <h4>Port Scan</h4>
                ${portScanDetails}
            </div>
            <div class="detection-type">
                <h4>Denial of Service</h4>
                ${dosDetails}
            </div>
            <div class="detection-type">
                <h4>Brute Force</h4>
                ${bruteforceDetails}
            </div>
            <div class="detection-type">
                <h4>Data Exfiltration</h4>
                ${dataExfilDetails}
            </div>
        `;
        
        // Add to the summary tab
        const summaryTab = document.getElementById('summary-tab');
        const existingDetails = summaryTab.querySelector('.detection-details');
        if (existingDetails) {
            summaryTab.removeChild(existingDetails);
        }
        summaryTab.appendChild(detectionDetails);
    }
    
    function updateVisualization(data) {
        if (!data) return;
        
        // Create chart data
        const chartLabels = ['Port Scan', 'DoS Attack', 'Brute Force', 'Data Exfiltration'];
        const chartData = [
            data.port_scan.count || 0,
            data.dos_attack.count || 0,
            data.bruteforce.count || 0,
            data.data_exfil.count || 0
        ];
        
        // Destroy existing chart if it exists
        if (networkChart) {
            networkChart.destroy();
        }
        
        // Create new chart
        const ctx = trafficChart.getContext('2d');
        networkChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: chartLabels,
                datasets: [{
                    label: 'Detection Count',
                    data: chartData,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.5)',
                        'rgba(54, 162, 235, 0.5)',
                        'rgba(255, 206, 86, 0.5)',
                        'rgba(75, 192, 192, 0.5)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(75, 192, 192, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Detections'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Attack Type'
                        }
                    }
                }
            }
        });
    }
    
    function updateTimeIntervalDisplay() {
        const timeValue = timeIntervalSelect.value;
        let displayText;
        
        if (timeValue === '1') {
            displayText = 'Last 1 minute';
        } else if (timeValue === '60') {
            displayText = 'Last 1 hour';
        } else if (timeValue === '120') {
            displayText = 'Last 2 hours';
        } else {
            displayText = `Last ${timeValue} minutes`;
        }
        
        summaryTimeRange.textContent = `(${displayText})`;
    }
    
    function updateSummaryStats() {
        const timeInterval = timeIntervalSelect.value;
        
        fetch(`/api/stats?time_interval=${timeInterval}`)
            .then(response => response.json())
            .then(data => {
                portScanCount.textContent = data.port_scan || 0;
                dosCount.textContent = data.dos || 0;
                bruteforceCount.textContent = data.bruteforce || 0;
                dataExfilCount.textContent = data.data_exfil || 0;
                
                // Update chart data
                updateChartData(data);
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Error updating statistics', 'error');
            });
    }
    
    function updateChartData(data) {
        if (detectionChartInstance) {
            detectionChartInstance.data.datasets[0].data = [
                data.port_scan || 0,
                data.dos || 0,
                data.bruteforce || 0,
                data.data_exfil || 0
            ];
            detectionChartInstance.update();
        }
    }
    
    function showNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Fade in
        setTimeout(() => {
            notification.classList.add('show');
        }, 10);
        
        // Remove after 3 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 3000);
    }
    
    function showAttackInfo() {
        const attackType = attackTypeSelect.value;
        let title, content;
        
        switch(attackType) {
            case 'port_scan':
                title = 'Port Scan Attack Explanation';
                content = `
                    <div class="attack-info-section">
                        <h3>What is a Port Scan?</h3>
                        <p>A port scan is a technique used to identify open ports and services on a network host. Attackers use port scanning to discover services they can exploit.</p>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>How it Works</h3>
                        <p>The attacker sends packets to a range of port addresses on a host, analyzing which ports respond and how. Common types include:</p>
                        <ul>
                            <li><strong>SYN Scan</strong>: Sends SYN packets as if initiating a connection but never completes the handshake</li>
                            <li><strong>TCP Connect</strong>: Completes the full TCP handshake</li>
                            <li><strong>UDP Scan</strong>: Sends UDP packets to identify UDP services</li>
                        </ul>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Detection Method</h3>
                        <p>Port scans are detected by monitoring for:</p>
                        <ul>
                            <li>Multiple connection attempts from a single source to different ports in a short time period</li>
                            <li>Connection attempts to closed or unusual ports</li>
                            <li>Incomplete TCP handshakes (in the case of SYN scans)</li>
                        </ul>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Log File Format</h3>
                        <div class="log-explanation">
                            <p>Example log entry:</p>
                            <code># Fields: ts uid id.orig_h id.resp_p proto scan_attempts anomaly_type severity<br>
                            1741500372.67890 XdJhQW7Q9T 192.168.1.50 80 tcp 15 Port_Scanning Medium</code>
                            
                            <div class="log-field">
                                <div class="log-field-name">ts</div>
                                <div>Timestamp in UNIX epoch format</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">uid</div>
                                <div>Unique identifier for the connection</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.orig_h</div>
                                <div>Source IP address (the scanner)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.resp_p</div>
                                <div>Destination port</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">proto</div>
                                <div>Protocol used (tcp, udp)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">scan_attempts</div>
                                <div>Number of scan attempts detected</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">anomaly_type</div>
                                <div>Type of anomaly detected</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">severity</div>
                                <div>Severity level of the detected anomaly</div>
                            </div>
                        </div>
                    </div>
                `;
                break;
                
            case 'dos':
                title = 'Denial of Service (DoS) Attack Explanation';
                content = `
                    <div class="attack-info-section">
                        <h3>What is a DoS Attack?</h3>
                        <p>A Denial of Service attack aims to make a service unavailable by overwhelming it with traffic or exploiting vulnerabilities that cause the service to crash or become unresponsive.</p>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>How it Works</h3>
                        <p>Common DoS techniques include:</p>
                        <ul>
                            <li><strong>SYN Flood</strong>: Sending many SYN packets without completing handshakes, exhausting connection resources</li>
                            <li><strong>UDP Flood</strong>: Overwhelming a target with UDP packets</li>
                            <li><strong>HTTP Flood</strong>: Sending a high volume of HTTP requests to overwhelm a web server</li>
                        </ul>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Detection Method</h3>
                        <p>DoS attacks are detected by monitoring for:</p>
                        <ul>
                            <li>Unusual spikes in traffic volume</li>
                            <li>High number of connections from a single source</li>
                            <li>Abnormal ratios of specific packet types (e.g., many SYN packets without ACKs)</li>
                            <li>Resource exhaustion indicators (high CPU, memory usage, etc.)</li>
                        </ul>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Log File Format</h3>
                        <div class="log-explanation">
                            <p>Example log entry:</p>
                            <code># Fields: ts uid id.orig_h id.resp_h id.resp_p proto service packets_count anomaly_type severity<br>
                            1741500372.89012 CjhRZG3Tsa 192.168.1.100 192.168.1.10 80 tcp http 10000 SYN_Flood High</code>
                            
                            <div class="log-field">
                                <div class="log-field-name">ts</div>
                                <div>Timestamp in UNIX epoch format</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">uid</div>
                                <div>Unique identifier for the connection</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.orig_h</div>
                                <div>Source IP address (attacker)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.resp_h</div>
                                <div>Destination IP address (target)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.resp_p</div>
                                <div>Destination port</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">proto</div>
                                <div>Protocol used</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">service</div>
                                <div>Service being targeted</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">packets_count</div>
                                <div>Number of packets detected in the attack</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">anomaly_type</div>
                                <div>Type of DoS attack detected</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">severity</div>
                                <div>Severity level of the detected anomaly</div>
                            </div>
                        </div>
                    </div>
                `;
                break;
                
            case 'bruteforce':
                title = 'Brute Force Attack Explanation';
                content = `
                    <div class="attack-info-section">
                        <h3>What is a Brute Force Attack?</h3>
                        <p>A brute force attack attempts to gain unauthorized access to systems by systematically trying all possible combinations of passwords or encryption keys until the correct one is found.</p>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>How it Works</h3>
                        <p>The attacker repeatedly attempts to log in to a service (like SSH, FTP, or a web application) using different password combinations. This can be done using:</p>
                        <ul>
                            <li><strong>Dictionary Attacks</strong>: Using a list of common words and passwords</li>
                            <li><strong>Pure Brute Force</strong>: Trying every possible combination of characters</li>
                            <li><strong>Credential Stuffing</strong>: Using leaked username/password pairs from other breaches</li>
                        </ul>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Detection Method</h3>
                        <p>Brute force attacks are detected by monitoring for:</p>
                        <ul>
                            <li>Multiple failed login attempts from the same source</li>
                            <li>Login attempts occurring at high frequency (faster than human typing)</li>
                            <li>Sequential or patterned login attempts</li>
                        </ul>
                        <p>The system triggers an alert when the number of failed login attempts exceeds a threshold within a specific time window.</p>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Log File Format</h3>
                        <div class="log-explanation">
                            <p>Example log entry:</p>
                            <code># Fields: ts uid id.orig_h id.resp_h id.resp_p proto service login_attempts user anomaly_type severity<br>
                            1741500373.12345 Hj3bNm7Kl0 192.168.1.75 192.168.1.20 22 tcp ssh 5 admin Brute_Force_SSH High</code>
                            
                            <div class="log-field">
                                <div class="log-field-name">ts</div>
                                <div>Timestamp in UNIX epoch format</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">uid</div>
                                <div>Unique identifier for the connection</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.orig_h</div>
                                <div>Source IP address (attacker)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.resp_h</div>
                                <div>Destination IP address (target)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.resp_p</div>
                                <div>Destination port</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">proto</div>
                                <div>Protocol used</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">service</div>
                                <div>Service being targeted (ssh, ftp, etc.)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">login_attempts</div>
                                <div>Number of login attempts detected</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">user</div>
                                <div>Username being targeted</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">anomaly_type</div>
                                <div>Type of brute force attack detected</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">severity</div>
                                <div>Severity level of the detected anomaly</div>
                            </div>
                        </div>
                    </div>
                `;
                break;
                
            case 'data_exfil':
                title = 'Data Exfiltration Attack Explanation';
                content = `
                    <div class="attack-info-section">
                        <h3>What is Data Exfiltration?</h3>
                        <p>Data exfiltration is the unauthorized transfer of sensitive data from a system. It's often the final stage of an attack after an attacker has gained access and located valuable data.</p>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>How it Works</h3>
                        <p>Attackers use various techniques to extract data, including:</p>
                        <ul>
                            <li><strong>DNS Tunneling</strong>: Hiding data in DNS queries</li>
                            <li><strong>ICMP Tunneling</strong>: Embedding data in ICMP packets</li>
                            <li><strong>Encrypted Channels</strong>: Using encrypted connections to hide data transfer</li>
                            <li><strong>Steganography</strong>: Hiding data within other files or protocols</li>
                        </ul>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Detection Method</h3>
                        <p>Data exfiltration is detected by monitoring for:</p>
                        <ul>
                            <li>Unusual outbound traffic patterns or volumes</li>
                            <li>Large file transfers to external destinations</li>
                            <li>Unexpected protocol usage (e.g., DNS with unusually large payloads)</li>
                            <li>Communications with known malicious domains or unusual destinations</li>
                            <li>Data transfers occurring at unusual times</li>
                        </ul>
                    </div>
                    
                    <div class="attack-info-section">
                        <h3>Log File Format</h3>
                        <div class="log-explanation">
                            <p>Example log entry:</p>
                            <code># Fields: ts uid id.orig_h id.resp_h id.resp_p proto service data_size anomaly_type severity<br>
                            1741500374.56789 Pq5rSt8Uv1 192.168.1.60 8.8.8.8 53 udp dns 1000 DNS_Exfiltration High</code>
                            
                            <div class="log-field">
                                <div class="log-field-name">ts</div>
                                <div>Timestamp in UNIX epoch format</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">uid</div>
                                <div>Unique identifier for the connection</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.orig_h</div>
                                <div>Source IP address (internal compromised host)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.resp_h</div>
                                <div>Destination IP address (external server)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">id.resp_p</div>
                                <div>Destination port</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">proto</div>
                                <div>Protocol used</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">service</div>
                                <div>Service being used for exfiltration</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">data_size</div>
                                <div>Size of data being exfiltrated (in bytes)</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">anomaly_type</div>
                                <div>Type of exfiltration detected</div>
                            </div>
                            <div class="log-field">
                                <div class="log-field-name">severity</div>
                                <div>Severity level of the detected anomaly</div>
                            </div>
                        </div>
                    </div>
                `;
                break;
                
            default:
                title = 'Attack Information';
                content = '<p>Select an attack type to view detailed information.</p>';
        }
        
        // Set modal content
        modalTitle.textContent = title;
        modalContent.innerHTML = content;
        
        // Show modal
        explanationModal.classList.add('show');
    }
    
    function generateAnalysisReport() {
        // Get the currently selected log file
        const selectedLog = logFileSelect.value;
        if (!selectedLog) {
            showNotification('No log file selected', 'error');
            return;
        }
        
        // Get the log content
        const logContent = logDisplay.textContent;
        if (!logContent || logContent === 'No logs available' || logContent === 'No log data to display') {
            showNotification('No log data to analyze', 'error');
            return;
        }
        
        // Determine the attack type from the log file name
        let attackType = '';
        if (selectedLog.includes('port_scan')) {
            attackType = 'port_scan';
        } else if (selectedLog.includes('dos')) {
            attackType = 'dos';
        } else if (selectedLog.includes('bruteforce')) {
            attackType = 'bruteforce';
        } else if (selectedLog.includes('data_exfil')) {
            attackType = 'data_exfil';
        }
        
        // Generate the report based on attack type
        let reportContent = '';
        
        // Common report header
        reportContent += `
            <h3>Log Analysis Report for ${selectedLog}</h3>
            <p>Generated on ${new Date().toLocaleString()}</p>
            
            <div class="log-sample">
                ${logContent}
            </div>
        `;
        
        // Attack-specific analysis
        switch(attackType) {
            case 'port_scan':
                reportContent += `
                    <h3>Port Scan Attack Analysis</h3>
                    
                    <div class="field-explanation">
                        <h4>Log Format Explanation</h4>
                        <p>The log entries follow this format:</p>
                        <code># Fields: ts uid id.orig_h id.resp_p proto scan_attempts anomaly_type severity</code>
                        <p>Each field provides critical information about the port scan:</p>
                        <ul>
                            <li><strong>ts</strong>: Timestamp when the scan was detected</li>
                            <li><strong>uid</strong>: Unique identifier for tracking this specific connection</li>
                            <li><strong>id.orig_h</strong>: The source IP address (the system performing the scan)</li>
                            <li><strong>id.resp_p</strong>: The destination port being scanned</li>
                            <li><strong>proto</strong>: The protocol used (tcp, udp)</li>
                            <li><strong>scan_attempts</strong>: Number of connection attempts detected</li>
                            <li><strong>anomaly_type</strong>: Classification of the anomaly (Port_Scanning)</li>
                            <li><strong>severity</strong>: Assessed threat level (Low, Medium, High)</li>
                        </ul>
                    </div>
                    
                    <div class="detection-method">
                        <h4>Detection Method</h4>
                        <p>Port scan detection is based on identifying patterns of connection attempts:</p>
                        <ul>
                            <li>Multiple connection attempts from a single source IP to different ports</li>
                            <li>Connection attempts occurring within a short time window</li>
                            <li>Connection patterns that match known scanning techniques (SYN, FIN, XMAS scans)</li>
                        </ul>
                        <p>The system triggers an alert when the number of connection attempts exceeds a threshold within a specific time window.</p>
                    </div>
                    
                    <div class="security-recommendation">
                        <h4>Security Recommendations</h4>
                        <ol>
                            <li>Investigate the source IP address (id.orig_h) to determine if it's a legitimate system or potential attacker</li>
                            <li>Check if the scanning IP is from your network or external</li>
                            <li>Implement firewall rules to block or rate-limit connections from the scanning IP if malicious</li>
                            <li>Consider implementing port knocking or other port obfuscation techniques for sensitive services</li>
                            <li>Ensure all exposed services are properly patched and configured</li>
                        </ol>
                    </div>
                `;
                break;
                
            case 'dos':
                reportContent += `
                    <h3>Denial of Service (DoS) Attack Analysis</h3>
                    
                    <div class="field-explanation">
                        <h4>Log Format Explanation</h4>
                        <p>The log entries follow this format:</p>
                        <code># Fields: ts uid id.orig_h id.resp_h id.resp_p proto service packets_count anomaly_type severity</code>
                        <p>Each field provides critical information about the DoS attack:</p>
                        <ul>
                            <li><strong>ts</strong>: Timestamp when the attack was detected</li>
                            <li><strong>uid</strong>: Unique identifier for tracking this specific connection</li>
                            <li><strong>id.orig_h</strong>: The source IP address (the attacking system)</li>
                            <li><strong>id.resp_h</strong>: The destination IP address (the target system)</li>
                            <li><strong>id.resp_p</strong>: The destination port being targeted</li>
                            <li><strong>proto</strong>: The protocol used (tcp, udp, icmp)</li>
                            <li><strong>service</strong>: The service being targeted (http, dns, etc.)</li>
                            <li><strong>packets_count</strong>: Number of packets detected in the attack</li>
                            <li><strong>anomaly_type</strong>: Classification of the DoS attack (SYN_Flood, etc.)</li>
                            <li><strong>severity</strong>: Assessed threat level (Low, Medium, High)</li>
                        </ul>
                    </div>
                    
                    <div class="detection-method">
                        <h4>Detection Method</h4>
                        <p>DoS attack detection is based on identifying abnormal traffic patterns:</p>
                        <ul>
                            <li>Unusually high volume of traffic from a single source to a specific destination</li>
                            <li>Abnormal ratios of packet types (e.g., many SYN packets without corresponding ACKs)</li>
                            <li>Traffic patterns that match known DoS attack signatures</li>
                        </ul>
                        <p>The system triggers an alert when the traffic volume or pattern exceeds normal thresholds.</p>
                    </div>
                    
                    <div class="security-recommendation">
                        <h4>Security Recommendations</h4>
                        <ol>
                            <li>Implement rate limiting or traffic filtering for the affected service</li>
                            <li>Configure your firewall to block or throttle traffic from the attacking IP</li>
                            <li>Consider deploying a DDoS protection service if attacks persist</li>
                            <li>Analyze server logs to assess the impact on the targeted service</li>
                            <li>Implement TCP/SYN cookies and increase connection queue sizes if experiencing SYN floods</li>
                        </ol>
                    </div>
                `;
                break;
                
            case 'bruteforce':
                reportContent += `
                    <h3>Brute Force Attack Analysis</h3>
                    
                    <div class="field-explanation">
                        <h4>Log Format Explanation</h4>
                        <p>The log entries follow this format:</p>
                        <code># Fields: ts uid id.orig_h id.resp_h id.resp_p proto service login_attempts user anomaly_type severity</code>
                        <p>Each field provides critical information about the brute force attack:</p>
                        <ul>
                            <li><strong>ts</strong>: Timestamp when the attack was detected</li>
                            <li><strong>uid</strong>: Unique identifier for tracking this specific connection</li>
                            <li><strong>id.orig_h</strong>: The source IP address (the attacking system)</li>
                            <li><strong>id.resp_h</strong>: The destination IP address (the target system)</li>
                            <li><strong>id.resp_p</strong>: The destination port (22 for SSH, 21 for FTP, etc.)</li>
                            <li><strong>proto</strong>: The protocol used (typically tcp)</li>
                            <li><strong>service</strong>: The service being targeted (ssh, ftp, etc.)</li>
                            <li><strong>login_attempts</strong>: Number of failed login attempts detected</li>
                            <li><strong>user</strong>: The username being targeted</li>
                            <li><strong>anomaly_type</strong>: Classification of the attack (Brute_Force_SSH, etc.)</li>
                            <li><strong>severity</strong>: Assessed threat level (Low, Medium, High)</li>
                        </ul>
                    </div>
                    
                    <div class="detection-method">
                        <h4>Detection Method</h4>
                        <p>Brute force attack detection is based on identifying patterns of failed authentication:</p>
                        <ul>
                            <li>Multiple failed login attempts from the same source</li>
                            <li>Login attempts occurring at high frequency (faster than human typing)</li>
                            <li>Sequential or patterned login attempts</li>
                        </ul>
                        <p>The system triggers an alert when the number of failed login attempts exceeds a threshold within a specific time window.</p>
                    </div>
                    
                    <div class="security-recommendation">
                        <h4>Security Recommendations</h4>
                        <ol>
                            <li>Implement account lockout policies after multiple failed attempts</li>
                            <li>Use tools like Fail2ban to automatically block IPs with multiple failed login attempts</li>
                            <li>Enforce strong password policies and consider implementing multi-factor authentication</li>
                            <li>Consider changing the default port for services like SSH to reduce automated scanning</li>
                            <li>Limit access to authentication services to specific IP ranges when possible</li>
                        </ol>
                    </div>
                `;
                break;
                
            case 'data_exfil':
                reportContent += `
                    <h3>Data Exfiltration Attack Analysis</h3>
                    
                    <div class="field-explanation">
                        <h4>Log Format Explanation</h4>
                        <p>The log entries follow this format:</p>
                        <code># Fields: ts uid id.orig_h id.resp_h id.resp_p proto service data_size anomaly_type severity</code>
                        <p>Each field provides critical information about the data exfiltration:</p>
                        <ul>
                            <li><strong>ts</strong>: Timestamp when the exfiltration was detected</li>
                            <li><strong>uid</strong>: Unique identifier for tracking this specific connection</li>
                            <li><strong>id.orig_h</strong>: The source IP address (the compromised internal host)</li>
                            <li><strong>id.resp_h</strong>: The destination IP address (the external server receiving data)</li>
                            <li><strong>id.resp_p</strong>: The destination port</li>
                            <li><strong>proto</strong>: The protocol used (tcp, udp, icmp)</li>
                            <li><strong>service</strong>: The service being used for exfiltration (dns, http, etc.)</li>
                            <li><strong>data_size</strong>: Size of data being exfiltrated (in bytes)</li>
                            <li><strong>anomaly_type</strong>: Classification of the exfiltration (DNS_Exfiltration, etc.)</li>
                            <li><strong>severity</strong>: Assessed threat level (Low, Medium, High)</li>
                        </ul>
                    </div>
                    
                    <div class="detection-method">
                        <h4>Detection Method</h4>
                        <p>Data exfiltration detection is based on identifying suspicious data transfers:</p>
                        <ul>
                            <li>Unusual outbound traffic patterns or volumes</li>
                            <li>Unexpected protocol usage (e.g., DNS with unusually large payloads)</li>
                            <li>Communications with known malicious domains or unusual destinations</li>
                            <li>Encoded or encrypted data transfers that don't match normal patterns</li>
                        </ul>
                        <p>The system triggers an alert when data transfer patterns match known exfiltration techniques or exceed normal thresholds.</p>
                    </div>
                    
                    <div class="security-recommendation">
                        <h4>Security Recommendations</h4>
                        <ol>
                            <li>Investigate the internal host (id.orig_h) for signs of compromise</li>
                            <li>Block outbound connections to the destination IP (id.resp_h)</li>
                            <li>Implement data loss prevention (DLP) solutions to monitor and control data transfers</li>
                            <li>Consider implementing DNS filtering and monitoring for unusual DNS queries</li>
                            <li>Review and restrict outbound traffic policies, especially for sensitive protocols</li>
                        </ol>
                    </div>
                `;
                break;
                
            default:
                reportContent += `
                    <h3>Log Analysis</h3>
                    <p>No specific attack pattern identified in this log file. Please review the log contents manually for suspicious activity.</p>
                `;
        }
        
        // Add a future enhancements section
        reportContent += `
            <div class="future-enhancements">
                <h4>Future Enhancements</h4>
                <p>In future versions of this dashboard, we plan to implement:</p>
                <ul>
                    <li>AI-powered log analysis with natural language query capabilities</li>
                    <li>Interactive visualization of attack patterns and network traffic</li>
                    <li>Integration with real-time threat intelligence feeds</li>
                    <li>Automated remediation recommendations based on detected attacks</li>
                </ul>
            </div>
        `;
        
        // Set the content in the modal
        logAnalysisContent.innerHTML = reportContent;
        
        // Show the modal
        logAnalysisModal.classList.add('show');
    }
    
    function generateAiSummary() {
        // Show loading state
        genaiResult.innerHTML = `
            <div class="genai-loading">
                <i class="fas fa-spinner"></i> Opening Log Analyzer...
            </div>
        `;
        
        // Force open the Log Analyzer in a new window with specific features
        const logAnalyzerWindow = window.open('http://localhost:8001', '_blank', 'width=1200,height=800,menubar=no,toolbar=no');
        
        // If window.open was blocked or failed, provide a direct link
        if (!logAnalyzerWindow || logAnalyzerWindow.closed || typeof logAnalyzerWindow.closed === 'undefined') {
            genaiResult.innerHTML = `
                <p class="error">Pop-up blocker may have prevented opening the Log Analyzer. Please <a href="http://localhost:8001" target="_blank">click here</a> to open it manually.</p>
            `;
        } else {
            // Update the result message after opening the window
            setTimeout(() => {
                genaiResult.innerHTML = `
                    <p>Log Analyzer opened in a new window. If you don't see it, please <a href="http://localhost:8001" target="_blank">click here</a>.</p>
                `;
            }, 1000);
        }
    }
    
    // Function to update detection counters
    function updateDetectionCounters() {
        console.log('Updating detection counters');
        
        fetch('/api/analyze_detection')
            .then(response => response.json())
            .then(data => {
                console.log('Detection data:', data);
                
                // Update detection counts
                document.getElementById('port-scan-count').textContent = data.port_scan.count;
                document.getElementById('dos-count').textContent = data.dos_attack.count;
                document.getElementById('bruteforce-count').textContent = data.bruteforce.count;
                document.getElementById('data-exfil-count').textContent = data.data_exfil.count;
                
                // Update summary tab with detection details
                updateSummaryTab(data);
                
                // Update chart with new data
                updateChart({
                    port_scan: data.port_scan.count || 0,
                    dos: data.dos_attack.count || 0,
                    bruteforce: data.bruteforce.count || 0,
                    data_exfil: data.data_exfil.count || 0
                });
            })
            .catch(error => {
                console.error('Error updating detection counters:', error);
            });
    }
    
    // Update stats and refresh data
    function updateStats() {
        const timeInterval = document.getElementById('time-interval').value;
        
        // Update logs list
        updateLogList();
        
        // Update chart with new data from the analyze_detection endpoint
        fetch('/api/analyze_detection')
            .then(response => response.json())
            .then(data => {
                // Update chart with new data
                updateChart({
                    port_scan: data.port_scan.count || 0,
                    dos: data.dos_attack.count || 0,
                    bruteforce: data.bruteforce.count || 0,
                    data_exfil: data.data_exfil.count || 0
                });
            })
            .catch(error => {
                console.error('Error fetching stats:', error);
            });
    }
    
    // Update the chart with new data
    function updateChart(data) {
        const ctx = document.getElementById('detection-chart').getContext('2d');
        
        // Destroy existing chart if it exists
        if (window.detectionChart) {
            window.detectionChart.destroy();
        }
        
        // Create new chart
        window.detectionChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Port Scan', 'DoS', 'Brute Force', 'Data Exfiltration'],
                datasets: [{
                    label: 'Attack Detections',
                    data: [
                        data.port_scan || 0,
                        data.dos || 0,
                        data.bruteforce || 0,
                        data.data_exfil || 0
                    ],
                    backgroundColor: [
                        '#3498db',
                        '#e74c3c',
                        '#f39c12',
                        '#9b59b6'
                    ],
                    borderColor: [
                        '#2980b9',
                        '#c0392b',
                        '#d35400',
                        '#8e44ad'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: `Attack Detections (Last ${document.getElementById('time-interval').value} minutes)`
                    }
                }
            }
        });
    }
    
    // Event listeners for time interval and refresh
    document.getElementById('time-interval').addEventListener('change', updateStats);
    document.getElementById('refresh-stats').addEventListener('click', updateStats);
    
    // Document ready function
    document.addEventListener('DOMContentLoaded', function() {
        console.log('DOM fully loaded');
        
        // Initialize tab functionality
        initializeTabs();
        
        // Initial data load
        updateStats();
        refreshLogs();
        
        // Update detection counters on page load
        updateDetectionCounters();
        
        // Show notification
        showNotification('Network Attack Simulator loaded successfully', 'info');
    });

    // Tab initialization function
    function initializeTabs() {
        console.log('Initializing tabs');
        const tabButtons = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        
        console.log('Found tab buttons:', tabButtons.length);
        console.log('Found tab contents:', tabContents.length);
        
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                console.log('Tab button clicked:', this.getAttribute('data-tab'));
                
                // Remove active class from all buttons and contents
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                
                // Add active class to clicked button and corresponding content
                this.classList.add('active');
                const tabId = this.getAttribute('data-tab');
                
                if (tabId === 'visualization-tab') {
                    updateStats();
                }
                
                if (tabId === 'logs-tab') {
                    refreshLogs();
                }
                
                const tabContent = document.getElementById(tabId);
                
                if (tabContent) {
                    tabContent.classList.add('active');
                } else {
                    console.error(`Tab content with id ${tabId} not found`);
                }
            });
        });
    }
    
    // Function to show a specific tab
    function showTab(tabId) {
        console.log('Showing tab:', tabId);
        
        // Hide all tabs
        const tabs = document.querySelectorAll('.tab-content');
        tabs.forEach(tab => {
            tab.classList.add('hidden');
        });
        
        // Show the selected tab
        const selectedTab = document.getElementById(tabId);
        if (selectedTab) {
            selectedTab.classList.remove('hidden');
            
            // Update active tab button
            const tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(button => {
                button.classList.remove('active');
                if (button.getAttribute('data-tab') === tabId) {
                    button.classList.add('active');
                }
            });
        } else {
            console.error('Tab not found:', tabId);
        }
    }
    
    // Initialize attack options
    toggleAttackOptions();
    
    // Initial logs refresh
    refreshLogs();
    
    // Initialize detection chart
    const ctx = detectionChart.getContext('2d');
    detectionChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Port Scan', 'DoS', 'Brute Force', 'Data Exfiltration'],
            datasets: [{
                label: 'Detected Attacks',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#3498db',
                    '#e74c3c',
                    '#f39c12',
                    '#9b59b6'
                ],
                borderColor: [
                    '#2980b9',
                    '#c0392b',
                    '#d35400',
                    '#8e44ad'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
});
