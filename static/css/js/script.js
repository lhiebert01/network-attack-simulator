// static/js/script.js
document.addEventListener('DOMContentLoaded', function() {
    // UI Elements
    const zeekStatus = document.getElementById('zeek-status');
    const startZeekBtn = document.getElementById('start-zeek');
    const stopZeekBtn = document.getElementById('stop-zeek');
    const runAttackBtn = document.getElementById('run-attack');
    const analyzeDetectionBtn = document.getElementById('analyze-detection');
    const refreshLogsBtn = document.getElementById('refresh-logs');
    const attackTypeSelect = document.getElementById('attack-type');
    const logFileSelect = document.getElementById('log-file');
    const logDisplay = document.getElementById('log-display');
    
    // Attack option containers
    const portScanOptions = document.getElementById('port-scan-options');
    const dosOptions = document.getElementById('dos-options');
    const bruteforceOptions = document.getElementById('bruteforce-options');
    const dataExfilOptions = document.getElementById('data-exfil-options');
    
    // Tab elements
    const tabHeaders = document.querySelectorAll('.tab-header');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    // Traffic visualization chart
    let trafficChart = null;
    
    // State variables
    let isZeekRunning = false;
    let currentLogs = {};
    
    // Initialize UI
    initUI();
    
    // Event Listeners
    startZeekBtn.addEventListener('click', startZeek);
    stopZeekBtn.addEventListener('click', stopZeek);
    runAttackBtn.addEventListener('click', runAttack);
    analyzeDetectionBtn.addEventListener('click', analyzeDetection);
    refreshLogsBtn.addEventListener('click', fetchLogs);
    attackTypeSelect.addEventListener('change', updateAttackOptions);
    logFileSelect.addEventListener('change', displaySelectedLog);
    
    // Tab navigation
    tabHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const tabId = header.getAttribute('data-tab');
            activateTab(tabId);
        });
    });
    
    // Initialize UI elements
    function initUI() {
        updateAttackOptions();
        
        // Initialize tabs
        activateTab('summary');
        
        // Initialize Chart.js
        const ctx = document.getElementById('traffic-chart').getContext('2d');
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Network Traffic (packets/sec)',
                    data: [],
                    backgroundColor: 'rgba(52, 152, 219, 0.2)',
                    borderColor: 'rgba(52, 152, 219, 1)',
                    borderWidth: 2,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Network Traffic Over Time',
                        font: {
                            size: 16
                        }
                    }
                }
            }
        });
    }
    
    // Tab activation
    function activateTab(tabId) {
        tabHeaders.forEach(header => {
            if (header.getAttribute('data-tab') === tabId) {
                header.classList.add('active');
            } else {
                header.classList.remove('active');
            }
        });
        
        tabPanes.forEach(pane => {
            if (pane.id === tabId + '-tab') {
                pane.classList.add('active');
            } else {
                pane.classList.remove('active');
            }
        });
    }
    
    // Update attack options based on selected attack type
    function updateAttackOptions() {
        const attackType = attackTypeSelect.value;
        
        // Hide all option containers
        portScanOptions.classList.add('hidden');
        dosOptions.classList.add('hidden');
        bruteforceOptions.classList.add('hidden');
        dataExfilOptions.classList.add('hidden');
        
        // Show the relevant option container
        switch (attackType) {
            case 'port_scan':
                portScanOptions.classList.remove('hidden');
                break;
            case 'dos':
                dosOptions.classList.remove('hidden');
                break;
            case 'bruteforce':
                bruteforceOptions.classList.remove('hidden');
                break;
            case 'data_exfil':
                dataExfilOptions.classList.remove('hidden');
                break;
        }
    }
    
    // Start Zeek
    async function startZeek() {
        if (isZeekRunning) {
            showNotification('Zeek is already running', 'warning');
            return;
        }
        
        const interfaceName = document.getElementById('interface').value;
        
        try {
            const response = await fetch('/api/start_zeek', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ interface: interfaceName })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                isZeekRunning = true;
                zeekStatus.textContent = 'Status: Running';
                zeekStatus.classList.add('running');
                zeekStatus.classList.remove('stopped');
                showNotification('Zeek started successfully', 'success');
                
                // Start periodic log refresh
                startLogRefresh();
            } else {
                showNotification('Failed to start Zeek: ' + data.message, 'error');
            }
        } catch (error) {
            showNotification('Error: ' + error.message, 'error');
        }
    }
    
    // Stop Zeek
    async function stopZeek() {
        if (!isZeekRunning) {
            showNotification('Zeek is not running', 'warning');
            return;
        }
        
        try {
            const response = await fetch('/api/stop_zeek', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({})
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                isZeekRunning = false;
                zeekStatus.textContent = 'Status: Stopped';
                zeekStatus.classList.remove('running');
                zeekStatus.classList.add('stopped');
                showNotification('Zeek stopped successfully', 'success');
                
                // Stop periodic log refresh
                stopLogRefresh();
            } else {
                showNotification('Failed to stop Zeek: ' + data.message, 'error');
            }
        } catch (error) {
            showNotification('Error: ' + error.message, 'error');
        }
    }
    
    // Run attack simulation
    async function runAttack() {
        if (!isZeekRunning) {
            showNotification('Please start Zeek first before running an attack simulation', 'warning');
            return;
        }
        
        const attackType = attackTypeSelect.value;
        const targetIP = document.getElementById('target-ip').value;
        
        let params = {
            type: attackType,
            target_ip: targetIP
        };
        
        // Add attack-specific parameters
        switch (attackType) {
            case 'port_scan':
                params.scan_type = document.getElementById('scan-type').value;
                break;
            case 'dos':
                params.count = document.getElementById('packet-count').value;
                break;
            case 'bruteforce':
                params.service = document.getElementById('service-type').value;
                break;
        }
        
        try {
            showNotification('Running attack simulation...', 'info');
            
            const response = await fetch('/api/simulate_attack', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(params)
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                showNotification('Attack simulation completed: ' + data.message, 'success');
                
                // Refresh logs after attack
                setTimeout(fetchLogs, 1000);
            } else {
                showNotification('Failed to run attack simulation: ' + data.message, 'error');
            }
        } catch (error) {
            showNotification('Error: ' + error.message, 'error');
        }
    }
    
    // Fetch and display log files
    async function fetchLogs() {
        try {
            const response = await fetch('/api/get_logs');
            currentLogs = await response.json();
            
            // Update log file selector
            const logFiles = Object.keys(currentLogs);
            
            if (logFiles.length === 0) {
                logFileSelect.innerHTML = '<option value="">No logs available</option>';
                logDisplay.textContent = 'No log data to display';
                return;
            }
            
            let options = '';
            logFiles.forEach(logFile => {
                options += `<option value="${logFile}">${logFile}</option>`;
            });
            
            logFileSelect.innerHTML = options;
            
            // Display the first log file by default
            logFileSelect.value = logFiles[0];
            displaySelectedLog();
            
            // Update traffic visualization
            updateTrafficVisualization();
            
            showNotification('Logs refreshed', 'success');
        } catch (error) {
            showNotification('Error fetching logs: ' + error.message, 'error');
        }
    }
    
    // Display selected log file
    function displaySelectedLog() {
        const selectedLog = logFileSelect.value;
        
        if (!selectedLog || !currentLogs[selectedLog]) {
            logDisplay.textContent = 'No log data to display';
            return;
        }
        
        const logEntries = currentLogs[selectedLog];
        
        if (logEntries.length === 0) {
            logDisplay.textContent = 'Log file is empty';
            return;
        }
        
        let formattedLog = '';
        
        logEntries.forEach((entry, index) => {
            if (typeof entry === 'object') {
                formattedLog += JSON.stringify(entry, null, 2) + '\n\n';
            } else {
                formattedLog += entry + '\n';
            }
        });
        
        logDisplay.textContent = formattedLog;
    }
    
    // Analyze detection results
    async function analyzeDetection() {
        try {
            const response = await fetch('/api/analyze_detection');
            const data = await response.json();
            
            // Show detection results section
            document.getElementById('detection-results').classList.remove('hidden');
            
            // Update each attack type result
            updateDetectionResult('port-scan', data.port_scan);
            updateDetectionResult('dos', data.dos_attack);
            updateDetectionResult('bruteforce', data.bruteforce);
            updateDetectionResult('data-exfil', data.data_exfil);
            
            // Switch to summary tab
            activateTab('summary');
            
            showNotification('Detection analysis completed', 'success');
        } catch (error) {
            showNotification('Error analyzing detections: ' + error.message, 'error');
        }
    }
    
    // Update the detection result for a specific attack type
    function updateDetectionResult(attackId, resultData) {
        const resultElement = document.getElementById(`${attackId}-result`);
        const statusElement = resultElement.querySelector('.detection-status');
        const detailsElement = resultElement.querySelector('.detection-details');
        
        if (resultData.detected) {
            statusElement.textContent = `Detected (${resultData.count} instances)`;
            statusElement.classList.add('detected');
            
            let detailsHtml = '';
            
            resultData.details.forEach(detail => {
                detailsHtml += `<div class="detection-detail-item">`;
                
                // Format the detail object properties
                Object.keys(detail).forEach(key => {
                    detailsHtml += `<div><strong>${key}:</strong> ${detail[key]}</div>`;
                });
                
                detailsHtml += `</div>`;
            });
            
            detailsElement.innerHTML = detailsHtml;
        } else {
            statusElement.textContent = 'Not Detected';
            statusElement.classList.remove('detected');
            detailsElement.innerHTML = '';
        }
    }
    
    // Update traffic visualization chart
    function updateTrafficVisualization() {
        if (!currentLogs.conn) return;
        
        // Process conn.log to extract timestamps and traffic volume
        const timestamps = [];
        const packetCounts = [];
        
        // Group connections by time and count packets
        const timeData = {};
        
        currentLogs.conn.forEach(entry => {
            if (typeof entry === 'object' && entry.ts) {
                // Round timestamp to nearest second
                const timestamp = Math.floor(entry.ts);
                
                if (!timeData[timestamp]) {
                    timeData[timestamp] = 0;
                }
                
                // Add orig_pkts and resp_pkts if available
                if (entry.orig_pkts && entry.resp_pkts) {
                    timeData[timestamp] += entry.orig_pkts + entry.resp_pkts;
                } else {
                    // Default increment if packet counts not available
                    timeData[timestamp] += 1;
                }
            }
        });
        
        // Convert to arrays for Chart.js
        Object.keys(timeData).sort().forEach(time => {
            const date = new Date(time * 1000);
            timestamps.push(date.toLocaleTimeString());
            packetCounts.push(timeData[time]);
        });
        
        // Update chart
        trafficChart.data.labels = timestamps;
        trafficChart.data.datasets[0].data = packetCounts;
        trafficChart.update();
    }
    
    // Periodic log refresh variables
    let logRefreshInterval = null;
    
    // Start periodic log refresh
    function startLogRefresh() {
        if (logRefreshInterval) {
            clearInterval(logRefreshInterval);
        }
        
        // Refresh logs every 5 seconds
        logRefreshInterval = setInterval(fetchLogs, 5000);
    }
    
    // Stop periodic log refresh
    function stopLogRefresh() {
        if (logRefreshInterval) {
            clearInterval(logRefreshInterval);
            logRefreshInterval = null;
        }
    }
    
    // Show notification
    function showNotification(message, type) {
        // Simple notification implementation
        console.log(`[${type}] ${message}`);
        
        // You could implement a more sophisticated notification system here
    }
});