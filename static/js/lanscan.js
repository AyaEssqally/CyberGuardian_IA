document.addEventListener('DOMContentLoaded', function() {
    // Enhanced Configuration
    const CONFIG = {
        scanTypes: {
            quick: { name: "Quick Scan", args: "-T4 -F", description: "Fast scan of common ports" },
            standard: { name: "Standard Scan", args: "-T4 -sV", description: "Service version detection" },
            aggressive: { name: "Aggressive Scan", args: "-T4 -A", description: "OS and service detection" },
            full: { name: "Full Scan", args: "-T4 -p- -A", description: "All ports with service detection" },
            os: { name: "OS Detection", args: "-T4 -O", description: "Operating system fingerprinting" },
            vuln: { name: "Vulnerability Scan", args: "-T4 --script=vuln", description: "Check for known vulnerabilities" },
            deep: { name: "Deep Scan", args: "-T4 -p- -A --script=vuln", description: "Comprehensive security audit" },
            wifi: { name: "WiFi Scan", args: "--script=wifi-discover", description: "Discover WiFi devices" },
            behavioral: { name: "Behavioral Analysis", args: "-T4 --script=behavioral-analysis", description: "Analyze network behavior" }
        },
        riskLevels: {
            critical: { threshold: 70, color: "#f72585", label: "Critical", icon: "fa-skull-crossbones" },
            high: { threshold: 40, color: "#fb8500", label: "High", icon: "fa-exclamation-triangle" },
            medium: { threshold: 20, color: "#ffb703", label: "Medium", icon: "fa-exclamation-circle" },
            low: { threshold: 0, color: "#8ac926", label: "Low", icon: "fa-check-circle" }
        },
        notificationTimeout: 5000,
        maxScanHistory: 10,
        defaultIpRange: "192.168.1.0/24",
        chartColors: [
            '#4cc9f0', '#4895ef', '#4361ee', '#3f37c9', 
            '#3a0ca3', '#480ca8', '#560bad', '#7209b7',
            '#b5179e', '#f72585'
        ]
    };

    // Application state
    const state = {
        currentScan: null,
        scanHistory: JSON.parse(localStorage.getItem('scanHistory')) || [],
        networkDevices: [],
        securityAlerts: [],
        systemStats: {},
        settings: {
            darkMode: localStorage.getItem('darkMode') === 'true',
            autoBlock: true,
            notifications: true,
            scanOptions: JSON.parse(localStorage.getItem('scanOptions')) || {
                quick: true,
                deep: false,
                vuln: false,
                wifi: false,
                behavioral: false
            }
        },
        charts: {
            services: null,
            threats: null,
            network: null
        }
    };

    // DOM references
    const DOM = {
        notificationContainer: document.getElementById('notification-container'),
        ipRangeInput: document.getElementById('ip-range'),
        scanTypeSelect: document.getElementById('scan-type'),
        startScanBtn: document.getElementById('start-scan'),
        cancelScanBtn: document.getElementById('cancel-scan'),
        scanProgress: document.getElementById('scan-progress'),
        progressText: document.getElementById('progress-text'),
        loadingOverlay: document.getElementById('loading-overlay'),
        scanResults: document.querySelector('.scan-results'),
        hostsTable: document.getElementById('hosts-table').querySelector('tbody'),
        threatsTable: document.getElementById('threats-table').querySelector('tbody'),
        servicesChart: document.getElementById('services-chart'),
        networkGraph: document.getElementById('network-graph'),
        darkModeToggle: document.getElementById('toggle-dark-mode'),
        securityCenterBtn: document.getElementById('security-center-btn'),
        wifiControlBtn: document.getElementById('wifi-control-btn'),
        modals: {
            hostDetails: document.getElementById('host-details-modal'),
            securityCenter: document.getElementById('security-center-modal'),
            wifiControl: document.getElementById('wifi-control-modal')
        },
        statsElements: {
            totalHosts: document.getElementById('total-hosts'),
            upHosts: document.getElementById('up-hosts'),
            openPorts: document.getElementById('open-ports'),
            vulnsCount: document.getElementById('vulns-count')
        }
    };

    // Initialize application
    function init() {
        initCharts();
        setupEventListeners();
        loadInitialData();
        applyUIState();
        updateSystemStats();
    }

    function initCharts() {
        // Services chart
        state.charts.services = new Chart(DOM.servicesChart, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: CONFIG.chartColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'right' },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    function setupEventListeners() {
        // Scan controls
        DOM.startScanBtn.addEventListener('click', startScan);
        DOM.cancelScanBtn.addEventListener('click', cancelScan);

        // UI controls
        DOM.darkModeToggle.addEventListener('click', toggleDarkMode);
        DOM.securityCenterBtn.addEventListener('click', () => showModal('securityCenter'));
        DOM.wifiControlBtn.addEventListener('click', () => showModal('wifiControl'));

        // Close modals
        document.querySelectorAll('.close-btn').forEach(btn => {
            btn.addEventListener('click', closeAllModals);
        });

        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                closeAllModals();
            }
        });

        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(tab => {
            tab.addEventListener('click', switchTab);
        });

        // Modal tab switching
        document.querySelectorAll('.modal-tab-btn').forEach(tab => {
            tab.addEventListener('click', switchModalTab);
        });

        // Export buttons
        document.getElementById('export-pdf').addEventListener('click', exportReport.bind(null, 'pdf'));
        document.getElementById('export-html').addEventListener('click', exportReport.bind(null, 'html'));
        document.getElementById('export-json').addEventListener('click', exportReport.bind(null, 'json'));
        document.getElementById('export-csv').addEventListener('click', exportReport.bind(null, 'csv'));

        // Scan options checkboxes
        document.querySelectorAll('.checkbox-grid input[type="checkbox"]').forEach(checkbox => {
            checkbox.addEventListener('change', updateScanOptions);
        });

        // Set default IP range
        DOM.ipRangeInput.value = CONFIG.defaultIpRange;
    }

    function loadInitialData() {
        // Load scan history
        fetch('/get_scan_history')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    state.scanHistory = data.history;
                    updateScanHistoryUI();
                }
            })
            .catch(error => {
                console.error('Failed to load scan history:', error);
            });

        // Load security alerts
        fetch('/get_security_alerts')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    state.securityAlerts = data.alerts;
                    updateThreatsTable(state.securityAlerts);
                }
            })
            .catch(error => {
                console.error('Failed to load security alerts:', error);
            });

        // Load blocked devices
        fetch('/get_blocked_devices')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateBlockedDevicesUI(data.blocked_devices);
                }
            })
            .catch(error => {
                console.error('Failed to load blocked devices:', error);
            });
    }

    function applyUIState() {
        // Apply dark/light mode
        document.body.classList.toggle('dark-mode', state.settings.darkMode);
        DOM.darkModeToggle.querySelector('i').className = 
            state.settings.darkMode ? 'fas fa-sun' : 'fas fa-moon';

        // Apply scan options
        for (const [option, enabled] of Object.entries(state.settings.scanOptions)) {
            const checkbox = document.getElementById(`opt-${option}`);
            if (checkbox) {
                checkbox.checked = enabled;
            }
        }
    }

    function updateSystemStats() {
        fetch('/get_system_stats')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    state.systemStats = data.stats;
                    // Update UI with system stats if needed
                }
            })
            .catch(error => {
                console.error('Failed to get system stats:', error);
            });

        // Refresh every 30 seconds
        setTimeout(updateSystemStats, 30000);
    }

    // Scan functions
    async function startScan() {
        const ipRange = DOM.ipRangeInput.value.trim();
        const scanType = DOM.scanTypeSelect.value;

        if (!validateIpRange(ipRange)) {
            showNotification('Invalid IP range format', 'error');
            return;
        }

        try {
            showLoading(true);
            resetScanUI();

            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip_range: ipRange,
                    scan_type: scanType,
                    options: getScanOptions()
                })
            });

            const data = await response.json();

            if (data.success) {
                state.currentScan = {
                    id: data.scan_id,
                    ipRange,
                    type: scanType,
                    startTime: new Date(),
                    progress: 0
                };
                
                monitorScanProgress(data.scan_id);
            } else {
                throw new Error(data.error || 'Failed to start scan');
            }
        } catch (error) {
            console.error('Scan error:', error);
            showNotification(error.message, 'error');
            showLoading(false);
        }
    }

    async function monitorScanProgress(scanId) {
        const progressInterval = setInterval(async () => {
            try {
                const response = await fetch(`/scan_status/${scanId}`);
                const data = await response.json();
                
                if (!data.success) {
                    throw new Error(data.error || 'Failed to get scan status');
                }
                
                updateScanProgress(data.progress);
                
                if (data.status === 'completed') {
                    clearInterval(progressInterval);
                    processScanResults(data.results);
                } else if (data.status === 'failed') {
                    clearInterval(progressInterval);
                    throw new Error(data.error || 'Scan failed');
                }
            } catch (error) {
                clearInterval(progressInterval);
                console.error('Progress monitoring error:', error);
                showNotification(error.message, 'error');
                showLoading(false);
            }
        },50000);
    }

    function cancelScan() {
        if (!state.currentScan?.id) return;
        
        fetch(`/cancel_scan/${state.currentScan.id}`, { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Scan cancelled', 'warning');
                } else {
                    showNotification(data.error || 'Failed to cancel scan', 'error');
                }
            })
            .catch(error => {
                console.error('Cancel scan error:', error);
                showNotification('Failed to cancel scan', 'error');
            })
            .finally(() => {
                state.currentScan = null;
                showLoading(false);
            });
    }

    function processScanResults(results) {
        state.currentScan.results = results;
        state.currentScan.endTime = new Date();
        
        // Update history
        state.scanHistory.unshift({
            id: state.currentScan.id,
            timestamp: state.currentScan.startTime.toISOString(),
            ipRange: state.currentScan.ipRange,
            type: state.currentScan.type,
            results: results.summary
        });
        
        // Keep only recent scans
        if (state.scanHistory.length > CONFIG.maxScanHistory) {
            state.scanHistory.pop();
        }
        
        localStorage.setItem('scanHistory', JSON.stringify(state.scanHistory));
        
        // Update UI
        updateScanUI(results);
        showNotification('Scan completed successfully', 'success');
        showLoading(false);
    }

    // UI update functions
    function updateScanUI(results) {
        DOM.scanResults.classList.remove('hidden');
        updateSummaryStats(results.summary);
        updateHostsTable(results.hosts);
        updateThreatsTable(results.threats || state.securityAlerts);
        updateServicesChart(results.summary.services);
        renderNetworkMap(results.hosts);
    }

    function updateSummaryStats(summary) {
        DOM.statsElements.totalHosts.textContent = summary.total_hosts || 0;
        DOM.statsElements.upHosts.textContent = summary.up_hosts || 0;
        DOM.statsElements.openPorts.textContent = summary.open_ports || 0;
        DOM.statsElements.vulnsCount.textContent = summary.vulnerabilities?.length || 0;
    }

    function updateHostsTable(hosts) {
        DOM.hostsTable.innerHTML = '';
        
        if (!hosts || hosts.length === 0) {
            DOM.hostsTable.innerHTML = '<tr><td colspan="6" class="text-center">No hosts found</td></tr>';
            return;
        }
        
        hosts.forEach(host => {
            const riskLevel = getRiskLevel(host.risk_score);
            const riskConfig = CONFIG.riskLevels[riskLevel];
            const row = document.createElement('tr');
            
            row.innerHTML = `
                <td>${host.ip}</td>
                <td>${host.hostnames[0]?.name || 'N/A'}</td>
                <td>${host.os?.name || 'Unknown'}</td>
                <td>${host.ports.filter(p => p.state === 'open').length}</td>
                <td>
                    <div class="risk-meter">
                        <div class="risk-level risk-${riskLevel}">
                            <i class="fas ${riskConfig.icon}"></i> ${riskConfig.label}
                        </div>
                        <div class="risk-bar">
                            <div class="risk-fill" style="width: ${host.risk_score}%; background: ${riskConfig.color}"></div>
                        </div>
                    </div>
                </td>
                <td>
                    <button class="btn-icon" onclick="showHostDetails('${host.ip}')">
                        <i class="fas fa-search"></i>
                    </button>
                    <button class="btn-icon" onclick="blockDevice('${host.ip}', 'Manual block')">
                        <i class="fas fa-ban"></i>
                    </button>
                </td>
            `;
            
            DOM.hostsTable.appendChild(row);
        });
    }

    function updateThreatsTable(threats) {
        DOM.threatsTable.innerHTML = '';
        
        if (!threats || threats.length === 0) {
            DOM.threatsTable.innerHTML = '<tr><td colspan="5" class="text-center">No threats detected</td></tr>';
            return;
        }
        
        threats.forEach(threat => {
            const row = document.createElement('tr');
            const date = new Date(threat.timestamp || Date.now());
            
            row.innerHTML = `
                <td><span class="threat-type ${threat.type}">${threat.type}</span></td>
                <td>${threat.ip || threat.identifier || 'N/A'}</td>
                <td>${threat.port || 'N/A'}</td>
                <td>${date.toLocaleString()}</td>
                <td>
                    <button class="btn-icon" onclick="blockDevice('${threat.ip || threat.identifier}', '${threat.description || threat.type}')">
                        <i class="fas fa-ban"></i>
                    </button>
                    <button class="btn-icon" onclick="showThreatDetails('${threat.ip || threat.identifier}')">
                        <i class="fas fa-info-circle"></i>
                    </button>
                </td>
            `;
            
            DOM.threatsTable.appendChild(row);
        });
    }

    function updateServicesChart(services) {
        if (!services) return;
        
        const labels = Object.keys(services);
        const data = Object.values(services);
        
        state.charts.services.data.labels = labels;
        state.charts.services.data.datasets[0].data = data;
        state.charts.services.update();
    }

    function renderNetworkMap(hosts) {
        DOM.networkGraph.innerHTML = '';
        
        if (!hosts || hosts.length === 0) {
            DOM.networkGraph.innerHTML = '<div class="empty-state">No network devices found</div>';
            return;
        }
        
        const width = DOM.networkGraph.clientWidth;
        const height = 500;
        const radius = 30;
        
        // Create SVG
        const svg = d3.select(DOM.networkGraph)
            .append('svg')
            .attr('width', width)
            .attr('height', height);
        
        // Simulation
        const simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2));
        
        // Nodes and links
        const nodes = [
            { id: 'gateway', name: 'Gateway', type: 'router', risk: 'low' },
            ...hosts.filter(h => h.status === 'up').map(host => ({
                id: host.ip,
                name: host.hostnames[0]?.name || host.ip,
                type: 'host',
                risk: getRiskLevel(host.risk_score),
                os: host.os?.name || 'Unknown',
                ports: host.ports.filter(p => p.state === 'open').length,
                threats: host.threats?.length || 0
            }))
        ];
        
        const links = hosts
            .filter(h => h.status === 'up')
            .map(host => ({ source: 'gateway', target: host.ip }));
        
        // Draw links
        const link = svg.append('g')
            .selectAll('line')
            .data(links)
            .enter().append('line')
            .attr('stroke', '#999')
            .attr('stroke-width', 2);
        
        // Draw nodes
        const node = svg.append('g')
            .selectAll('g')
            .data(nodes)
            .enter().append('g')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Node circles
        node.append('circle')
            .attr('r', radius)
            .attr('fill', d => {
                if (d.type === 'router') return '#4cc9f0';
                return CONFIG.riskLevels[d.risk].color;
            })
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .on('click', d => {
                if (d.type === 'host') showHostDetails(d.id);
            });
        
        // Node icons
        node.append('text')
            .attr('dy', 4)
            .attr('text-anchor', 'middle')
            .attr('fill', '#fff')
            .style('pointer-events', 'none')
            .text(d => {
                if (d.type === 'router') return '⌂';
                if (d.ports > 10) return '🖥️';
                return '💻';
            });
        
        // Node labels
        node.append('text')
            .attr('dy', radius + 15)
            .attr('text-anchor', 'middle')
            .text(d => d.name.length > 12 ? d.name.substring(0, 9) + '...' : d.name)
            .attr('fill', getComputedStyle(document.body).getPropertyValue('--text-color'));
        
        // Update simulation
        simulation.nodes(nodes).on('tick', ticked);
        simulation.force('link').links(links);
        
        function ticked() {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node.attr('transform', d => `translate(${d.x},${d.y})`);
        }
        
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    }

    function updateScanHistoryUI() {
        const historyContainer = document.getElementById('scan-history');
        
        if (state.scanHistory.length === 0) {
            historyContainer.innerHTML = `
                <div class="history-empty">
                    <i class="fas fa-clock"></i>
                    <p>No recent scans</p>
                </div>
            `;
            return;
        }
        
        historyContainer.innerHTML = '';
        
        state.scanHistory.forEach(scan => {
            const item = document.createElement('div');
            item.className = 'history-item';
            item.innerHTML = `
                <div class="history-item-header">
                    <span class="history-item-type">${CONFIG.scanTypes[scan.type]?.name || scan.type}</span>
                    <span class="history-item-time">${new Date(scan.timestamp).toLocaleString()}</span>
                </div>
                <div class="history-item-details">
                    <span>${scan.ipRange}</span>
                    <span>${scan.results?.up_hosts || 0} hosts</span>
                    <span class="history-item-status ${scan.status}">${scan.status}</span>
                </div>
            `;
            item.addEventListener('click', () => loadScanResults(scan.id));
            historyContainer.appendChild(item);
        });
    }

    function updateBlockedDevicesUI(devices) {
        const table = document.getElementById('blocked-devices-table')?.querySelector('tbody');
        if (!table) return;
        
        table.innerHTML = '';
        
        if (!devices || devices.length === 0) {
            table.innerHTML = '<tr><td colspan="5" class="text-center">No blocked devices</td></tr>';
            return;
        }
        
        devices.forEach(device => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${device.mac || 'N/A'}</td>
                <td>${device.ip || 'N/A'}</td>
                <td>${device.reason || 'Manual block'}</td>
                <td>${new Date(device.timestamp).toLocaleString()}</td>
                <td>
                    <button class="btn-icon" onclick="unblockDevice('${device.ip}', '${device.mac}')">
                        <i class="fas fa-unlock"></i>
                    </button>
                </td>
            `;
            table.appendChild(row);
        });
    }

    // Utility functions
    function showLoading(show) {
        DOM.loadingOverlay.style.display = show ? 'flex' : 'none';
        DOM.startScanBtn.disabled = show;
    }

    function resetScanUI() {
        DOM.scanProgress.style.width = '0%';
        DOM.progressText.textContent = '0%';
        DOM.scanResults.classList.add('hidden');
    }

    function updateScanProgress(progress) {
        DOM.scanProgress.style.width = `${progress}%`;
        DOM.progressText.textContent = `${progress}%`;
        if (state.currentScan) {
            state.currentScan.progress = progress;
        }
    }

    function showNotification(message, type = 'info') {
        if (!state.settings.notifications) return;
        
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas ${getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        DOM.notificationContainer.appendChild(notification);
        
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }, CONFIG.notificationTimeout);
    }

    function getNotificationIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    function getRiskLevel(score) {
        for (const [level, config] of Object.entries(CONFIG.riskLevels)) {
            if (score >= config.threshold) return level;
        }
        return 'low';
    }

    function validateIpRange(ipRange) {
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
        return ipRegex.test(ipRange);
    }

    function getScanOptions() {
        return {
            quick: document.getElementById('opt-quick').checked,
            deep: document.getElementById('opt-deep').checked,
            vuln: document.getElementById('opt-vuln').checked,
            wifi: document.getElementById('opt-wifi').checked,
            behavioral: document.getElementById('opt-behavioral').checked
        };
    }

    function updateScanOptions() {
        state.settings.scanOptions = {
            quick: document.getElementById('opt-quick').checked,
            deep: document.getElementById('opt-deep').checked,
            vuln: document.getElementById('opt-vuln').checked,
            wifi: document.getElementById('opt-wifi').checked,
            behavioral: document.getElementById('opt-behavioral').checked
        };
        localStorage.setItem('scanOptions', JSON.stringify(state.settings.scanOptions));
    }

    function toggleDarkMode() {
        state.settings.darkMode = !state.settings.darkMode;
        localStorage.setItem('darkMode', state.settings.darkMode);
        applyUIState();
    }

    function showModal(modalId) {
        if (!DOM.modals[modalId]) return;
        DOM.modals[modalId].style.display = 'block';
    }

    function closeAllModals() {
        Object.values(DOM.modals).forEach(modal => {
            if (modal) modal.style.display = 'none';
        });
    }

    function switchTab(event) {
        const tabId = event.target.dataset.tab;
        
        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn === event.target);
        });
        
        // Update active tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === tabId);
        });
    }

    function switchModalTab(event) {
        const tabId = event.target.dataset.tab;
        const modal = event.target.closest('.modal-content');
        
        // Update active tab button
        modal.querySelectorAll('.modal-tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn === event.target);
        });
        
        // Update active tab content
        modal.querySelectorAll('.modal-tab-content').forEach(content => {
            content.classList.toggle('active', content.id === tabId);
        });
    }

    function exportReport(format) {
        if (!state.currentScan?.results) {
            showNotification('No scan results to export', 'error');
            return;
        }
        
        fetch('/generate_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                results: state.currentScan.results,
                report_type: format
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.open(data.report_url, '_blank');
                showNotification(`Report exported as ${format.toUpperCase()}`, 'success');
            } else {
                throw new Error(data.error || 'Failed to generate report');
            }
        })
        .catch(error => {
            console.error('Export error:', error);
            showNotification(error.message, 'error');
        });
    }

    function loadScanResults(scanId) {
        fetch(`/scan_status/${scanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success && data.results) {
                    updateScanUI(data.results);
                    showNotification('Scan results loaded', 'success');
                } else {
                    throw new Error(data.error || 'Failed to load scan results');
                }
            })
            .catch(error => {
                console.error('Load scan error:', error);
                showNotification(error.message, 'error');
            });
    }

    // Global functions
    window.showHostDetails = function(ip) {
        if (!state.currentScan?.results?.hosts) return;
        
        const host = state.currentScan.results.hosts.find(h => h.ip === ip);
        if (!host) return;
        
        // Update basic info
        document.getElementById('host-details-ip').textContent = host.ip;
        document.getElementById('host-details-status').textContent = 
            host.status === 'up' ? 'Active' : 'Inactive';
        document.getElementById('host-details-risk').textContent = 
            `${host.risk_score || 0}/100`;
        
        // Update ports table
        const portsTable = document.getElementById('host-ports-table').querySelector('tbody');
        portsTable.innerHTML = '';
        
        host.ports.filter(p => p.state === 'open').forEach(port => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${port.port}</td>
                <td>${port.protocol}</td>
                <td>${port.service?.name || 'unknown'}</td>
                <td>${port.service?.product || ''} ${port.service?.version || ''}</td>
                <td><span class="risk-${port.risk || 'low'}">${port.risk || 'low'}</span></td>
            `;
            portsTable.appendChild(row);
        });
        
        showModal('hostDetails');
    };

    window.blockDevice = async function(ip, reason = 'Manual block') {
        try {
            const response = await fetch('/block_device', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, reason })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showNotification(`Device ${ip} blocked successfully`, 'success');
                // Refresh blocked devices list
                fetch('/get_blocked_devices')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            updateBlockedDevicesUI(data.blocked_devices);
                        }
                    });
            } else {
                throw new Error(data.error || 'Failed to block device');
            }
        } catch (error) {
            console.error('Block device error:', error);
            showNotification(error.message, 'error');
        }
    };

    window.unblockDevice = async function(ip, mac) {
        try {
            const response = await fetch('/unblock_device', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, mac })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showNotification(`Device ${ip || mac} unblocked`, 'success');
                // Refresh blocked devices list
                fetch('/get_blocked_devices')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            updateBlockedDevicesUI(data.blocked_devices);
                        }
                    });
            } else {
                throw new Error(data.error || 'Failed to unblock device');
            }
        } catch (error) {
            console.error('Unblock device error:', error);
            showNotification(error.message, 'error');
        }
    };

    window.showThreatDetails = function(ip) {
        // Find threat in current scan results or security alerts
        let threat;
        if (state.currentScan?.results?.threats) {
            threat = state.currentScan.results.threats.find(t => t.ip === ip);
        }
        if (!threat && state.securityAlerts) {
            threat = state.securityAlerts.find(t => t.ip === ip);
        }
        
        if (!threat) return;
        
        // Update threat details modal
        document.getElementById('threat-details-ip').textContent = threat.ip || 'Unknown';
        document.getElementById('threat-details-type').textContent = threat.type || 'Unknown';
        document.getElementById('threat-details-severity').textContent = threat.severity || 'Unknown';
        document.getElementById('threat-details-time').textContent = 
            new Date(threat.timestamp).toLocaleString();
        document.getElementById('threat-details-description').textContent = 
            threat.description || 'No description available';
        
        // Show threat details modal
        document.getElementById('threat-details-modal').style.display = 'block';
    };

    // Initialize the app
    init();
});