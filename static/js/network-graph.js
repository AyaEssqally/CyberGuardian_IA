document.addEventListener('DOMContentLoaded', function() {
    // This would contain the D3.js network graph implementation
    // For now, we'll just provide a placeholder
    
    window.updateNetworkGraph = function(hosts) {
        const container = document.getElementById('network-graph');
        
        // Filter only active hosts
        const activeHosts = hosts.filter(host => host.status === 'up');
        
        if (activeHosts.length === 0) {
            container.innerHTML = '<div class="graph-placeholder"><i class="fas fa-exclamation-triangle"></i><p>No active hosts found</p></div>';
            return;
        }
        
        // Simple visualization for demo purposes
        let html = '<div class="network-visualization">';
        
        // Add central router
        html += '<div class="network-node router"><i class="fas fa-network-wired"></i><span>Router</span></div>';
        
        // Add host nodes
        activeHosts.forEach(host => {
            const hostname = host.hostnames[0]?.name || host.ip;
            const os = host.os?.name ? host.os.name.split(' ')[0] : 'Unknown';
            const portCount = host.ports.filter(p => p.state === 'open').length;
            
            html += `
                <div class="network-node host" data-ip="${host.ip}" onclick="showHostDetails('${host.ip}')">
                    <div class="node-icon">
                        <i class="fas fa-laptop"></i>
                    </div>
                    <div class="node-info">
                        <div class="node-name">${hostname}</div>
                        <div class="node-details">
                            <span>${os}</span>
                            <span>${portCount} ports</span>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    };
    
    /*
    // Example of a real D3.js implementation would look like:
    function createNetworkGraph(hosts) {
        const width = document.getElementById('network-graph').clientWidth;
        const height = 300;
        
        // Clear previous graph
        d3.select("#network-graph").html("");
        
        // Create SVG
        const svg = d3.select("#network-graph")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
            
        // Create simulation
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink().id(d => d.id))
            .force("charge", d3.forceManyBody().strength(-1000))
            .force("center", d3.forceCenter(width / 2, height / 2));
            
        // Add more D3.js code here to create the actual graph...
    }
    */
});