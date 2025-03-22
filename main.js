document.addEventListener('DOMContentLoaded', function() {
    let mdsData = [];

    // Fetch the MDS data
    fetch('mds_metadata.json')
        .then(response => response.json())
        .then(data => {
            document.getElementById('metadata-version').innerHTML = `Metadata version: ${data.no} (Next update on ${data.nextUpdate})`;
            document.getElementById('legal-header').innerHTML = data.legalHeader || '';
            mdsData = data.entries || [];
            displayTable(mdsData);
        })
        .catch(error => {
            console.error('Error loading MDS data:', error);
            document.getElementById('results').innerHTML = '<p class="error">Error loading data. Please try again later.</p>';
        });

    function displayTable(entries) {
        const resultsDiv = document.getElementById('results');
        
        if (!entries || entries.length === 0) {
            resultsDiv.innerHTML = '<p>No entries found.</p>';
            return;
        }

        // Prepare the table HTML
        let html = `
            <div class="table-container">
                <table id="mds-table" class="display">
                    <thead>
                        <tr>
                            <th>Icon</th>
                            <th>Description</th>
                            <th>Protocol&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</th>
                            <th>Updated&nbsp;&nbsp;</th>
                            <th>Extensions</th>
                            <th>Options</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        // Add rows for each entry
        entries.forEach(entry => {
            if (entry.metadataStatement) {
                const ms = entry.metadataStatement;
                const id = ms.aaguid || ms.aaid || ms.attestationCertificateKeyIdentifiers?.[0] || 'N/A';
                const status = entry.statusReports && entry.statusReports[0]?.status || 'N/A';
                let level = status === 'FIDO_CERTIFIED_L2' ? ' (L2)' : status === 'FIDO_CERTIFIED_L1' ? ' (L1)' : '';

                // Format lastUpdated as YYWnn
                let formattedDate = 'N/A';
                if (entry.timeOfLastStatusChange && entry.timeOfLastStatusChange !== 'N/A') {
                    const date = new Date(entry.timeOfLastStatusChange);
                    if (!isNaN(date.getTime())) {
                        const year = date.getFullYear().toString().slice(-2);
                        
                        // Calculate the ISO week number
                        const weekNumber = getWeekNumber(date);
                        
                        formattedDate = `${year}W${weekNumber}`;
                    } else {
                        formattedDate = entry.timeOfLastStatusChange;
                    }
                }

                // Process extensions (array of strings)
                let extensions = 'N/A';
                if (ms.authenticatorGetInfo && ms.authenticatorGetInfo.extensions) {
                    extensions = ms.authenticatorGetInfo.extensions.join('<br>');
                }

                // Process options (object keys)
                let options = 'N/A';
                if (ms.authenticatorGetInfo && ms.authenticatorGetInfo.options) {
                    options = Object.keys(ms.authenticatorGetInfo.options).join('<br>');
                }

                html += `<tr>
                    <td>
                        ${ms.icon ? 
                            `<img src="${ms.icon}" alt="Authenticator icon" class="authenticator-icon">` : 
                            'No icon'
                        }
                    </td>
                    <td><span class="tooltip">${ms.description || 'N/A'}<span class="tooltiptext">${id}</span></span></td>
                    <td>${ms.protocolFamily.toUpperCase() + level || 'N/A'}</td>
                    <td data-sort="${entry.timeOfLastStatusChange || ''}">${formattedDate}</td>
                    <td>${extensions}</td>
                    <td>${options}</td>
                </tr>`;
            }
        });
        
        html += `
                    </tbody>
                </table>
            </div>
        `;

        // Update the DOM
        resultsDiv.innerHTML = html;
        
        // Initialize DataTable
        $('#mds-table').DataTable({
            responsive: true,
            pageLength: 25,
            order: [[1, 'asc']], // Default sort by description
            columnDefs: [
                { 
                    targets: 0, // Icon column
                    orderable: false 
                }
            ],
            language: {
                search: "Filter entries:",
                lengthMenu: "Show _MENU_ entries per page"
            }
        });
    }
});

// Helper function to calculate ISO week number
function getWeekNumber(date) {
    // Copy date so don't modify original
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    // Set to nearest Thursday: current date + 4 - current day number
    // Make Sunday's day number 7
    d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
    // Get first day of year
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    // Calculate full weeks to nearest Thursday
    const weekNumber = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
    
    return weekNumber;
}