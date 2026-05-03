
                    // Safe-bind: element may not exist depending on template version
                    const _activityBtn = document.getElementById('activityLogsBtn');
                    if (_activityBtn) {
                        _activityBtn.addEventListener('click', function() {
                            console.log('Activity Logs button clicked');
                            showActivityLogs();
                        });
                    }
                


        // Track last known alert count
        let lastAlertCount = 888;
        
        // Auto-refresh every 60 seconds
        setTimeout(() => location.reload(), 60000);
        
        // Check for new critical alerts every 10 seconds
        setInterval(checkForNewAlerts, 10000);
        
        function checkForNewAlerts() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.high_risk > lastAlertCount) {
                        showAlertPopup(data.high_risk - lastAlertCount);
                        lastAlertCount = data.high_risk;
                    }
                })
                .catch(err => console.error('Failed to check alerts:', err));
        }
        
        function showAlertPopup(newAlertCount) {
            playAlertSound();
            
            const popup = document.createElement('div');
            popup.className = 'alert-popup';
            popup.innerHTML = `
                <div class="alert-popup-content">
                    <div class="alert-popup-icon">🚨</div>
                    <div class="alert-popup-title">Critical Alert Detected!</div>
                    <div class="alert-popup-message">
                        ${newAlertCount} new high-risk ${newAlertCount === 1 ? 'event' : 'events'} detected
                    </div>
                    <div class="alert-popup-actions">
                        <button class="alert-popup-btn" onclick="location.reload()">View Details</button>
                        <button class="alert-popup-btn-secondary" onclick="closeAlertPopup(this)">Dismiss</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(popup);
            
            setTimeout(() => {
                if (popup.parentElement) {
                    closeAlertPopup(popup);
                }
            }, 15000);
        }
        
        function closeAlertPopup(element) {
            const popup = element.closest ? element.closest('.alert-popup') : element;
            if (popup) {
                popup.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => popup.remove(), 300);
            }
        }
        
        function playAlertSound() {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                
                gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.5);
            } catch (e) {
                console.log('Audio not supported');
            }
        }
        
        function updateThreshold(value) {
            const threshold = (value / 100).toFixed(2);
            document.getElementById('thresholdValue').textContent = threshold;
            
            fetch('/update_threshold', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({threshold: parseFloat(threshold)})
            });
        }
        
        function exportData() {
            window.location.href = '/export_csv';
        }
        
        function clearData() {
            if(confirm('Clear all events? This cannot be undone.')) {
                fetch('/clear_all', {method: 'POST'})
                    .then(() => {
                        // update UI dynamically instead of full reload
                        updateStatsAndEvents();
                    });
            }
        }

        // New dynamic refresh function
        function refreshNow() {
            applyDashboardScope();
        }

        function scopeQuery() {
            const uf = (document.getElementById('userFilter') && document.getElementById('userFilter').value) || '';
            const af = (document.getElementById('agentFilter') && document.getElementById('agentFilter').value) || '';
            const q = [];
            if (uf) q.push('user=' + encodeURIComponent(uf));
            if (af) q.push('agent=' + encodeURIComponent(af));
            return q.length ? ('?' + q.join('&')) : '';
        }

        // Fetch stats and events and update the DOM
        function updateStatsAndEvents() {
            const qs = scopeQuery();
            Promise.all([
                fetch('/api/stats').then(r => r.json()),
                fetch('/api/events' + qs).then(r => r.json())
            ]).then(([stats, events]) => {
                // Update stat elements
                const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
                setText('stat-total-events', stats.total_events);
                setText('stat-file-events', stats.file_events);
                setText('stat-usb-events', stats.usb_events);
                setText('stat-logon-events', stats.logon_events);
                setText('stat-clipboard-events', stats.clipboard_events);
                setText('stat-process-events', stats.process_events);
                setText('stat-outlook-events', stats.outlook_events);
                setText('stat-imap-events', stats.imap_events);
                setText('stat-high-risk', stats.high_risk);
                setText('stat-avg-risk', (stats.total_events>0? (stats.avg_risk||0).toFixed(2): '0.00'));

                // Rebuild events table body
                const tbody = document.getElementById('events-tbody');
                if (tbody) {
                    if (!events || events.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="6" class="no-data"><div class="no-data-icon">📊</div><div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">No Events Detected</div><div style="color: #6B7280;">Waiting for user activity...</div></td></tr>`;
                    } else {
                        tbody.innerHTML = events.map(ev => {
                            const badgeClass = ev.event_type || 'unknown';
                            return `
                                <tr data-event-type="${ev.event_type}" data-detail="${(ev.details||'').replace(/"/g,'&quot;')}" data-summary="${(ev.details||'').replace(/"/g,'&quot;')}">
                                    <td style="font-family: 'Courier New', monospace; color: #9CA3AF;">${ev.timestamp}</td>
                                    <td style="font-weight: 600;">${ev.agent_id}</td>
                                    <td><span class="badge badge-${badgeClass}">${(ev.event_type||'').toUpperCase()}</span></td>
                                    <td>${(ev.action||'').replace(/_/g,' ')}</td>
                                    <td style="max-width: 400px; color: #9CA3AF; font-size: 0.85rem;">${ev.details}</td>
                                    <td><span class="badge ${ev.risk_class}">${(ev.risk_score||0).toFixed(3)}</span></td>
                                </tr>`;
                        }).join('\n');
                    }
                }
            }).catch(err => console.error('Failed to refresh stats/events:', err));
        }

        function loadDashboardAlerts() {
            fetch('/api/dashboard/alerts' + scopeQuery())
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('dashboard-alerts-tbody');
                    if (!tbody) return;
                    const rows = data.alerts || [];
                    if (rows.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="6" class="no-data"><div class="no-data-icon">🔔</div><div style="font-size: 1rem;">No alerts for this scope</div><div style="color: #6B7280; font-size: 0.85rem;">Pick another user/endpoint or lower the risk threshold.</div></td></tr>`;
                        return;
                    }
                    tbody.innerHTML = rows.map(a => {
                        const sev = (a.severity || 'MEDIUM');
                        let cls = 'risk-medium';
                        if (sev === 'CRITICAL' || sev === 'HIGH') cls = 'risk-critical';
                        else if (sev === 'LOW') cls = 'risk-low';
                        return `<tr>
                            <td style="font-family: monospace; font-size: 0.8rem; color: #9CA3AF;">${(a.time || '').toString().slice(0, 24)}</td>
                            <td>${(a.agent_id || '—')}</td>
                            <td style="font-weight: 600;">${a.user || '—'}</td>
                            <td><span class="badge badge-unknown">${(a.metric || '').replace(/_/g, ' ')}</span></td>
                            <td style="max-width: 360px; color: #9CA3AF; font-size: 0.85rem;">${(a.note || '').replace(/</g, '&lt;')}</td>
                            <td><span class="badge ${cls}">${sev}</span></td>
                        </tr>`;
                    }).join('');
                })
                .catch(err => console.error('Failed to load dashboard alerts:', err));
        }

        function loadScreenshotsIntoModal() {
            fetch('/api/screenshots')
                .then(r => r.json())
                .then(items => {
                    const tbody = document.getElementById('screenshots-modal-tbody');
                    if (!tbody) return;
                    const uf = (document.getElementById('userFilter') && document.getElementById('userFilter').value) || '';
                    const af = (document.getElementById('agentFilter') && document.getElementById('agentFilter').value) || '';

                    let rows = Array.isArray(items) ? items : [];
                    if (uf) {
                        rows = rows.filter(x => (x.user || '').toString() === uf);
                    }
                    // screenshots API doesn't store agent_id separately; fall back to filename match
                    if (af) {
                        rows = rows.filter(x => (x.filename || '').toString().includes(af));
                    }

                    if (!rows.length) {
                        tbody.innerHTML = `<tr><td colspan="5" class="no-data"><div class="no-data-icon">📸</div><div style="font-size: 1rem;">No screenshots for this scope</div><div style="color: #6B7280; font-size: 0.85rem;">Trigger a sensitive clipboard/file event on the endpoint.</div></td></tr>`;
                        return;
                    }

                    tbody.innerHTML = rows.slice(0, 20).map(s => {
                        const ts = (s.timestamp || '').toString();
                        const u = s.user || 'unknown';
                        const sev = s.severity || 'LOW';
                        const url = s.url || (`/screenshot/${encodeURIComponent(s.filename)}`);
                        return `<tr>
                            <td style="font-family: monospace; font-size: 0.8rem; color: #9CA3AF;">${ts.slice(0, 24)}</td>
                            <td style="font-weight: 600;">${u}</td>
                            <td><span class="badge ${sev==='CRITICAL'?'risk-critical':sev==='HIGH'?'risk-high':sev==='MEDIUM'?'risk-medium':'risk-low'}">${sev}</span></td>
                            <td><img src="${url}" style="height:36px;border-radius:6px;border:1px solid #374151" /></td>
                            <td><a class="btn" style="display:inline-block; padding: 0.3rem 0.8rem; font-size: 0.85rem; text-decoration:none;" href="${url}" target="_blank">Open</a></td>
                        </tr>`;
                    }).join('');
                })
                .catch(err => console.error('Failed to load screenshots:', err));
        }

        function openScreenshotsModal() {
            const modal = document.getElementById('screenshotsModal');
            if (!modal) return;
            loadScreenshotsIntoModal();
            modal.style.display = 'flex';
        }

        function closeScreenshotsModal() {
            const modal = document.getElementById('screenshotsModal');
            if (modal) modal.style.display = 'none';
        }

        function applyDashboardScope() {
            updateStatsAndEvents();
            loadDashboardAlerts();
            loadIncidents();
            loadLeaderboard();
            loadAuditTrail();
        }

        // Event filter logic — only the main activity table (#events-tbody)
        const filterButtons = document.querySelectorAll('.event-filter-btn');

        filterButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                filterButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const filter = btn.getAttribute('data-filter');
                const eventRows = document.querySelectorAll('#events-tbody tr');
                eventRows.forEach(row => {
                    if (filter === 'all' || row.getAttribute('data-event-type') === filter) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        });

        // Event details modal logic
        const eventTable = document.querySelector('.event-section tbody');
        if (eventTable) {
            eventTable.addEventListener('click', function(evt) {
                let tr = evt.target.closest('tr');
                if (tr && tr.getAttribute('data-summary')) {
                    const summary = tr.getAttribute('data-summary');
                    const modal = document.createElement('div');
                    modal.className = 'event-modal-bg';
                    modal.innerHTML = `
                        <div class='event-modal'>
                            <h2>Event Details</h2>
                            <div style="white-space: pre-wrap; font-family: monospace; background: #0B0F19; padding: 1rem; border-radius: 8px; margin: 1rem 0;">${summary}</div>
                            <button onclick='this.parentElement.parentElement.remove()'>Close</button>
                        </div>
                    `;
                    document.body.appendChild(modal);
                }
            });
        }
        // Activity Log Modal
        function showActivityLogs() {
            console.log('Showing activity logs...');
            // Create and show loading indicator
            const loadingModal = document.createElement('div');
            loadingModal.className = 'activity-log-modal';
            loadingModal.innerHTML = `
                <div class="activity-log-content" style="text-align: center; padding: 2rem;">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">📋</div>
                    <div>Loading activity logs...</div>
                </div>
            `;
            document.body.appendChild(loadingModal);

            // Fetch the logs
            fetch('/api/activity_logs')
                .then(response => {
                    console.log('Response received:', response);
                    return response.json();
                })
                .then(logs => {
                    console.log('Logs received:', logs);
                    // Remove loading indicator
                    loadingModal.remove();
                    
                    // Create the actual logs modal
                    const modal = document.createElement('div');
                    modal.className = 'activity-log-modal';
                    modal.innerHTML = `
                        <div class="activity-log-content">
                            <div class="activity-log-header">
                                <h2>📋 User Activity Logs</h2>
                                <div class="activity-log-controls">
                                    <button class="refresh-btn" onclick="refreshActivityLogs()">🔄 Refresh</button>
                                    <button class="close-btn" onclick="closeActivityModal(this)">×</button>
                                </div>
                            </div>
                            <div class="activity-log-body">
                                ${logs.length > 0 ? logs.map(log => `
                                    <div class="log-entry ${log.event_type.toLowerCase()}">
                                        <div class="log-time">${log.timestamp}</div>
                                        <div class="log-type">${log.event_type}</div>
                                        <div class="log-details">${formatLogDetails(log)}</div>
                                    </div>
                                `).join('') : '<div class="no-logs">No activity logs found</div>'}
                            </div>
                        </div>
                    `;
                    document.body.appendChild(modal);

                    // Add click handler to close modal when clicking outside
                    modal.addEventListener('click', function(e) {
                        if (e.target === modal) {
                            modal.remove();
                        }
                    });
                })
                .catch(error => {
                    console.error('Error fetching logs:', error);
                    loadingModal.innerHTML = `
                        <div class="activity-log-content" style="text-align: center; padding: 2rem;">
                            <div style="font-size: 2rem; margin-bottom: 1rem;">⚠️</div>
                            <div>Error loading activity logs</div>
                            <button onclick="this.closest('.activity-log-modal').remove()" style="margin-top: 1rem;">Close</button>
                        </div>
                    `;
                });
        }

        function formatLogDetails(log) {
            if (typeof log.details === 'object') {
                return Object.entries(log.details)
                    .map(([key, value]) => `<strong>${key}:</strong> ${value}`)
                    .join('<br>');
            }
            return log.details;
        }

        function closeActivityModal(button) {
            const modal = button.closest('.activity-log-modal');
            if (modal) {
                modal.style.opacity = '0';
                setTimeout(() => modal.remove(), 300);
            }
        }

        function refreshActivityLogs() {
            const currentModal = document.querySelector('.activity-log-modal');
            if (currentModal) {
                currentModal.remove();
            }
            showActivityLogs();
        }

        // Load user risk leaderboard
        function loadLeaderboard() {
            fetch('/api/users/risk_leaderboard')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('leaderboard-tbody');
                    if (!tbody) return;
                    
                    const users = data.leaderboard || [];
                    if (users.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="5" class="no-data"><div class="no-data-icon">👥</div><div style="font-size: 1.2rem; font-weight: 600;">No User Risk Data</div><div style="color: #6B7280;">Waiting for activity analysis...</div></td></tr>`;
                        return;
                    }
                    
                    tbody.innerHTML = users.slice(0, 20).map(user => {
                        const riskPct = (user.risk_score * 100).toFixed(1);
                        let riskLevel = 'LOW', riskClass = 'risk-low';
                        if (user.risk_score >= 0.8) {
                            riskLevel = 'CRITICAL';
                            riskClass = 'risk-critical';
                        } else if (user.risk_score >= 0.6) {
                            riskLevel = 'HIGH';
                            riskClass = 'risk-high';
                        } else if (user.risk_score >= 0.4) {
                            riskLevel = 'MEDIUM';
                            riskClass = 'risk-medium';
                        }
                        
                        const factors = user.risk_factors || {};
                        const factorsList = Object.entries(factors)
                            .map(([key, val]) => `${key}: ${(val * 100).toFixed(0)}%`)
                            .join(', ');
                        
                        return `
                            <tr class="user-row" onclick="selectUserForScope('${user.username}', ${JSON.stringify(user).replace(/'/g, '&#39;')})">
                                <td style="font-weight: 600; cursor: pointer; transition: color 0.2s;" onmouseover="this.style.color='#60a5fa'" onmouseout="this.style.color='#E5E7EB'">${user.username}</td>
                                <td><span class="badge ${riskClass}">${riskPct}%</span></td>
                                <td><span class="badge ${riskClass}">${riskLevel}</span></td>
                                <td style="font-size: 0.85rem; color: #9CA3AF;">${factorsList || 'N/A'}</td>
                                <td><button class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.85rem;" onclick="event.stopPropagation(); selectUserForScope('${user.username}', ${JSON.stringify(user).replace(/'/g, '&#39;')})">👤 View</button></td>
                            </tr>
                        `;
                    }).join('\n');
                })
                .catch(err => console.error('Failed to load leaderboard:', err));
        }

        // Load incidents (includes high-risk rows derived from events)
        function loadIncidents() {
            fetch('/incidents' + scopeQuery())
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('incidents-tbody');
                    if (!tbody) return;
                    
                    const incidents = (data.incidents || []);
                    if (incidents.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="6" class="no-data"><div class="no-data-icon">🔐</div><div style="font-size: 1.2rem; font-weight: 600;">No incidents for this scope</div><div style="color: #6B7280;">Try &quot;All endpoints&quot; / &quot;All users&quot; or generate high-risk events.</div></td></tr>`;
                        return;
                    }
                    
                    tbody.innerHTML = incidents.slice(0, 50).map(incident => {
                        let severityClass = 'risk-low';
                        if (incident.severity === 'CRITICAL') severityClass = 'risk-critical';
                        else if (incident.severity === 'HIGH') severityClass = 'risk-high';
                        else if (incident.severity === 'MEDIUM') severityClass = 'risk-medium';
                        
                        let statusClass = 'badge';
                        const st = (incident.status || '').toString().toUpperCase();
                        if (st === 'OPEN') statusClass += ' risk-critical';
                        else if (st === 'IN_PROGRESS') statusClass += ' risk-high';
                        else statusClass += ' risk-low';
                        const when = incident.timestamp || incident.created_at || 'Unknown';
                        
                        return `
                            <tr>
                                <td style="font-weight: 600;">${incident.title || 'Untitled Incident'}</td>
                                <td><span class="badge ${severityClass}">${incident.severity || 'UNKNOWN'}</span></td>
                                <td><span class="${statusClass}">${st || 'UNKNOWN'}</span></td>
                                <td style="font-size: 0.85rem;">${(incident.affected_users || []).join(', ') || 'N/A'}</td>
                                <td style="font-size: 0.85rem; color: #9CA3AF;">${when}</td>
                                <td><button class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.85rem;">📋</button></td>
                            </tr>
                        `;
                    }).join('\n');
                })
                .catch(err => console.error('Failed to load incidents:', err));
        }

        // Load audit trail
        function loadAuditTrail() {
            const uf = (document.getElementById('userFilter') && document.getElementById('userFilter').value) ? document.getElementById('userFilter').value : '';
            const qs = uf ? ('?user_id=' + encodeURIComponent(uf)) : '';
            fetch('/api/audit_log' + qs)
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('audit-tbody');
                    if (!tbody) return;
                    
                    const entries = (data.entries || []).slice(0, 100);
                    if (entries.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="5" class="no-data"><div class="no-data-icon">📋</div><div style="font-size: 1.2rem; font-weight: 600;">No Audit Records</div><div style="color: #6B7280;">No admin actions yet</div></td></tr>`;
                        return;
                    }
                    
                    tbody.innerHTML = entries.map(entry => {
                        return `
                            <tr>
                                <td style="font-family: 'Courier New', monospace; color: #9CA3AF; font-size: 0.85rem;">${entry.timestamp || 'Unknown'}</td>
                                <td style="font-weight: 600;">${entry.admin || 'System'}</td>
                                <td>${entry.action || 'Unknown'}</td>
                                <td>${entry.target_user || 'N/A'}</td>
                                <td style="font-size: 0.85rem; color: #9CA3AF; max-width: 300px;">${entry.details || 'N/A'}</td>
                            </tr>
                        `;
                    }).join('\n');
                })
                .catch(err => console.error('Failed to load audit trail:', err));
        }

        function selectUserForScope(username, userDataStr) {
            const uf = document.getElementById('userFilter');
            if (uf) uf.value = username;
            applyDashboardScope();
            showUserDetails(username, userDataStr);
        }

        // Show user detail modal
        function showUserDetails(username, userDataStr) {
            const userData = typeof userDataStr === 'string' ? JSON.parse(userDataStr) : userDataStr;
            const modal = document.getElementById('userModal');
            const title = document.getElementById('userModalTitle');
            const body = document.getElementById('userModalBody');
            
            if (!modal) return;
            
            title.textContent = `User Details: ${username}`;
            
            const riskScore = userData.risk_score || 0;
            const riskPct = (riskScore * 100).toFixed(1);
            const factors = userData.risk_factors || {};
            
            let riskLevel = 'LOW', riskColor = '#10B981';
            if (riskScore >= 0.8) {
                riskLevel = 'CRITICAL';
                riskColor = '#EF4444';
            } else if (riskScore >= 0.6) {
                riskLevel = 'HIGH';
                riskColor = '#FB923C';
            } else if (riskScore >= 0.4) {
                riskLevel = 'MEDIUM';
                riskColor = '#FBBF24';
            }
            
            const meterColor = riskColor;
            const meterWidth = (riskScore * 100).toFixed(1) + '%';
            
            body.innerHTML = `
                <div style="margin-bottom: 2rem;">
                    <div style="font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; color: #E5E7EB;">Risk Score: <span style="color: ${riskColor};">${riskPct}%</span></div>
                    <div style="font-size: 0.9rem; color: #9CA3AF; margin-bottom: 1rem;">Risk Level: <span style="color: ${riskColor}; font-weight: 600;">${riskLevel}</span></div>
                    <div class="risk-meter">
                        <div class="risk-meter-fill" style="width: ${meterWidth}; background-color: ${meterColor};"></div>
                    </div>
                </div>
                
                <div style="background: rgba(0, 0, 0, 0.3); border-radius: 8px; padding: 1rem; margin-bottom: 2rem;">
                    <div style="font-weight: 600; margin-bottom: 1rem; color: #E5E7EB;">Risk Factor Breakdown</div>
                    ${Object.entries(factors).map(([key, val]) => {
                        const factorPct = (val * 100).toFixed(1);
                        return `
                            <div class="risk-factor-item">
                                <span class="risk-factor-label">${key.replace(/_/g, ' ')}</span>
                                <span class="risk-factor-value">${factorPct}%</span>
                            </div>
                        `;
                    }).join('')}
                </div>
                
                <div style="text-align: center; color: #6B7280; font-size: 0.9rem;">
                    <p>Click "Close" to view this user's events, incidents, and audit actions.</p>
                </div>
            `;
            
            modal.style.display = 'flex';
        }

        function closeUserModal() {
            const modal = document.getElementById('userModal');
            if (modal) {
                modal.style.display = 'none';
            }
        }

        // Close user modal when clicking outside
        window.addEventListener('click', function(event) {
            const modal = document.getElementById('userModal');
            if (modal && event.target === modal) {
                modal.style.display = 'none';
            }
        });

        // Populate endpoint + user dropdowns from activity
        function loadScopeFilters() {
            fetch('/api/users')
                .then(r => r.json())
                .then(data => {
                    const userSel = document.getElementById('userFilter');
                    const agentSel = document.getElementById('agentFilter');
                    if (!userSel || !agentSel) return;
                    
                    const users = data.users || [];
                    const agents = data.agents || [];
                    
                    while (userSel.options.length > 1) userSel.remove(1);
                    while (agentSel.options.length > 1) agentSel.remove(1);
                    
                    agents.forEach(aid => {
                        const o = document.createElement('option');
                        o.value = aid;
                        o.textContent = '🖥 ' + aid;
                        agentSel.appendChild(o);
                    });
                    
                    users.forEach(user => {
                        const option = document.createElement('option');
                        option.value = user;
                        // Display only the actual username part (DOMAIN\user → user)
                        const label = (user || '').toString().includes('\\') ? (user.toString().split('\\').slice(-1)[0]) : user;
                        option.textContent = '👤 ' + label;
                        userSel.appendChild(option);
                    });
                })
                .catch(err => console.error('Failed to load scope filters:', err));
        }

        function setupScopeHandlers() {
            const userFilter = document.getElementById('userFilter');
            const agentFilter = document.getElementById('agentFilter');
            const onChange = () => applyDashboardScope();
            if (userFilter) userFilter.addEventListener('change', onChange);
            if (agentFilter) agentFilter.addEventListener('change', onChange);
        }

        // Initialize - load data on page load
        window.addEventListener('load', function() {
            console.log('Page loaded, initializing dashboard...');
            loadScopeFilters();
            setupScopeHandlers();
            applyDashboardScope();
        });

        // Refresh scoped data every 30 seconds
        setInterval(function() {
            applyDashboardScope();
        }, 30000);
    