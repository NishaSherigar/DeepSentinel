# =============================================================================
# DeepSentinel — multi_lan_addon.py
# Tracks multiple agent machines and adds /agents endpoint.
# Zero changes to existing server.py HTML needed.
#
# ADD to server.py before if __name__ == '__main__':
#   from multi_lan_addon import register_multi_lan
#   register_multi_lan(app)
# =============================================================================

import os, sys, json, threading
from datetime import datetime, timedelta
from flask import request, jsonify, render_template_string

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# ── Agent registry ─────────────────────────────────────────────────────────
# Tracks all machines that have sent events
_agents = {}   # agent_id → {last_seen, ip, events_count, risk_scores, status}
_lock   = threading.Lock()


def update_agent(agent_id, ip, risk_score, event_type):
    """Called on every /receive_log event to update agent status."""
    now = datetime.now().isoformat()
    with _lock:
        if agent_id not in _agents:
            _agents[agent_id] = {
                "agent_id":     agent_id,
                "ip":           ip,
                "first_seen":   now,
                "last_seen":    now,
                "events_count": 0,
                "risk_scores":  [],
                "event_types":  {},
                "status":       "active",
                "peak_risk":    0.0,
                "avg_risk":     0.0,
            }
            print(f"🖥️  New agent connected: {agent_id} ({ip})")

        a = _agents[agent_id]
        a["last_seen"]     = now
        a["ip"]            = ip
        a["events_count"] += 1

        # Track risk scores (keep last 50)
        a["risk_scores"].append(float(risk_score or 0))
        a["risk_scores"] = a["risk_scores"][-50:]
        a["peak_risk"]   = max(a["risk_scores"])
        a["avg_risk"]    = round(
            sum(a["risk_scores"]) / len(a["risk_scores"]), 3)

        # Track event types
        et = event_type or "unknown"
        a["event_types"][et] = a["event_types"].get(et, 0) + 1


def _get_agent_status(agent):
    """Calculate if agent is active/idle/offline."""
    try:
        last = datetime.fromisoformat(agent["last_seen"])
        diff = (datetime.now() - last).total_seconds()
        if diff < 60:   return "active"
        if diff < 300:  return "idle"
        return "offline"
    except:
        return "unknown"


# =============================================================================
# AGENTS DASHBOARD PAGE
# =============================================================================

AGENTS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>DeepSentinel — Connected Agents</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="10">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Inter',sans-serif; background:#0B0F19; color:#E5E7EB; padding:2rem; }

        .header {
            display:flex; align-items:center; justify-content:space-between;
            margin-bottom:2rem;
        }
        h1 {
            font-size:1.5rem; font-weight:700;
            background:linear-gradient(135deg,#60a5fa,#2065ba);
            -webkit-background-clip:text; -webkit-text-fill-color:transparent;
        }
        .back {
            background:rgba(99,102,241,.15); color:#2065ba;
            border:1px solid rgba(99,102,241,.3);
            padding:.5rem 1.25rem; border-radius:8px;
            text-decoration:none; font-size:.9rem; font-weight:600;
        }

        .stats-row {
            display:grid; grid-template-columns:repeat(4,1fr);
            gap:1rem; margin-bottom:2rem;
        }
        .stat {
            background:linear-gradient(135deg,#1a1f2e,#0f1419);
            border:1px solid #1F2937; border-radius:12px; padding:1.25rem;
        }
        .stat-label { font-size:.75rem; color:#6B7280; text-transform:uppercase;
                      letter-spacing:.05em; margin-bottom:.5rem; }
        .stat-value { font-size:2rem; font-weight:700; color:#60a5fa; }

        .agent-grid {
            display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
            gap:1.5rem;
        }
        .agent-card {
            background:linear-gradient(135deg,#1a1f2e,#0f1419);
            border:1px solid #1F2937; border-radius:16px; padding:1.5rem;
            transition:all .2s;
        }
        .agent-card:hover {
            border-color:#374151;
            box-shadow:0 8px 24px rgba(99,102,241,.1);
        }
        .agent-card.critical { border-color:rgba(239,68,68,.4); }
        .agent-card.high     { border-color:rgba(249,115,22,.4); }

        .agent-header {
            display:flex; align-items:center; justify-content:space-between;
            margin-bottom:1rem;
        }
        .agent-id { font-size:1rem; font-weight:700; color:#E5E7EB; }
        .agent-ip { font-size:.75rem; color:#6B7280; margin-top:.2rem; }

        .status-dot {
            width:10px; height:10px; border-radius:50%; display:inline-block;
            margin-right:6px;
        }
        .status-active  { background:#10B981; box-shadow:0 0 8px #10B981; animation:pulse 2s infinite; }
        .status-idle    { background:#EAB308; }
        .status-offline { background:#6B7280; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }

        .status-badge {
            padding:.2rem .75rem; border-radius:20px; font-size:.72rem; font-weight:700;
        }
        .badge-active  { background:rgba(16,185,129,.2); color:#10B981; }
        .badge-idle    { background:rgba(234,179,8,.2);  color:#EAB308; }
        .badge-offline { background:rgba(107,114,128,.2);color:#6B7280; }

        .risk-bar-wrap {
            background:#1F2937; border-radius:4px; height:6px; margin:.5rem 0;
        }
        .risk-bar { height:6px; border-radius:4px; transition:width .5s; }
        .risk-critical { background:#EF4444; }
        .risk-high     { background:#F97316; }
        .risk-medium   { background:#EAB308; }
        .risk-low      { background:#10B981; }

        .stats-grid {
            display:grid; grid-template-columns:1fr 1fr; gap:.5rem; margin-top:1rem;
        }
        .mini-stat { background:#0f1419; border-radius:8px; padding:.75rem; }
        .mini-label { font-size:.7rem; color:#6B7280; margin-bottom:.25rem; }
        .mini-value { font-size:1.1rem; font-weight:700; color:#2065ba; }

        .events-breakdown {
            margin-top:1rem; padding-top:1rem;
            border-top:1px solid #1F2937;
        }
        .events-title { font-size:.75rem; color:#6B7280;
                        text-transform:uppercase; margin-bottom:.5rem; }
        .event-pill {
            display:inline-block; padding:.2rem .6rem; border-radius:6px;
            font-size:.7rem; font-weight:600; margin:.2rem .2rem 0 0;
            background:rgba(99,102,241,.15); color:#2065ba;
        }

        .action-btns {
            display:flex; gap:.5rem; margin-top:1rem;
            padding-top:1rem; border-top:1px solid #1F2937;
        }
        .btn {
            flex:1; padding:.5rem; border:none; border-radius:8px;
            font-size:.75rem; font-weight:700; cursor:pointer; transition:all .2s;
        }
        .btn-block  { background:rgba(239,68,68,.2); color:#EF4444;
                      border:1px solid rgba(239,68,68,.3); }
        .btn-block:hover  { background:rgba(239,68,68,.4); }
        .btn-shot   { background:rgba(99,102,241,.2); color:#2065ba;
                      border:1px solid rgba(99,102,241,.3); }
        .btn-shot:hover   { background:rgba(99,102,241,.4); }
        .btn-unlock { background:rgba(16,185,129,.2); color:#10B981;
                      border:1px solid rgba(16,185,129,.3); }
        .btn-unlock:hover { background:rgba(16,185,129,.4); }

        .last-seen { font-size:.72rem; color:#6B7280; margin-top:.75rem; }
        .no-agents { text-align:center; padding:4rem; color:#6B7280; font-size:1.1rem; }
        .refresh-note { text-align:right; font-size:.75rem; color:#374151;
                        margin-top:1rem; }
    </style>
</head>
<body>

<div class="header">
    <div>
        <h1>🖥️ Connected Agents — Multi-LAN Monitor</h1>
        <p style="color:#6B7280;font-size:.85rem;margin-top:.25rem">
            All machines reporting to DeepSentinel
        </p>
    </div>
    <a href="/dashboard" class="back">← Dashboard</a>
</div>

<!-- Summary stats -->
<div class="stats-row">
    <div class="stat">
        <div class="stat-label">Total Machines</div>
        <div class="stat-value">{{ agents|length }}</div>
    </div>
    <div class="stat">
        <div class="stat-label">Active Now</div>
        <div class="stat-value" style="color:#10B981">
            {{ agents|selectattr('status','eq','active')|list|length }}
        </div>
    </div>
    <div class="stat">
        <div class="stat-label">High Risk</div>
        <div class="stat-value" style="color:#EF4444">
            {{ agents|selectattr('peak_risk','gt',0.7)|list|length }}
        </div>
    </div>
    <div class="stat">
        <div class="stat-label">Total Events</div>
        <div class="stat-value">
            {{ agents|sum(attribute='events_count') }}
        </div>
    </div>
</div>

<!-- Agent cards -->
{% if agents %}
<div class="agent-grid">
    {% for agent in agents|sort(attribute='peak_risk', reverse=True) %}
    {% set risk = agent.peak_risk %}
    {% set status = agent.status %}

    <div class="agent-card
        {% if risk > 0.9 %}critical{% elif risk > 0.7 %}high{% endif %}">

        <!-- Header -->
        <div class="agent-header">
            <div>
                <div class="agent-id">
                    🖥️ {{ agent.agent_id }}
                </div>
                <div class="agent-ip">IP: {{ agent.ip or 'unknown' }}</div>
            </div>
            <span class="status-badge badge-{{ status }}">
                <span class="status-dot status-{{ status }}"></span>
                {{ status|upper }}
            </span>
        </div>

        <!-- Risk bar -->
        <div style="font-size:.75rem;color:#9CA3AF;margin-bottom:.25rem">
            Peak Risk Score
        </div>
        <div class="risk-bar-wrap">
            <div class="risk-bar
                {% if risk > 0.9 %}risk-critical
                {% elif risk > 0.7 %}risk-high
                {% elif risk > 0.5 %}risk-medium
                {% else %}risk-low{% endif %}"
                style="width:{{ (risk * 100)|int }}%">
            </div>
        </div>
        <div style="font-size:.8rem;color:
            {% if risk > 0.9 %}#EF4444
            {% elif risk > 0.7 %}#F97316
            {% elif risk > 0.5 %}#EAB308
            {% else %}#10B981{% endif %};
            font-weight:700">
            {{ '%.3f'|format(risk) }}
            {% if risk > 0.9 %} 💀 CRITICAL
            {% elif risk > 0.7 %} 🔴 HIGH
            {% elif risk > 0.5 %} 🟡 MEDIUM
            {% else %} 🟢 LOW{% endif %}
        </div>

        <!-- Mini stats -->
        <div class="stats-grid">
            <div class="mini-stat">
                <div class="mini-label">Total Events</div>
                <div class="mini-value">{{ agent.events_count }}</div>
            </div>
            <div class="mini-stat">
                <div class="mini-label">Avg Risk</div>
                <div class="mini-value">{{ '%.3f'|format(agent.avg_risk) }}</div>
            </div>
        </div>

        <!-- Event type breakdown -->
        <div class="events-breakdown">
            <div class="events-title">Event Types</div>
            {% for etype, count in agent.event_types.items() %}
            <span class="event-pill">{{ etype }}: {{ count }}</span>
            {% endfor %}
        </div>

        <!-- Admin action buttons -->
        <div class="action-btns">
            <button class="btn btn-block"
                onclick="sendCmd('{{ agent.agent_id }}','block')">
                🔒 Block
            </button>
            <button class="btn btn-shot"
                onclick="sendCmd('{{ agent.agent_id }}','screenshot')">
                📸 Screenshot
            </button>
            <button class="btn btn-unlock"
                onclick="sendCmd('{{ agent.agent_id }}','unblock')">
                🔓 Unblock
            </button>
        </div>

        <div class="last-seen">
            Last seen: {{ agent.last_seen[:19] }}
        </div>

    </div>
    {% endfor %}
</div>

{% else %}
<div class="no-agents">
    No agents connected yet.<br>
    <span style="font-size:.9rem;margin-top:.5rem;display:block">
        Run file_agent.py or run_agent.py on monitored machines.
    </span>
</div>
{% endif %}

<div class="refresh-note">Auto-refreshes every 10 seconds</div>

<script>
function sendCmd(agentId, command) {
    const labels = {
        'block':      'Block internet on ' + agentId + '?',
        'unblock':    'Unblock ' + agentId + '?',
        'screenshot': 'Request screenshot from ' + agentId + '?',
    };
    if (!confirm(labels[command] || command + ' on ' + agentId + '?')) return;

    fetch('/admin/command', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            agent_id: agentId,
            command:  command,
            reason:   'Admin action from agents page',
            admin:    'admin'
        })
    })
    .then(r => r.json())
    .then(d => {
        alert('✅ Command sent: ' + d.message);
    })
    .catch(e => alert('❌ Error: ' + e));
}
</script>

</body>
</html>
"""


# =============================================================================
# REGISTER ROUTES
# =============================================================================

def register_multi_lan(app):
    """Wire multi-LAN tracking into server.py."""

    # Patch receive_log to track agents
    try:
        original = app.view_functions['receive_log']
    except KeyError:
        print("⚠️  receive_log not found")
        return

    def patched_receive_log():
        response = original()
        try:
            data     = request.get_json(force=True, silent=True) or {}
            ip       = request.remote_addr or "unknown"
            events   = data.get('events', [])
            if not events and 'event_type' in data:
                events = [data]

            for evt in events:
                agent_id   = (evt.get('agent_id') or
                              data.get('agent_id') or 'unknown')
                risk_score = float(evt.get('risk_score', 0) or 0)
                event_type = evt.get('event_type', 'unknown')
                update_agent(agent_id, ip, risk_score, event_type)
        except Exception as e:
            pass
        return response

    app.view_functions['receive_log'] = patched_receive_log

    # Agents dashboard page
    @app.route('/agents')
    def agents_page():
        with _lock:
            agent_list = []
            for a in _agents.values():
                entry = dict(a)
                entry['status'] = _get_agent_status(a)
                agent_list.append(entry)
        return render_template_string(AGENTS_HTML, agents=agent_list)

    # API endpoint for agent data
    @app.route('/api/agents')
    def api_agents():
        with _lock:
            agent_list = []
            for a in _agents.values():
                entry = dict(a)
                entry['status'] = _get_agent_status(a)
                # Don't return full risk_scores array
                entry.pop('risk_scores', None)
                agent_list.append(entry)
        return jsonify(agent_list)

    print("✅ Multi-LAN tracking registered")
    print("   /agents     → agent machines dashboard")
    print("   /api/agents → JSON agent data")
