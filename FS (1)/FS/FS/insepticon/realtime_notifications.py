# =============================================================================
# DeepSentinel — realtime_notifications.py
# Real-Time Notification System
# Supports WebSocket, Email, and Slack notifications
# =============================================================================

import os
import json
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))


class NotificationManager:
    """Manages real-time alerts via multiple channels"""
    
    CHANNELS = ['websocket', 'email', 'slack']
    
    def __init__(self):
        self.config_path = os.path.join(ROOT, "config.json")
        self.notif_log_path = os.path.join(ROOT, "data", "notifications.jsonl")
        self.notification_queue = []
        self.websocket_subscribers = []  # Will be populated by Flask
        self.config = self._load_config()
        
        os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    
    def _load_config(self):
        """Load notification config"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                return config.get('notifications', {
                    'email_enabled': True,
                    'slack_enabled': False,
                    'websocket_enabled': True,
                    'smtp_server': 'localhost',
                    'smtp_port': 25,
                    'slack_webhook': None,
                    'min_severity': 'HIGH',  # Only send HIGH and CRITICAL
                    'batch_interval': 300  # Send in batches every 5 minutes
                })
        except:
            return {
                'email_enabled': True,
                'slack_enabled': False,
                'websocket_enabled': True,
                'smtp_server': 'localhost',
                'smtp_port': 25,
                'slack_webhook': None,
                'min_severity': 'HIGH',
                'batch_interval': 300
            }
    
    def notify_alert(self, alert_data, channels=['websocket', 'email'], immediate=False):
        """
        Send alert notification via specified channels
        alert_data: {
            'alert_id': str,
            'severity': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
            'alert_type': str,
            'user_id': str,
            'message': str,
            'timestamp': str,
            'details': dict
        }
        """
        
        # Check severity filter
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        min_sev_order = severity_order.get(self.config.get('min_severity', 'HIGH'), 3)
        
        if severity_order.get(alert_data.get('severity', 'LOW'), 1) < min_sev_order:
            return False
        
        notification = {
            'alert_id': alert_data.get('alert_id'),
            'severity': alert_data.get('severity'),
            'alert_type': alert_data.get('alert_type'),
            'user_id': alert_data.get('user_id'),
            'message': alert_data.get('message'),
            'timestamp': datetime.now().isoformat(),
            'channels_sent': [],
            'status': 'QUEUED'
        }
        
        # Queue for batch processing unless immediate
        if immediate:
            self._send_notification(notification, channels)
        else:
            self.notification_queue.append((notification, channels))
        
        # Log notification
        self._log_notification(notification)
        
        return True
    
    def _send_notification(self, notification, channels):
        """Send notification immediately"""
        
        for channel in channels:
            if channel == 'websocket' and self.config.get('websocket_enabled'):
                self._send_websocket(notification)
            
            elif channel == 'email' and self.config.get('email_enabled'):
                self._send_email(notification)
            
            elif channel == 'slack' and self.config.get('slack_enabled'):
                self._send_slack(notification)
        
        notification['status'] = 'SENT'
        notification['sent_at'] = datetime.now().isoformat()
    
    def _send_websocket(self, notification):
        """Broadcast to WebSocket subscribers"""
        
        # In Flask, this will be called from the notification endpoint
        # Each subscriber gets: {type: 'alert', data: {...}, timestamp: ...}
        
        message = {
            'type': 'alert',
            'data': notification,
            'timestamp': datetime.now().isoformat(),
            'severity_color': {
                'CRITICAL': 'red',
                'HIGH': 'orange',
                'MEDIUM': 'yellow',
                'LOW': 'green'
            }.get(notification['severity'], 'blue')
        }
        
        # Store for broadcast to all connected clients
        # (Implementation in Flask route)
        notification['channels_sent'].append('websocket')
        
        return message
    
    def _send_email(self, notification):
        """Send email notification"""
        
        try:
            # Build email
            msg = MIMEMultipart()
            msg['Subject'] = f"[{notification['severity']}] DeepSentinel Alert: {notification['message']}"
            msg['From'] = self.config.get('from_email', 'deepsentinel@deepsec.ai')
            msg['To'] = self._get_recipient_email(notification['user_id'])
            
            # HTML body
            severity_color = {
                'CRITICAL': '#d32f2f',
                'HIGH': '#f57c00',
                'MEDIUM': '#fbc02d',
                'LOW': '#388e3c'
            }.get(notification['severity'], '#1976d2')
            
            html = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .alert-card {{
                        border-left: 5px solid {severity_color};
                        padding: 15px;
                        margin: 10px 0;
                        background: #f5f5f5;
                    }}
                    .severity {{ color: {severity_color}; font-weight: bold; }}
                </style>
            </head>
            <body>
                <h2>DeepSentinel Alert</h2>
                <div class="alert-card">
                    <p><strong>Severity:</strong> <span class="severity">{notification['severity']}</span></p>
                    <p><strong>Alert Type:</strong> {notification['alert_type']}</p>
                    <p><strong>User:</strong> {notification['user_id']}</p>
                    <p><strong>Time:</strong> {notification['timestamp']}</p>
                    <p><strong>Message:</strong> {notification['message']}</p>
                </div>
                <p><a href="http://localhost:5000/dashboard">View in Dashboard</a></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            # Send via SMTP
            server = smtplib.SMTP(
                self.config.get('smtp_server', 'localhost'),
                self.config.get('smtp_port', 25)
            )
            
            server.send_message(msg)
            server.quit()
            
            notification['channels_sent'].append('email')
            return True
            
        except Exception as e:
            print(f"Email notification failed: {e}")
            return False
    
    def _send_slack(self, notification):
        """Send Slack webhook notification"""
        
        try:
            import requests
            
            webhook_url = self.config.get('slack_webhook')
            if not webhook_url:
                return False
            
            severity_color = {
                'CRITICAL': 'danger',
                'HIGH': 'warning',
                'MEDIUM': '#ff6600',
                'LOW': 'good'
            }.get(notification['severity'], '#0099ff')
            
            payload = {
                'attachments': [{
                    'fallback': notification['message'],
                    'color': severity_color,
                    'title': f"{notification['severity']} - {notification['alert_type']}",
                    'text': notification['message'],
                    'fields': [
                        {'title': 'User', 'value': notification['user_id'], 'short': True},
                        {'title': 'Alert ID', 'value': notification['alert_id'], 'short': True},
                        {'title': 'Time', 'value': notification['timestamp'], 'short': False}
                    ],
                    'actions': [
                        {
                            'type': 'button',
                            'text': 'View in Dashboard',
                            'url': 'http://localhost:5000/dashboard'
                        }
                    ]
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                notification['channels_sent'].append('slack')
                return True
            
        except Exception as e:
            print(f"Slack notification failed: {e}")
        
        return False
    
    def _get_recipient_email(self, user_id):
        """Get email address for user"""
        # Load from user database or config
        # For now, return a placeholder
        return f"{user_id}@deepsec.ai"
    
    def _log_notification(self, notification):
        """Log sent notification for audit"""
        try:
            with open(self.notif_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(notification) + '\n')
        except:
            pass
    
    def subscribe_websocket(self, client_id, send_func):
        """Register WebSocket subscriber"""
        self.websocket_subscribers.append({
            'id': client_id,
            'send': send_func,
            'subscribed_at': datetime.now()
        })
    
    def unsubscribe_websocket(self, client_id):
        """Remove WebSocket subscriber"""
        self.websocket_subscribers = [
            s for s in self.websocket_subscribers if s['id'] != client_id
        ]
    
    def broadcast_websocket(self, message):
        """Broadcast message to all WebSocket subscribers"""
        for subscriber in self.websocket_subscribers:
            try:
                subscriber['send'](json.dumps(message))
            except:
                pass
    
    def get_notification_history(self, user_id=None, limit=100):
        """Get notification history"""
        history = []
        
        try:
            with open(self.notif_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            notif = json.loads(line)
                            if user_id is None or notif.get('user_id') == user_id:
                                history.append(notif)
                        except:
                            pass
        except:
            pass
        
        # Sort by timestamp descending
        history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return history[:limit]
    
    def configure_smtp(self, server, port, from_email):
        """Configure SMTP settings"""
        self.config['smtp_server'] = server
        self.config['smtp_port'] = port
        self.config['from_email'] = from_email
        
        # Persist
        return self.config
    
    def configure_slack(self, webhook_url):
        """Configure Slack webhook"""
        self.config['slack_webhook'] = webhook_url
        self.config['slack_enabled'] = True if webhook_url else False
        
        return self.config
    
    def set_min_severity(self, severity):
        """Set minimum severity to send notifications"""
        valid = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        if severity in valid:
            self.config['min_severity'] = severity
        
        return self.config
