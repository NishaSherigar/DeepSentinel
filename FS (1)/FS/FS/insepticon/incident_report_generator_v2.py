"""
LLM-Powered Incident Investigation & User Behavior Report Generator
FIXED VERSION - Handles all user/agent formats and produces professional reports

FIXES IN THIS VERSION:
- Matches users by: username, user, User, AND agent_id (for DESKTOP-HOST-001 type users)
- Proper timestamp extraction and display
- Real data extraction with proper null handling
- Professional PDF formatting with colors and structure
- Accurate timeline presentation
- Correct risk calculations
- Empty behavior reports fixed
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import google.generativeai as genai
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, grey, black, red, orange, yellow, green
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether
from reportlab.pdfgen import canvas

# Configuration
REPORTS_DIR = Path("data/reports")
REPORTS_DIR.mkdir(exist_ok=True)

# Initialize Gemini API from environment. Never commit API keys.
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)


def get_gemini_model():
    if not GEMINI_API_KEY:
        return None
    return genai.GenerativeModel('gemini-1.5-flash')

class IncidentReportGeneratorV2:
    """Generates detailed incident investigation reports using REAL DATA and LLM"""
    
    def __init__(self, events_log):
        """Initialize with events log"""
        self.events_log = events_log or []
        self.model = get_gemini_model()
        
    def parse_timestamp(self, ts_str):
        """Parse timestamp in multiple formats"""
        if not ts_str:
            return None
        try:
            if ' ' in str(ts_str):
                return datetime.strptime(str(ts_str), "%Y-%m-%d %H:%M:%S")
            return datetime.fromisoformat(str(ts_str).replace('Z', '+00:00'))
        except:
            return None
    
    def match_user(self, event, username):
        """Check if event matches the user - handles all formats"""
        # Direct matches
        if event.get('username') == username:
            return True
        if event.get('user') == username:
            return True
        if event.get('User') == username:
            return True
        if event.get('agent_id') == username:
            return True
        
        # Case-insensitive
        if str(event.get('username', '')).strip().lower() == username.lower():
            return True
        if str(event.get('user', '')).strip().lower() == username.lower():
            return True
        if str(event.get('agent_id', '')).strip().lower() == username.lower():
            return True
        
        return False
    
    def get_user_baseline(self, username, days=30):
        """Calculate user's normal behavior baseline - supports all user types"""
        
        # Get ALL events matching this user (username, user, or agent_id)
        user_events = [e for e in self.events_log if self.match_user(e, username)]
        
        if not user_events:
            return {
                'total_events': 0,
                'avg_daily_events': 0,
                'working_hours_percentage': 0,
                'off_hours_percentage': 0,
                'has_file_events': False,
                'has_usb_events': False,
            }
        
        # Use the data's own time range
        timestamps = [self.parse_timestamp(e.get('timestamp')) for e in user_events if self.parse_timestamp(e.get('timestamp'))]
        
        if timestamps:
            timestamps.sort()
            latest_ts = timestamps[-1]
            cutoff_time = latest_ts - timedelta(days=days)
            user_events = [e for e in user_events 
                          if (ts := self.parse_timestamp(e.get('timestamp'))) and cutoff_time <= ts <= latest_ts]
        
        # Calculate metrics
        hours = []
        for event in user_events:
            ts = self.parse_timestamp(event.get('timestamp'))
            if ts:
                hours.append(ts.hour)
        
        working_hours = len([h for h in hours if 9 <= h < 18]) if hours else 0
        off_hours = len([h for h in hours if h < 9 or h >= 18]) if hours else 0
        total_hours = len(hours) if hours else 1
        
        return {
            'total_events': len(user_events),
            'avg_daily_events': len(user_events) / max(1, days),
            'working_hours_percentage': (working_hours / max(1, total_hours)) * 100,
            'off_hours_percentage': (off_hours / max(1, total_hours)) * 100,
            'has_file_events': any(e.get('event_type') == 'file' for e in user_events),
            'has_usb_events': any(e.get('event_type') == 'usb' for e in user_events),
        }
    
    def calculate_risk_score(self, username, incident_data, baseline):
        """Calculate risk score based on detected anomalies"""
        
        risk_score = 1.0  # Start at baseline low
        risk_factors = []
        
        events = incident_data.get('events', [])
        if not events:
            return risk_score, risk_factors
        
        # Factor 1: Off-hours access
        off_hours_events = [e for e in events if self.parse_timestamp(e.get('timestamp')) and self.parse_timestamp(e.get('timestamp')).hour not in range(9, 18)]
        if off_hours_events:
            risk_score += 1.5
            risk_factors.append(f"Off-hours access detected ({len(off_hours_events)} events outside 9 AM - 5 PM)")
        
        # Factor 2: USB usage
        usb_events = [e for e in events if e.get('event_type') == 'usb']
        if usb_events:
            if not baseline.get('has_usb_events'):
                risk_score += 2.0
                risk_factors.append(f"First-time USB device usage detected ({len(usb_events)} USB events)")
            else:
                risk_score += 0.8
                risk_factors.append(f"USB transfers detected ({len(usb_events)} events)")
        
        # Factor 3: Large file transfers
        file_events = [e for e in events if e.get('event_type') == 'file']
        large_files = []
        for fe in file_events:
            try:
                size_str = str(fe.get('size', '0'))
                if 'MB' in size_str:
                    size_mb = float(size_str.replace('MB', '').strip())
                    if size_mb > 10:
                        large_files.append(fe)
                else:
                    size_bytes = int(size_str.split()[0]) if size_str and ' ' in size_str else 0
                    if size_bytes > 10485760:  # 10 MB
                        large_files.append(fe)
            except:
                pass
        
        if large_files:
            risk_score += min(1.8, 0.2 * len(large_files))
            risk_factors.append(f"Large file transfers detected ({len(large_files)} files >10MB)")
        
        # Factor 4: Data volume anomaly
        if baseline.get('avg_daily_events') > 0:
            current_events = len(events)
            baseline_events = baseline.get('avg_daily_events', 1)
            if current_events > baseline_events * 3:
                risk_score += 1.3
                risk_factors.append(f"Abnormal data volume ({current_events} vs typical {int(baseline_events)}/day)")
        
        # Factor 5: Rapid activity pattern
        if len(events) > 1:
            timestamps = []
            for e in events:
                ts = self.parse_timestamp(e.get('timestamp'))
                if ts:
                    timestamps.append(ts)
            
            if timestamps:
                timestamps.sort()
                time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 60
                if time_span > 0 and time_span < 60 and len(timestamps) > 5:
                    events_per_min = len(timestamps) / time_span
                    if events_per_min > 1:
                        risk_score += 1.2
                        risk_factors.append(f"Rapid activity pattern ({int(events_per_min)} events/min)")
        
        # Cap score
        risk_score = min(10.0, max(1.0, risk_score))
        
        return risk_score, risk_factors
    
    def collect_incident_data(self, username, hours_lookback=24):
        """Collect REAL and DETAILED incident data for a user"""
        
        # Get ALL events for this user
        user_events = [e for e in self.events_log if self.match_user(e, username)]
        
        if not user_events:
            return {
                'username': username,
                'events': [],
                'total_events': 0,
                'file_count': 0,
                'usb_count': 0,
                'process_count': 0,
            }
        
        # Find time window based on data itself
        timestamps = []
        for e in user_events:
            ts = self.parse_timestamp(e.get('timestamp'))
            if ts:
                timestamps.append((ts, e))
        
        if not timestamps:
            return {
                'username': username,
                'events': [],
                'total_events': 0,
                'file_count': 0,
                'usb_count': 0,
                'process_count': 0,
            }
        
        timestamps.sort(key=lambda x: x[0])
        latest_ts = timestamps[-1][0]
        cutoff_ts = latest_ts - timedelta(hours=hours_lookback)
        
        # Get events in this window
        incident_events = [e for ts, e in timestamps if cutoff_ts <= ts <= latest_ts]
        
        # Count types
        file_count = len([e for e in incident_events if e.get('event_type') == 'file'])
        usb_count = len([e for e in incident_events if e.get('event_type') == 'usb'])
        process_count = len([e for e in incident_events if e.get('event_type') == 'process'])
        
        return {
            'username': username,
            'events': incident_events,
            'total_events': len(incident_events),
            'file_count': file_count,
            'usb_count': usb_count,
            'process_count': process_count,
            'latest_timestamp': latest_ts,
            'earliest_timestamp': cutoff_ts,
        }
    
    def generate_llm_incident_analysis(self, incident_data, risk_score, risk_factors):
        """Generate LLM analysis with REAL DATA"""
        
        events = incident_data.get('events', [])
        username = incident_data.get('username', 'Unknown')
        
        # Create event summary
        event_summary = f"""
Events for user {username}:
- Total events: {len(events)}
- File events: {incident_data.get('file_count', 0)}
- USB events: {incident_data.get('usb_count', 0)}
- Process events: {incident_data.get('process_count', 0)}

Detected Risk Factors:
{chr(10).join('- ' + str(rf) for rf in risk_factors)}

Timeline (recent events):
"""
        
        # Add event details
        for i, e in enumerate(events[-20:]):  # Last 20 events
            ts = e.get('timestamp', 'Unknown time')
            et = e.get('event_type', 'unknown')
            action = e.get('action', '')
            target = e.get('target', '')
            event_summary += f"\n  {i+1}. [{ts}] {et} - {action} {target}".strip()
        
        prompt = f"""Analyze this security incident:

User: {username}
Risk Score: {risk_score}/10
Analysis Period: Last 24 hours

{event_summary}

Provide a brief professional analysis covering:
1. INCIDENT SUMMARY - What happened
2. RISK ASSESSMENT - Why this is a threat
3. RECOMMENDED ACTIONS - What to do next

Keep response concise and professional."""
        
        try:
            if not self.model:
                raise RuntimeError("GEMINI_API_KEY is not configured")
            response = self.model.generate_content(prompt)
            return response.text if response else "Unable to generate analysis"
        except Exception as e:
            return f"LLM Analysis: Risk score {risk_score}/10 based on detected anomalies: {', '.join(risk_factors)}"
    
    def generate_incident_pdf(self, username, event_types=None, output_filename=None):
        """Generate incident PDF with automatic risk scoring - COMPLETELY REWRITTEN"""
        
        try:
            # Get baseline
            baseline = self.get_user_baseline(username)
            
            # Collect incident data
            incident_data = self.collect_incident_data(username)
            
            if not incident_data.get('events'):
                return {
                    'error': f'No events found for user {username}',
                    'success': False
                }
            
            # Calculate risk
            risk_score, risk_factors = self.calculate_risk_score(username, incident_data, baseline)
            
            # Get LLM analysis
            llm_analysis = self.generate_llm_incident_analysis(incident_data, risk_score, risk_factors)
            
            # Generate PDF
            if not output_filename:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                output_filename = f"incident_{username}_{timestamp}.pdf"
            
            output_path = REPORTS_DIR / output_filename
            
            # Create PDF
            doc = SimpleDocTemplate(str(output_path), pagesize=letter,
                                   topMargin=0.5*inch, bottomMargin=0.5*inch,
                                   leftMargin=0.75*inch, rightMargin=0.75*inch)
            
            # Styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=HexColor('#1a1a2e'),
                spaceAfter=6,
                alignment=1
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=HexColor('#0f3460'),
                spaceAfter=8,
                spaceBefore=10,
                borderColor=HexColor('#e94560'),
                borderWidth=2,
                borderPadding=5
            )
            
            # Get risk color
            if risk_score >= 8:
                risk_color = '#d32f2f'  # Red - CRITICAL
                status = "CRITICAL"
            elif risk_score >= 6:
                risk_color = '#f57c00'  # Orange - HIGH
                status = "HIGH"
            elif risk_score >= 4:
                risk_color = '#fbc02d'  # Yellow - MEDIUM
                status = "MEDIUM"
            else:
                risk_color = '#388e3c'  # Green - LOW
                status = "LOW"
            
            # Build PDF content
            story = []
            
            # Header
            story.append(Paragraph("DEEPSENTINEL INCIDENT REPORT", title_style))
            story.append(Paragraph("AI-Powered Security Investigation", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Report info
            report_data = [
                ['Report ID:', f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"],
                ['User:', username],
                ['Generated:', datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
                ['Period:', f"{incident_data.get('earliest_timestamp', 'N/A')} to {incident_data.get('latest_timestamp', 'N/A')}"]
            ]
            report_table = Table(report_data, colWidths=[1.5*inch, 3.5*inch])
            report_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#e3f2fd')),
                ('TEXTCOLOR', (0, 0), (-1, -1), black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cccccc')),
            ]))
            story.append(report_table)
            story.append(Spacer(1, 0.15*inch))
            
            # Risk Score Section
            risk_data = [
                ['RISK SCORE', f"{risk_score:.1f}/10"],
                ['STATUS', status],
            ]
            risk_table = Table(risk_data, colWidths=[1.5*inch, 3.5*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#fff3e0')),
                ('BACKGROUND', (1, 0), (1, 0), HexColor(risk_color)),
                ('TEXTCOLOR', (1, 0), (1, 0), 'white'),
                ('TEXTCOLOR', (0, 0), (-1, -1), black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('PADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cccccc')),
            ]))
            story.append(risk_table)
            story.append(Spacer(1, 0.15*inch))
            
            # Risk Factors
            story.append(Paragraph("RISK FACTORS DETECTED", heading_style))
            if risk_factors:
                for i, factor in enumerate(risk_factors, 1):
                    story.append(Paragraph(f"• {factor}", styles['Normal']))
            else:
                story.append(Paragraph("• No specific risk factors detected", styles['Normal']))
            story.append(Spacer(1, 0.15*inch))
            
            # Event Summary
            story.append(Paragraph("EVENT SUMMARY (24-HOUR INCIDENT WINDOW)", heading_style))
            summary_data = [
                ['Total Events', str(incident_data.get('total_events', 0))],
                ['File Events', str(incident_data.get('file_count', 0))],
                ['USB Events', str(incident_data.get('usb_count', 0))],
                ['Process Events', str(incident_data.get('process_count', 0))],
            ]
            summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#f5f5f5')),
                ('TEXTCOLOR', (0, 0), (-1, -1), black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dddddd')),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.15*inch))
            
            # Timeline
            story.append(Paragraph("INCIDENT TIMELINE (Last 20 Events)", heading_style))
            timeline_events = incident_data.get('events', [])[-20:]
            if timeline_events:
                for i, event in enumerate(timeline_events, 1):
                    ts = event.get('timestamp', 'Unknown')
                    et = event.get('event_type', 'unknown').upper()
                    action = event.get('action', '').upper()
                    target = event.get('target', event.get('drive', event.get('path', 'N/A')))
                    
                    timeline_text = f"{i}. [{ts}] <b>{et}</b> - {action} {target}"
                    story.append(Paragraph(timeline_text, styles['Normal']))
            else:
                story.append(Paragraph("No events in incident window", styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
            story.append(PageBreak())
            
            # LLM Analysis
            story.append(Paragraph("AI ANALYSIS & RECOMMENDATIONS", heading_style))
            story.append(Paragraph(llm_analysis, styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Footer
            story.append(Paragraph("_" * 80, styles['Normal']))
            story.append(Paragraph("Report generated by DeepSentinel AI Security System | CONFIDENTIAL - FOR SECURITY TEAM ONLY", 
                                  ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=grey, alignment=2)))
            
            # Build PDF
            doc.build(story)
            
            return {
                'success': True,
                'filename': output_filename,
                'path': str(output_path),
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'events_analyzed': incident_data.get('total_events', 0)
            }
        
        except Exception as e:
            import traceback
            print(f"PDF generation error: {e}")
            traceback.print_exc()
            return {
                'error': str(e),
                'success': False
            }


class UserBehaviorReportGenerator:
    """Generates 30-day user behavior analysis reports"""
    
    def __init__(self, events_log):
        self.events_log = events_log or []
        self.model = get_gemini_model()
    
    def parse_timestamp(self, ts_str):
        if not ts_str:
            return None
        try:
            if ' ' in str(ts_str):
                return datetime.strptime(str(ts_str), "%Y-%m-%d %H:%M:%S")
            return datetime.fromisoformat(str(ts_str).replace('Z', '+00:00'))
        except:
            return None
    
    def match_user(self, event, username):
        """Check if event matches user - handles all formats"""
        if event.get('username') == username or event.get('user') == username or event.get('User') == username or event.get('agent_id') == username:
            return True
        if str(event.get('username', '')).strip().lower() == username.lower():
            return True
        if str(event.get('user', '')).strip().lower() == username.lower():
            return True
        if str(event.get('agent_id', '')).strip().lower() == username.lower():
            return True
        return False
    
    def generate_behavior_pdf(self, username, output_filename=None):
        """Generate 30-day behavior report"""
        
        try:
            # Get 30-day events
            user_events = [e for e in self.events_log if self.match_user(e, username)]
            
            if not user_events:
                return {
                    'error': f'No events found for user {username}',
                    'success': False
                }
            
            # Filter to 30-day window
            timestamps = []
            for e in user_events:
                ts = self.parse_timestamp(e.get('timestamp'))
                if ts:
                    timestamps.append((ts, e))
            
            if not timestamps:
                return {'error': 'No valid timestamps found', 'success': False}
            
            timestamps.sort(key=lambda x: x[0])
            latest_ts = timestamps[-1][0]
            cutoff_ts = latest_ts - timedelta(days=30)
            
            behavior_events = [e for ts, e in timestamps if cutoff_ts <= ts <= latest_ts]
            
            if not behavior_events:
                return {'error': 'No events in 30-day window', 'success': False}
            
            # Generate filename
            if not output_filename:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                output_filename = f"behavior_{username}_{timestamp}.pdf"
            
            output_path = REPORTS_DIR / output_filename
            
            # Create PDF
            doc = SimpleDocTemplate(str(output_path), pagesize=letter,
                                   topMargin=0.5*inch, bottomMargin=0.5*inch,
                                   leftMargin=0.75*inch, rightMargin=0.75*inch)
            
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=HexColor('#1a1a2e'),
                spaceAfter=6,
                alignment=1
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=HexColor('#0f3460'),
                spaceAfter=8,
                spaceBefore=10,
                borderColor=HexColor('#e94560'),
                borderWidth=2,
                borderPadding=5
            )
            
            # Build story
            story = []
            
            story.append(Paragraph("30-DAY USER BEHAVIOR REPORT", title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Report info
            report_data = [
                ['User:', username],
                ['Analysis Period:', '30 days'],
                ['Generated:', datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
                ['Total Events:', str(len(behavior_events))],
            ]
            report_table = Table(report_data, colWidths=[1.5*inch, 3.5*inch])
            report_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#e3f2fd')),
                ('TEXTCOLOR', (0, 0), (-1, -1), black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cccccc')),
            ]))
            story.append(report_table)
            story.append(Spacer(1, 0.2*inch))
            
            # Event type summary
            story.append(Paragraph("EVENT TYPE SUMMARY", heading_style))
            type_counter = Counter(e.get('event_type') for e in behavior_events)
            summary_data = [['Event Type', 'Count']]
            for et, count in type_counter.most_common(10):
                summary_data.append([str(et).upper(), str(count)])
            
            summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f3460')),
                ('TEXTCOLOR', (0, 0), (-1, 0), 'white'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f5f5f5'), 'white']),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cccccc')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.2*inch))
            
            # Behavior analysis
            story.append(Paragraph("BEHAVIORAL INSIGHTS", heading_style))
            
            hours = []
            for e in behavior_events:
                ts = self.parse_timestamp(e.get('timestamp'))
                if ts:
                    hours.append(ts.hour)
            
            working_hours = len([h for h in hours if 9 <= h < 18]) if hours else 0
            off_hours = len([h for h in hours if h < 9 or h >= 18]) if hours else 0
            total = len(hours) if hours else 1
            
            story.append(Paragraph(f"<b>Working Hours Activity:</b> {(working_hours/total)*100:.1f}% of events", styles['Normal']))
            story.append(Paragraph(f"<b>Off-Hours Activity:</b> {(off_hours/total)*100:.1f}% of events", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            # Recent events
            story.append(Paragraph("RECENT ACTIVITY (Last 20 Events)", heading_style))
            for i, e in enumerate(behavior_events[-20:], 1):
                ts = e.get('timestamp', 'Unknown')
                et = e.get('event_type', 'unknown').upper()
                action = e.get('action', '')
                story.append(Paragraph(f"{i}. [{ts}] {et} - {action}", styles['Normal']))
            
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph("_" * 80, styles['Normal']))
            story.append(Paragraph("Report generated by DeepSentinel AI Security System | CONFIDENTIAL", 
                                  ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=grey, alignment=2)))
            
            doc.build(story)
            
            return {
                'success': True,
                'filename': output_filename,
                'path': str(output_path),
                'events_analyzed': len(behavior_events)
            }
        
        except Exception as e:
            import traceback
            print(f"Behavior PDF error: {e}")
            traceback.print_exc()
            return {
                'error': str(e),
                'success': False
            }
    
    def generate_behavior_report_pdf(self, username, output_filename=None):
        """Alias for generate_behavior_pdf - matches server.py expectations"""
        return self.generate_behavior_pdf(username, output_filename)
