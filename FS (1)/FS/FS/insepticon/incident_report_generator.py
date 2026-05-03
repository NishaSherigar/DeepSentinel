"""
LLM-Powered Incident Investigation & User Behavior Report Generator
Generates professional PDF reports using AI analysis of security events
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
from reportlab.lib.colors import HexColor, grey, black, red
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.pdfgen import canvas
import textwrap

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

class IncidentReportGenerator:
    """Generates detailed incident investigation reports using LLM"""
    
    def __init__(self, events_log):
        """
        Initialize with events log
        Args:
            events_log: List of event dictionaries
        """
        self.events_log = events_log
        self.model = get_gemini_model()
        
    def parse_timestamp(self, ts_str):
        """Parse timestamp in multiple formats"""
        if not ts_str:
            return None
        try:
            # Try space-separated format (2025-10-26 12:00:55)
            if ' ' in ts_str:
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            # Try ISO format
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except:
            return None
    
    def collect_incident_data(self, username, hours_lookback=24):
        """
        Collect all incident data for a user
        
        Args:
            username: Username to investigate
            hours_lookback: How many hours to look back for events
            
        Returns:
            Dictionary with organized incident data
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_lookback)
        user_events = []
        
        for event in self.events_log:
            if event.get('username') == username or event.get('user') == username:
                ts = self.parse_timestamp(event.get('timestamp'))
                if ts and ts >= cutoff_time:
                    user_events.append(event)
        
        # Sort by timestamp
        user_events.sort(key=lambda x: self.parse_timestamp(x.get('timestamp')) or datetime.min)
        
        # Aggregate data
        file_actions = [e for e in user_events if e.get('event_type') == 'file']
        usb_actions = [e for e in user_events if e.get('event_type') == 'usb']
        email_actions = [e for e in user_events if e.get('event_type') in ['outlook', 'imap']]
        process_actions = [e for e in user_events if e.get('event_type') == 'process']
        logon_actions = [e for e in user_events if e.get('event_type') == 'logon']
        
        # Calculate risk indicators
        has_usb = len(usb_actions) > 0
        has_off_hours = any(self.parse_timestamp(e.get('timestamp')).hour not in range(9, 18) 
                           for e in user_events 
                           if self.parse_timestamp(e.get('timestamp')))
        has_external_emails = any('external' in str(e.get('target', '')).lower() or 
                                  '@' in str(e.get('target', ''))
                                  for e in email_actions)
        
        return {
            'username': username,
            'incident_time': datetime.utcnow().isoformat(),
            'total_events': len(user_events),
            'file_actions': len(file_actions),
            'usb_actions': len(usb_actions),
            'email_actions': len(email_actions),
            'recent_events': user_events[-20:],  # Last 20 events
            'files_accessed': [e.get('target', 'Unknown') for e in file_actions][:15],
            'usb_devices': [e.get('target', 'Unknown USB') for e in usb_actions],
            'emails_sent': [e.get('target', 'Unknown') for e in email_actions][:10],
            'risk_indicators': {
                'usb_activity': has_usb,
                'off_hours_access': has_off_hours,
                'external_communication': has_external_emails
            },
            'event_summary': {
                'files': len(file_actions),
                'usb_transfers': len(usb_actions),
                'emails': len(email_actions),
                'processes': len(process_actions),
                'logons': len(logon_actions)
            }
        }
    
    def generate_llm_incident_analysis(self, incident_data, risk_score=8.5):
        """
        Use Gemini to generate professional incident analysis
        
        Args:
            incident_data: Dictionary with incident information
            risk_score: Calculated risk score (0-10)
            
        Returns:
            Dictionary with LLM-generated report sections
        """
        
        prompt = f"""You are DeepSentinel AI, a professional security incident investigator.

Generate a detailed incident investigation report for the following incident:

USER: {incident_data['username']}
INCIDENT TIME: {incident_data['incident_time']}
RISK SCORE: {risk_score:.1f}/10

INCIDENT SUMMARY:
- Total events in 24 hours: {incident_data['total_events']}
- Files accessed: {incident_data['event_summary']['files']}
- USB transfers: {incident_data['event_summary']['usb_transfers']}
- Emails sent: {incident_data['event_summary']['emails']}
- Processes executed: {incident_data['event_summary']['processes']}
- Login events: {incident_data['event_summary']['logons']}

RISK INDICATORS DETECTED:
- USB Activity: {incident_data['risk_indicators']['usb_activity']}
- Off-hours access: {incident_data['risk_indicators']['off_hours_access']}
- External communication: {incident_data['risk_indicators']['external_communication']}

FILES ACCESSED:
{chr(10).join(f"  • {f}" for f in incident_data['files_accessed'][:10])}

USB DEVICES:
{chr(10).join(f"  • {d}" for d in incident_data['usb_devices'][:5]) if incident_data['usb_devices'] else "  None detected"}

EXTERNAL EMAILS:
{chr(10).join(f"  • {e}" for e in incident_data['emails_sent'][:5]) if incident_data['emails_sent'] else "  None detected"}

Please generate a comprehensive incident investigation report with the following sections:

1. INCIDENT SUMMARY (2-3 sentences explaining what appears to have happened)
2. TIMELINE (Bullet points of suspicious events in chronological order)
3. DATA IMPACT (What files/systems were affected and why this is concerning)
4. RISK ASSESSMENT (Detailed analysis of why this is high-risk - behavioral anomalies, policy violations, etc.)
5. IMMEDIATE ACTIONS (Critical steps to take now, within 1 hour)
6. SHORT-TERM ACTIONS (Actions within next 3-8 hours)
7. LONG-TERM REMEDIATION (Systemic changes to prevent recurrence)

Format the response as a JSON object with these exact keys:
{{
    "summary": "string: 2-3 sentences",
    "timeline": ["string: event1", "string: event2", ...],
    "data_impact": "string: detailed explanation",
    "risk_assessment": "string: detailed analysis",
    "immediate_actions": ["action1", "action2", ...],
    "short_term_actions": ["action1", "action2", ...],
    "long_term_remediation": ["action1", "action2", ...]
}}

Ensure each section is detailed and professional. Use technical security terminology."""

        try:
            if not self.model:
                raise RuntimeError("GEMINI_API_KEY is not configured")
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.7,
                    max_output_tokens=2000
                )
            )
            
            # Extract JSON from response
            response_text = response.text
            
            # Try to parse JSON
            try:
                # Find JSON in response
                start_idx = response_text.find('{')
                end_idx = response_text.rfind('}') + 1
                if start_idx != -1 and end_idx > start_idx:
                    json_str = response_text[start_idx:end_idx]
                    return json.loads(json_str)
            except:
                pass
            
            # Fallback to structured response
            return {
                'summary': response_text[:500],
                'timeline': [response_text[:300]],
                'data_impact': 'Multiple files accessed and USB transfers detected',
                'risk_assessment': 'High-risk indicators present including off-hours access and USB activity',
                'immediate_actions': ['Revoke user sessions', 'Preserve evidence', 'Alert security team'],
                'short_term_actions': ['Conduct user interview', 'Review file logs', 'Check USB contents'],
                'long_term_remediation': ['Implement USB restrictions', 'Deploy DLP', 'Review access controls']
            }
            
        except Exception as e:
            print(f"LLM Error: {e}")
            return {
                'summary': f'Incident detected for {incident_data["username"]}',
                'timeline': ['Multiple suspicious events detected'],
                'data_impact': f'{incident_data["event_summary"]["files"]} files accessed',
                'risk_assessment': 'Manual investigation required',
                'immediate_actions': ['Alert security team', 'Preserve logs'],
                'short_term_actions': ['Investigate user', 'Review files'],
                'long_term_remediation': ['Enhance monitoring']
            }
    
    def generate_incident_pdf(self, username, risk_score=8.5, output_filename=None):
        """
        Generate full incident report PDF
        
        Args:
            username: User to investigate
            risk_score: Risk score (0-10)
            output_filename: Optional output filename
            
        Returns:
            Path to generated PDF
        """
        
        # Collect data
        incident_data = self.collect_incident_data(username)
        
        # Get LLM analysis
        analysis = self.generate_llm_incident_analysis(incident_data, risk_score)
        
        # Generate PDF
        if not output_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"incident_{username}_{timestamp}.pdf"
        
        output_path = REPORTS_DIR / output_filename
        
        # Create PDF document
        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#60a5fa'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#1F2937'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        # Add content
        story.append(Paragraph("DEEPSENTINEL INCIDENT REPORT", title_style))
        story.append(Spacer(1, 12))
        
        # Report info
        info_data = [
            ['Report ID', f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"],
            ['User', username],
            ['Risk Score', f"{risk_score:.1f}/10"],
            ['Generated', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Total Events (24h)', str(incident_data['total_events'])]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#F3F4F6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#E5E7EB'))
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 20))
        
        # Summary section
        story.append(Paragraph("INCIDENT SUMMARY", heading_style))
        story.append(Paragraph(analysis.get('summary', 'N/A'), styles['BodyText']))
        story.append(Spacer(1, 12))
        
        # Data impact
        story.append(Paragraph("DATA IMPACT", heading_style))
        story.append(Paragraph(
            f"<b>Files Accessed:</b> {incident_data['event_summary']['files']}<br/>"
            f"<b>USB Transfers:</b> {incident_data['event_summary']['usb_transfers']}<br/>"
            f"<b>External Emails:</b> {incident_data['event_summary']['emails']}<br/>",
            styles['BodyText']
        ))
        if incident_data['files_accessed']:
            story.append(Paragraph("<b>Affected Files:</b>", styles['Normal']))
            story.append(Paragraph(
                "<br/>".join([f"• {f}" for f in incident_data['files_accessed'][:5]]),
                styles['BodyText']
            ))
        story.append(Spacer(1, 12))
        
        # Risk assessment
        story.append(Paragraph("RISK ASSESSMENT", heading_style))
        story.append(Paragraph(analysis.get('risk_assessment', 'N/A'), styles['BodyText']))
        story.append(Spacer(1, 12))
        
        # Add page break for actions
        story.append(PageBreak())
        
        # Immediate actions
        story.append(Paragraph("IMMEDIATE ACTIONS (Within 1 Hour)", heading_style))
        for action in analysis.get('immediate_actions', [])[:5]:
            story.append(Paragraph(f"☐ {action}", styles['BodyText']))
        story.append(Spacer(1, 12))
        
        # Short-term actions
        story.append(Paragraph("SHORT-TERM ACTIONS (Next 3-8 Hours)", heading_style))
        for action in analysis.get('short_term_actions', [])[:5]:
            story.append(Paragraph(f"☐ {action}", styles['BodyText']))
        story.append(Spacer(1, 12))
        
        # Long-term actions
        story.append(Paragraph("LONG-TERM REMEDIATION", heading_style))
        for action in analysis.get('long_term_remediation', [])[:5]:
            story.append(Paragraph(f"☐ {action}", styles['BodyText']))
        story.append(Spacer(1, 20))
        
        # Timeline
        story.append(Paragraph("EVENT TIMELINE", heading_style))
        for i, event in enumerate(incident_data['recent_events'][-10:], 1):
            ts = self.parse_timestamp(event.get('timestamp'))
            time_str = ts.strftime("%H:%M:%S") if ts else "N/A"
            event_type = event.get('event_type', 'unknown')
            target = event.get('target', '')[:50]
            story.append(Paragraph(
                f"<b>{time_str}</b> - {event_type} | {target}",
                styles['BodyText']
            ))
        
        # Build PDF
        doc.build(story)
        
        return str(output_path)


class UserBehaviorReportGenerator:
    """Generates comprehensive user behavior analysis reports"""
    
    def __init__(self, events_log):
        self.events_log = events_log
        self.model = get_gemini_model()
    
    def parse_timestamp(self, ts_str):
        """Parse timestamp in multiple formats"""
        if not ts_str:
            return None
        try:
            if ' ' in ts_str:
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except:
            return None
    
    def collect_user_behavior_data(self, username, days=30):
        """
        Collect comprehensive behavioral data for a user
        
        Args:
            username: Username to analyze
            days: Days to look back
            
        Returns:
            Dictionary with behavior statistics
        """
        cutoff_time = datetime.utcnow() - timedelta(days=days)
        user_events = []
        
        for event in self.events_log:
            if event.get('username') == username or event.get('user') == username:
                ts = self.parse_timestamp(event.get('timestamp'))
                if ts and ts >= cutoff_time:
                    user_events.append(event)
        
        # Hourly distribution
        hourly_dist = Counter()
        for event in user_events:
            ts = self.parse_timestamp(event.get('timestamp'))
            if ts:
                hourly_dist[ts.hour] += 1
        
        # Working hours (9-17)
        working_hours_events = sum(count for hour, count in hourly_dist.items() if 9 <= hour < 18)
        off_hours_events = sum(count for hour, count in hourly_dist.items() if hour < 9 or hour >= 18)
        
        # Event type distribution
        event_types = Counter(e.get('event_type', 'unknown') for e in user_events)
        
        # File access patterns
        file_events = [e for e in user_events if e.get('event_type') == 'file']
        folders_accessed = set()
        for event in file_events:
            target = event.get('target', '')
            if '\\' in target:
                folder = target.rsplit('\\', 1)[0]
                folders_accessed.add(folder)
        
        return {
            'username': username,
            'total_events': len(user_events),
            'analysis_period_days': days,
            'event_summary': dict(event_types),
            'working_hours_events': working_hours_events,
            'off_hours_events': off_hours_events,
            'after_hours_percentage': (off_hours_events / len(user_events) * 100) if user_events else 0,
            'daily_average': len(user_events) / max(days, 1),
            'unique_folders': len(folders_accessed),
            'hourly_distribution': dict(hourly_dist),
            'recent_event_types': [e.get('event_type') for e in user_events[-20:]],
            'risky_indicators': {
                'high_file_access': event_types.get('file', 0) > 100,
                'unusual_hours': off_hours_events > 10,
                'usb_activity': event_types.get('usb', 0) > 2 if 'usb' in event_types else False,
                'process_execution': event_types.get('process', 0) > 50
            }
        }
    
    def generate_behavior_report_pdf(self, username, risk_score=3.5, output_filename=None):
        """
        Generate comprehensive user behavior report PDF
        
        Args:
            username: User to analyze
            risk_score: Current risk score
            output_filename: Optional output filename
            
        Returns:
            Path to generated PDF
        """
        
        # Collect data
        behavior_data = self.collect_user_behavior_data(username)
        
        # Generate PDF
        if not output_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"behavior_{username}_{timestamp}.pdf"
        
        output_path = REPORTS_DIR / output_filename
        
        # Create PDF
        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=HexColor('#60a5fa'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=HexColor('#1F2937'),
            spaceAfter=10,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        # Title
        story.append(Paragraph(f"USER BEHAVIOR REPORT - {username.upper()}", title_style))
        story.append(Spacer(1, 12))
        
        # Report metadata
        meta_data = [
            ['Report Date', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Analysis Period', f"{behavior_data['analysis_period_days']} days"],
            ['Total Events', str(behavior_data['total_events'])],
            ['Current Risk Score', f"{risk_score:.1f}/10"],
            ['Daily Average', f"{behavior_data['daily_average']:.1f} events/day"]
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#F3F4F6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#E5E7EB'))
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 16))
        
        # Activity summary
        story.append(Paragraph("ACTIVITY SUMMARY", heading_style))
        story.append(Paragraph(
            f"<b>Working Hours:</b> {behavior_data['working_hours_events']} events "
            f"({100 - behavior_data['after_hours_percentage']:.1f}%)<br/>"
            f"<b>Off-Hours:</b> {behavior_data['off_hours_events']} events "
            f"({behavior_data['after_hours_percentage']:.1f}%)<br/>"
            f"<b>Unique Folders Accessed:</b> {behavior_data['unique_folders']}<br/>",
            styles['BodyText']
        ))
        story.append(Spacer(1, 12))
        
        # Event breakdown
        story.append(Paragraph("EVENT TYPE BREAKDOWN", heading_style))
        event_summary_text = "<br/>".join([
            f"• <b>{etype}</b>: {count} events"
            for etype, count in sorted(behavior_data['event_summary'].items(), 
                                      key=lambda x: x[1], reverse=True)[:7]
        ])
        story.append(Paragraph(event_summary_text, styles['BodyText']))
        story.append(Spacer(1, 12))
        
        # Risk indicators
        story.append(Paragraph("RISK INDICATORS", heading_style))
        indicators_text = "<br/>".join([
            f"⚠️ {indicator.replace('_', ' ').title()}: {'Yes' if status else 'No'}"
            for indicator, status in behavior_data['risky_indicators'].items()
        ])
        story.append(Paragraph(indicators_text, styles['BodyText']))
        story.append(Spacer(1, 12))
        
        # Behavioral analysis
        story.append(PageBreak())
        story.append(Paragraph("BEHAVIORAL ANALYSIS", heading_style))
        
        analysis_text = f"""
User {username} shows the following behavioral patterns over the past {behavior_data['analysis_period_days']} days:

<b>Activity Level:</b> {behavior_data['daily_average']:.1f} events per day
<b>Work Pattern:</b> {'Primarily working hours' if behavior_data['after_hours_percentage'] < 10 else 'Significant after-hours activity'}
<b>File Access:</b> {behavior_data['event_summary'].get('file', 0)} file operations
<b>Process Execution:</b> {behavior_data['event_summary'].get('process', 0)} processes

<b>Risk Assessment:</b>
"""
        
        risk_factors = []
        if behavior_data['risky_indicators']['high_file_access']:
            risk_factors.append("High file access volume compared to baseline")
        if behavior_data['risky_indicators']['unusual_hours']:
            risk_factors.append("Unusual access patterns outside business hours")
        if behavior_data['risky_indicators']['usb_activity']:
            risk_factors.append("USB device activity detected")
        if behavior_data['risky_indicators']['process_execution']:
            risk_factors.append("Elevated process execution activity")
        
        if risk_factors:
            analysis_text += "<br/>".join([f"• {factor}" for factor in risk_factors])
        else:
            analysis_text += "Behavior appears normal and within expected parameters."
        
        story.append(Paragraph(analysis_text, styles['BodyText']))
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("RECOMMENDATIONS", heading_style))
        
        recommendations = [
            "Monitor for any deviations from established baseline",
            "Review any unusual access patterns",
            "Ensure all accessed resources are approved for this user",
            "Conduct periodic spot-check audits"
        ]
        
        if risk_score > 5:
            recommendations.insert(0, "URGENT: Schedule security review interview")
        
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"☐ {rec}", styles['BodyText']))
        
        # Build PDF
        doc.build(story)
        
        return str(output_path)


def generate_quick_incident_report(username, events_log, risk_score=8.5):
    """Quick function to generate incident report"""
    gen = IncidentReportGenerator(events_log)
    return gen.generate_incident_pdf(username, risk_score)


def generate_quick_behavior_report(username, events_log, risk_score=3.5):
    """Quick function to generate behavior report"""
    gen = UserBehaviorReportGenerator(events_log)
    return gen.generate_behavior_report_pdf(username, risk_score)
