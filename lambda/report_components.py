"""
WakimWorks HIPAA Compliance Report - Visual Components
Reusable rendering functions for report elements
"""

from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors as rl_colors
from report_styles import get_color_palette, get_typography_styles

def render_severity_badge(severity):
    """Renders a colored severity badge"""
    colors = get_color_palette()
    severity_upper = severity.upper()
    
    badge_color = colors.get(severity_upper, colors['GREY'])
    text_color = rl_colors.white if severity_upper in ['CRITICAL', 'HIGH', 'LOW', 'PASS'] else rl_colors.black
    
    badge_data = [[severity_upper]]
    badge_table = Table(badge_data, colWidths=[0.8*inch])
    badge_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), badge_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), text_color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('BOX', (0, 0), (-1, -1), 2, badge_color)
    ]))
    
    return badge_table

def render_metadata_table(data):
    """Renders report metadata table"""
    colors = get_color_palette()
    
    table = Table(data, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors['LIGHT_GREY']),
        ('TEXTCOLOR', (0, 0), (-1, -1), rl_colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, rl_colors.white)
    ]))
    
    return table

def render_summary_stats_table(stats):
    """Renders executive summary statistics table"""
    colors = get_color_palette()
    
    data = [
        ['Total Violations', 'Affected Buckets', 'HIPAA Controls'],
        [str(stats['total_violations']), str(stats['affected_resources']), 
         str(len([c for c in stats['hipaa_controls'].keys() if c != 'N/A']))]
    ]
    
    table = Table(data, colWidths=[2*inch, 2*inch, 2*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors['AWS_DARK_BLUE']),
        ('TEXTCOLOR', (0, 0), (-1, 0), rl_colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 20),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors['CRITICAL']),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, rl_colors.black),
        ('BOX', (0, 0), (-1, -1), 2, rl_colors.black)
    ]))
    
    return table

def render_risk_posture_card(risk_posture, compliance_score):
    """Renders risk posture and compliance score card"""
    colors = get_color_palette()
    styles = get_typography_styles()
    
    score_color = colors['PASS'] if compliance_score >= 90 else (
        colors['WARNING'] if compliance_score >= 70 else colors['CRITICAL']
    )
    
    data = [
        ['OVERALL RISK POSTURE', 'COMPLIANCE SCORE'],
        [risk_posture, f"{compliance_score}%"]
    ]
    
    table = Table(data, colWidths=[3*inch, 3*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors['AWS_DARK_BLUE']),
        ('TEXTCOLOR', (0, 0), (-1, 0), rl_colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('FONTSIZE', (0, 1), (-1, -1), 36),
        ('TEXTCOLOR', (0, 1), (0, 1), colors.get(risk_posture, colors['GREY'])),
        ('TEXTCOLOR', (1, 1), (1, 1), score_color),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('GRID', (0, 0), (-1, -1), 2, rl_colors.black),
        ('BOX', (0, 0), (-1, -1), 3, rl_colors.black)
    ]))
    
    return table

def render_issue_count_tiles(categorized):
    """Renders issue count tiles by severity"""
    colors = get_color_palette()
    
    data = [
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        [str(len(categorized['critical'])), str(len(categorized['high'])), 
         str(len(categorized['medium'])), str(len(categorized['low']))]
    ]
    
    table = Table(data, colWidths=[1.5*inch]*4)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors['CRITICAL']),
        ('BACKGROUND', (1, 0), (1, 0), colors['HIGH']),
        ('BACKGROUND', (2, 0), (2, 0), colors['WARNING']),
        ('BACKGROUND', (3, 0), (3, 0), colors['LOW']),
        ('TEXTCOLOR', (0, 0), (0, 0), rl_colors.white),
        ('TEXTCOLOR', (1, 0), (1, 0), rl_colors.black),
        ('TEXTCOLOR', (2, 0), (2, 0), rl_colors.black),
        ('TEXTCOLOR', (3, 0), (3, 0), rl_colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, 1), 28),
        ('TEXTCOLOR', (0, 1), (-1, 1), colors['CRITICAL']),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 2, rl_colors.black)
    ]))
    
    return table

def render_callout_box(text, box_type='warning'):
    """Renders a callout box for important information"""
    colors = get_color_palette()
    styles = get_typography_styles()
    
    bg_color = colors['LIGHT_YELLOW'] if box_type == 'warning' else colors['LIGHT_BLUE']
    border_color = colors['WARNING'] if box_type == 'warning' else colors['LOW']
    
    icon = "⚠ " if box_type == 'warning' else "ℹ "
    
    para = Paragraph(icon + text, styles['CalloutText'])
    
    data = [[para]]
    table = Table(data, colWidths=[6.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
        ('BOX', (0, 0), (-1, -1), 2, border_color),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ('RIGHTPADDING', (0, 0), (-1, -1), 15)
    ]))
    
    return table

def render_hipaa_control_table(hipaa_controls, get_hipaa_description):
    """Renders HIPAA control mapping table"""
    colors = get_color_palette()
    
    data = [['HIPAA Control', 'Description', 'Violations']]
    for control, count in hipaa_controls.items():
        if control != 'N/A':
            data.append([control, get_hipaa_description(control), str(count)])
    
    if len(data) <= 1:
        return None
    
    table = Table(data, colWidths=[1.5*inch, 3.5*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors['AWS_DARK_BLUE']),
        ('TEXTCOLOR', (0, 0), (-1, 0), rl_colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, rl_colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [rl_colors.white, colors['LIGHT_GREY']])
    ]))
    
    return table

def render_findings_table(events, get_hipaa_control):
    """Renders key findings table"""
    colors = get_color_palette()
    from datetime import datetime
    
    data = [['Timestamp', 'Rule Name', 'HIPAA Control', 'Resource ID', 'Status']]
    for event in events[:30]:
        timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
        data.append([
            timestamp,
            event['configRuleName'][:30],
            get_hipaa_control(event['configRuleName']),
            event['resourceId'][:25],
            event['complianceType']
        ])
    
    table = Table(data, colWidths=[1.2*inch, 1.8*inch, 1*inch, 1.5*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors['AWS_DARK_BLUE']),
        ('TEXTCOLOR', (0, 0), (-1, 0), rl_colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, rl_colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [rl_colors.white, colors['LIGHT_GREY']])
    ]))
    
    return table

def render_recommendations_list(recommendations):
    """Renders top recommendations with priority badges"""
    styles = get_typography_styles()
    elements = []
    
    for i, rec in enumerate(recommendations, 1):
        badge = render_severity_badge(rec['priority'])
        text = Paragraph(f"{i}. {rec['action']} (Est. time: {rec['time']})", styles['BodyText'])
        
        elements.append(badge)
        elements.append(Spacer(1, 0.05*inch))
        elements.append(text)
        elements.append(Spacer(1, 0.15*inch))
    
    return elements
