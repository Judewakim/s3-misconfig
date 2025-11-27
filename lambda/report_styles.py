"""
WakimWorks HIPAA Compliance Report - Typography & Color System
Defines the visual grammar for all report components
"""

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

def get_color_palette():
    """Returns the severity color palette"""
    return {
        'CRITICAL': colors.HexColor('#d13212'),
        'HIGH': colors.HexColor('#ff9900'),
        'MEDIUM': colors.HexColor('#ffc107'),
        'LOW': colors.HexColor('#17a2b8'),
        'PASS': colors.HexColor('#28a745'),
        'FAIL': colors.HexColor('#d13212'),
        'WARNING': colors.HexColor('#ffc107'),
        'AWS_DARK_BLUE': colors.HexColor('#232f3e'),
        'AWS_ORANGE': colors.HexColor('#ff9900'),
        'LIGHT_GREY': colors.HexColor('#f5f5f5'),
        'LIGHT_YELLOW': colors.HexColor('#fff3cd'),
        'LIGHT_RED': colors.HexColor('#fff5f5'),
        'LIGHT_GREEN': colors.HexColor('#d4edda'),
        'LIGHT_BLUE': colors.HexColor('#d1ecf1'),
        'GREY': colors.HexColor('#6c757d'),
        'BORDER_GREY': colors.HexColor('#dee2e6')
    }

def get_typography_styles():
    """Returns all paragraph styles for the report"""
    base_styles = getSampleStyleSheet()
    colors_palette = get_color_palette()
    
    styles = {
        'DocumentTitle': ParagraphStyle(
            'DocumentTitle',
            parent=base_styles['Heading1'],
            fontSize=28,
            textColor=colors_palette['AWS_DARK_BLUE'],
            alignment=TA_CENTER,
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ),
        
        'SectionHeader': ParagraphStyle(
            'SectionHeader',
            parent=base_styles['Heading2'],
            fontSize=18,
            textColor=colors_palette['AWS_DARK_BLUE'],
            spaceBefore=20,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ),
        
        'SubsectionHeader': ParagraphStyle(
            'SubsectionHeader',
            parent=base_styles['Heading3'],
            fontSize=14,
            textColor=colors_palette['AWS_DARK_BLUE'],
            spaceBefore=15,
            spaceAfter=8,
            backColor=colors_palette['LIGHT_GREY'],
            borderPadding=8,
            fontName='Helvetica-Bold'
        ),
        
        'ControlTitle': ParagraphStyle(
            'ControlTitle',
            parent=base_styles['Heading4'],
            fontSize=11,
            textColor=colors.black,
            spaceBefore=10,
            spaceAfter=5,
            fontName='Helvetica-Bold'
        ),
        
        'BodyText': ParagraphStyle(
            'BodyText',
            parent=base_styles['Normal'],
            fontSize=12,
            textColor=colors.black,
            alignment=TA_LEFT,
            leading=16,
            fontName='Helvetica'
        ),
        
        'EmphasisText': ParagraphStyle(
            'EmphasisText',
            parent=base_styles['Normal'],
            fontSize=12,
            textColor=colors_palette['CRITICAL'],
            fontName='Helvetica-Oblique',
            backColor=colors_palette['LIGHT_YELLOW'],
            borderPadding=5
        ),
        
        'MonospaceText': ParagraphStyle(
            'MonospaceText',
            parent=base_styles['Code'],
            fontSize=10,
            textColor=colors.black,
            fontName='Courier',
            backColor=colors.HexColor('#f8f9fa'),
            borderColor=colors_palette['BORDER_GREY'],
            borderWidth=1,
            borderPadding=10,
            leftIndent=10,
            rightIndent=10
        ),
        
        'MetadataText': ParagraphStyle(
            'MetadataText',
            parent=base_styles['Normal'],
            fontSize=10,
            textColor=colors_palette['GREY'],
            fontName='Helvetica'
        ),
        
        'BulletText': ParagraphStyle(
            'BulletText',
            parent=base_styles['Normal'],
            fontSize=12,
            textColor=colors.black,
            fontName='Helvetica',
            leftIndent=20,
            bulletIndent=10
        ),
        
        'CalloutText': ParagraphStyle(
            'CalloutText',
            parent=base_styles['Normal'],
            fontSize=11,
            textColor=colors.black,
            fontName='Helvetica',
            backColor=colors_palette['LIGHT_YELLOW'],
            borderColor=colors_palette['WARNING'],
            borderWidth=2,
            borderPadding=12
        )
    }
    
    return styles

def get_severity_color(severity):
    """Returns the color for a given severity level"""
    palette = get_color_palette()
    return palette.get(severity.upper(), palette['GREY'])
