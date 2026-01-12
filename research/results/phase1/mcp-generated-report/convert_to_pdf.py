#!/usr/bin/env python3
"""
Convert Markdown report to PDF
"""

import sys
import os

try:
    from markdown import markdown
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
except ImportError:
    print("Installing required packages...")
    os.system("pip3 install --user markdown weasyprint")
    from markdown import markdown
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration

def markdown_to_pdf(md_file, pdf_file):
    """Convert markdown file to PDF"""
    # Read markdown file
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()
    
    # Convert markdown to HTML
    html_content = markdown(md_content, extensions=['extra', 'tables', 'codehilite'])
    
    # Add CSS styling
    html_with_style = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{
                size: A4;
                margin: 2cm;
            }}
            body {{
                font-family: 'DejaVu Sans', Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.6;
                color: #333;
            }}
            h1 {{
                color: #2c3e50;
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
                page-break-after: avoid;
            }}
            h2 {{
                color: #34495e;
                border-bottom: 2px solid #95a5a6;
                padding-bottom: 8px;
                margin-top: 30px;
                page-break-after: avoid;
            }}
            h3 {{
                color: #555;
                margin-top: 20px;
                page-break-after: avoid;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin: 20px 0;
                page-break-inside: avoid;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #3498db;
                color: white;
                font-weight: bold;
            }}
            tr:nth-child(even) {{
                background-color: #f2f2f2;
            }}
            code {{
                background-color: #f4f4f4;
                padding: 2px 4px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
            }}
            pre {{
                background-color: #f4f4f4;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
                page-break-inside: avoid;
            }}
            .alert-box {{
                background-color: #fff3cd;
                border: 1px solid #ffc107;
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
            }}
        </style>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """
    
    # Convert HTML to PDF
    font_config = FontConfiguration()
    HTML(string=html_with_style).write_pdf(
        pdf_file,
        font_config=font_config
    )
    
    print(f"✓ PDF generated successfully: {pdf_file}")

if __name__ == "__main__":
    md_file = "phase1_attack_analysis_report.md"
    pdf_file = "phase1_attack_analysis_report.pdf"
    
    if not os.path.exists(md_file):
        print(f"Error: {md_file} not found")
        sys.exit(1)
    
    markdown_to_pdf(md_file, pdf_file)
