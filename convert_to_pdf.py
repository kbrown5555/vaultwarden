#!/usr/bin/env python3
"""
Convert markdown security audit report to PDF
"""
import markdown
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
import sys

def convert_md_to_pdf(md_file, pdf_file):
    # Read markdown file
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()

    # Convert markdown to HTML
    html_content = markdown.markdown(
        md_content,
        extensions=['tables', 'fenced_code', 'codehilite', 'toc']
    )

    # Add CSS styling for better PDF appearance
    css_content = """
    @page {
        size: A4;
        margin: 2cm;
        @top-center {
            content: "Vaultwarden Security Audit Report";
            font-size: 10pt;
            color: #666;
        }
        @bottom-center {
            content: "Page " counter(page) " of " counter(pages);
            font-size: 10pt;
            color: #666;
        }
    }

    body {
        font-family: Arial, Helvetica, sans-serif;
        font-size: 11pt;
        line-height: 1.6;
        color: #333;
    }

    h1 {
        color: #1a1a1a;
        font-size: 24pt;
        border-bottom: 3px solid #333;
        padding-bottom: 10px;
        margin-top: 20px;
        page-break-before: always;
    }

    h1:first-of-type {
        page-break-before: avoid;
    }

    h2 {
        color: #2c3e50;
        font-size: 18pt;
        border-bottom: 2px solid #3498db;
        padding-bottom: 5px;
        margin-top: 20px;
        page-break-after: avoid;
    }

    h3 {
        color: #34495e;
        font-size: 14pt;
        margin-top: 15px;
        page-break-after: avoid;
    }

    h4 {
        color: #555;
        font-size: 12pt;
        margin-top: 10px;
    }

    table {
        border-collapse: collapse;
        width: 100%;
        margin: 15px 0;
        page-break-inside: avoid;
    }

    th {
        background-color: #3498db;
        color: white;
        padding: 10px;
        text-align: left;
        font-weight: bold;
        border: 1px solid #2980b9;
    }

    td {
        padding: 8px;
        border: 1px solid #ddd;
    }

    tr:nth-child(even) {
        background-color: #f9f9f9;
    }

    code {
        background-color: #f4f4f4;
        border: 1px solid #ddd;
        padding: 2px 5px;
        border-radius: 3px;
        font-family: 'Courier New', monospace;
        font-size: 10pt;
    }

    pre {
        background-color: #f8f8f8;
        border: 1px solid #ddd;
        border-left: 4px solid #3498db;
        padding: 10px;
        overflow-x: auto;
        page-break-inside: avoid;
    }

    pre code {
        background-color: transparent;
        border: none;
        padding: 0;
    }

    blockquote {
        border-left: 4px solid #3498db;
        padding-left: 15px;
        margin: 15px 0;
        color: #555;
        font-style: italic;
    }

    ul, ol {
        margin: 10px 0;
        padding-left: 30px;
    }

    li {
        margin: 5px 0;
    }

    strong {
        color: #2c3e50;
    }

    a {
        color: #3498db;
        text-decoration: none;
    }

    hr {
        border: none;
        border-top: 2px solid #ddd;
        margin: 20px 0;
    }

    .warning {
        color: #e67e22;
    }

    .checkmark {
        color: #27ae60;
    }
    """

    # Wrap HTML with proper structure
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Vaultwarden Security Audit Report</title>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    # Convert HTML to PDF
    font_config = FontConfiguration()
    html_doc = HTML(string=full_html)
    css = CSS(string=css_content, font_config=font_config)

    html_doc.write_pdf(pdf_file, stylesheets=[css], font_config=font_config)
    print(f"Successfully converted {md_file} to {pdf_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 convert_to_pdf.py <input.md> <output.pdf>")
        sys.exit(1)

    md_file = sys.argv[1]
    pdf_file = sys.argv[2]
    convert_md_to_pdf(md_file, pdf_file)
