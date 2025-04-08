# pip install markdown
# pip install pdfkit
# E atenção: o pdfkit depende do wkhtmltopdf instalado no sistema.
# Linux: sudo apt install wkhtmltopdf
# Mac: brew install wkhtmltopdf

import argparse
import markdown
import pdfkit
import os
import sys

CSS_PADRAO = """
body {
  font-family: "Segoe UI", Roboto, sans-serif;
  line-height: 1.6;
  max-width: 900px;
  margin: 2rem auto;
  padding: 0 2rem;
  background: white;
  color: #333;
}
h1, h2, h3 {
  color: #191970;
  margin-top: 2rem;
}
code, pre {
  background: #f5f5f5;
  padding: 0.4em 0.6em;
  border-radius: 6px;
  font-family: monospace;
  font-size: 0.95em;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}
th, td {
  border: 1px solid #ddd;
  padding: 8px;
}
"""

def md_para_pdf(md_path, pdf_path):
    if not os.path.exists(md_path):
        print(f"Erro: arquivo '{md_path}' não encontrado.")
        sys.exit(1)

    with open(md_path, "r", encoding="utf-8") as f:
        md_content = f.read()
        html_body = markdown.markdown(md_content, extensions=["fenced_code", "codehilite", "tables"])

    html_template = "<html><head><meta charset='utf-8'><style>{}</style></head><body>{}</body></html>".format(
        CSS_PADRAO, html_body)

    pdfkit.from_string(html_template, pdf_path)
    print(f"[✔] PDF gerado com sucesso: {pdf_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Converter Markdown para PDF com estilo embutido.")
    parser.add_argument("entrada", help="Caminho do arquivo .md de entrada.")
    parser.add_argument("-o", "--saida", default="saida.pdf", help="Nome do arquivo PDF de saída.")

    args = parser.parse_args()
    md_para_pdf(args.entrada, args.saida)
