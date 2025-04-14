
# pip install markdown

import argparse
import markdown
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
img {
  max-width: 100%;
  border: 1px solid #ccc;
  margin: 10px 0;
}
"""

def md_para_html(md_path, html_path):
    if not os.path.exists(md_path):
        print(f"Erro: arquivo '{md_path}' não encontrado.")
        sys.exit(1)

    with open(md_path, "r", encoding="utf-8") as f:
        md_content = f.read()
        html_body = markdown.markdown(md_content, extensions=["fenced_code", "codehilite", "tables"])

    html_template = "<html><head><meta charset='utf-8'><style>{}</style></head><body>{}</body></html>".format(
        CSS_PADRAO, html_body)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f"[✔] HTML gerado com sucesso: {html_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Converter Markdown para HTML com estilo embutido.")
    parser.add_argument("entrada", help="Caminho do arquivo .md de entrada.")
    parser.add_argument("-o", "--saida", default="saida.html", help="Nome do arquivo HTML de saída.")

    args = parser.parse_args()
    md_para_html(args.entrada, args.saida)
