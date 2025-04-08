# 🔍 PCAP Forensics Toolkit

Conjunto de ferramentas Python para análise forense e extração de informações de arquivos `.pcap`. Ideal para profissionais de segurança, pentesters e analistas forenses que desejam investigar tráfego de rede capturado.

## 📂 Funcionalidades

- **Análise Forense Avançada**
  - Detecta varreduras de portas (SYN scan), comunicações C2, exfiltração de dados, user-agents suspeitos e possíveis vazamentos de credenciais.
  - Gera relatórios em Markdown com indicadores e evidências.
- **Extração de Arquivos**
  - Reconstrói arquivos transmitidos via TCP usando assinaturas (magic bytes).
- **Leitura e Interpretação de Pacotes**
  - Analisa pacotes TCP, decodifica flags e extrai campos HTTP como User-Agent e Referer.
- **Decodificação de Pacotes em HEX**
  - Permite interpretar pacotes fornecidos como strings hexadecimais (útil em análises manuais).

## 📦 Estrutura do Projeto

| Script                          | Descrição |
|----------------------------------|-----------|
| `auditoria_forense_pcap.py`     | Versão padrão para auditoria de tráfego `.pcap`, com relatório básico. |
| `auditoria_forense_pcap_completo.py` | Versão aprimorada com detecção de exfiltração, C2, user-agents e credenciais. |
| `extrator_arquivos_pcap.py`     | Extrai arquivos transferidos por TCP (PDFs, imagens, zips, etc). |
| `leitor_pcap.py`                | Analisa pacotes TCP com SCAPY e exporta para arquivo. |
| `analisador.py`                 | Interpreta pacotes TCP em formato hexadecimal. |
| `analisador_plus.py`           | Versão extendida do analisador com parsing de headers HTTP e extração de credenciais. |

## 🛠️ Pré-requisitos

- Python 3.6+
- Instale as dependências com:

```bash
pip install scapy
```

## 🚀 Como Usar

### Auditoria Forense

```bash
python3 auditoria_forense_pcap_completo.py captura.pcap
```

Gera `relatorio_forense.md` com resumo da análise.

### Extração de Arquivos de um PCAP

```bash
python3 extrator_arquivos_pcap.py captura.pcap
```

Arquivos reconstruídos serão salvos em `./arquivos_extraidos`.

### Análise de Pacotes em HEX

```bash
python3 analisador_plus.py pacote_hex.txt
```

Ou versão simples:

```bash
python3 analisador.py pacote_hex.txt
```

### Visualização Detalhada com SCAPY

```bash
python3 leitor_pcap.py captura.pcap
```

## 📄 Relatório Forense

O relatório gerado inclui:

- Hosts ativos (ARP, ICMP)
- Consultas DNS suspeitas
- Top IPs e portas acessadas
- Detecção de ataques (SYN scan, C2, exfiltração)
- User-Agents incomuns
- Vazamentos de credenciais

## 🔒 Aplicações

- Análise forense de incidentes
- Verificação de tráfego suspeito
- Reversão de dados trafegados
- Treinamentos de Red/Blue Team

## 📃 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais detalhes.
