import sys
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
from collections import defaultdict, Counter
from datetime import datetime

if len(sys.argv) != 2:
    print("Uso: python auditoria_forense_pcap.py <arquivo.pcap>")
    sys.exit(1)

pcap_file = sys.argv[1]
print(f"[+] Lendo arquivo: {pcap_file}")
packets = rdpcap(pcap_file)
print(f"[+] Total de pacotes carregados: {len(packets)}")

conexoes = set()
ip_counter = Counter()
porta_counter = Counter()
dns_queries = set()
icmp_hosts = set()
arp_hosts = set()
flags_por_conexao = defaultdict(list)
scan_suspeitos = set()

timestamps = []

print("[+] Iniciando análise dos pacotes...")

for pkt in packets:
    if hasattr(pkt, 'time'):
        try:
            timestamps.append(float(pkt.time))
        except Exception:
            continue

    if IP in pkt:
        ip_counter[pkt[IP].src] += 1

    if IP in pkt and TCP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        conexoes.add((src, sport, dst, dport))
        porta_counter[dport] += 1
        flags_por_conexao[(src, sport, dst, dport)].append(flags)

        if flags == 0x02:  # SYN
            scan_suspeitos.add(src)

    if IP in pkt and UDP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        conexoes.add((src, sport, dst, dport))
        porta_counter[dport] += 1

    if pkt.haslayer(DNS) and pkt.haslayer(UDP):
        try:
            if pkt[DNS].qdcount > 0 and pkt[DNS].qd is not None:
                qname = pkt[DNS].qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors='ignore')
                dns_queries.add(qname)
        except Exception:
            pass

    if pkt.haslayer(ICMP) and IP in pkt:
        icmp_hosts.add(pkt[IP].src)

    if pkt.haslayer(ARP):
        arp_hosts.add(pkt[ARP].psrc)

if timestamps:
    start_time = datetime.fromtimestamp(min(timestamps)).strftime('%Y-%m-%d %H:%M:%S')
    end_time = datetime.fromtimestamp(max(timestamps)).strftime('%Y-%m-%d %H:%M:%S')
else:
    start_time = end_time = "Indefinido"

relatorio_path = "relatorio_forense.md"
with open(relatorio_path, "w") as f:
    f.write(f"# Relatório de Análise Forense de Tráfego (.pcap)\n\n")
    f.write(f"**Data da Análise:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"**Arquivo analisado:** `{pcap_file}`\n\n")

    f.write("## 1. Resumo da Captura\n")
    f.write(f"- Total de pacotes: {len(packets)}\n")
    f.write(f"- Período da captura: {start_time} até {end_time}\n")
    f.write(f"- Sessões únicas: {len(conexoes)}\n")
    f.write(f"- Protocolos detectados: TCP, UDP, ICMP, ARP, DNS\n\n")

    f.write("## 2. Principais Hosts\n")
    f.write("### IPs com maior volume de pacotes\n")
    for ip, count in ip_counter.most_common(10):
        f.write(f"- {ip}: {count} pacotes\n")

    f.write("\n### Hosts descobertos via ARP\n")
    for ip in sorted(arp_hosts):
        f.write(f"- {ip}\n")

    f.write("\n### Hosts que enviaram ICMP\n")
    for ip in sorted(icmp_hosts):
        f.write(f"- {ip}\n")

    f.write("\n## 3. Conexões TCP\n")
    for conn, flags in list(flags_por_conexao.items())[:10]:
        flag_str = ",".join(str(f) for f in flags)
        f.write(f"- {conn}: [{flag_str}]\n")

    f.write("\n## 4. Atividades Suspeitas\n")
    if scan_suspeitos:
        f.write("### Detectado possível SYN Scan dos IPs:\n")
        for ip in scan_suspeitos:
            f.write(f"- {ip}\n")
    else:
        f.write("- Nenhuma atividade suspeita de scan detectada.\n")

    f.write("\n## 5. Consultas DNS\n")
    for query in dns_queries:
        f.write(f"- {query}\n")

    f.write("\n## 6. Portas mais acessadas\n")
    for porta, count in porta_counter.most_common(10):
        f.write(f"- Porta {porta}: {count} vezes\n")

    f.write("\n## 7. Conclusões\n")
    if scan_suspeitos:
        f.write("- Recomendado investigar IPs envolvidos em varredura TCP.\n")
    if len(dns_queries) > 0:
        f.write("- Verificar reputação de domínios DNS acessados.\n")
    f.write("- Analisar comportamento dos IPs mais ativos.\n")

print(f"[✓] Relatório Markdown salvo como '{relatorio_path}'")
