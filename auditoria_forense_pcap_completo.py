# auditoria_forense_pcap_completo.py
import sys
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
from collections import defaultdict, Counter
from datetime import datetime
import base64

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
c2_suspeitos = set()
user_agents = Counter()
credenciais_expostas = []
ip_dados_enviados = Counter()
ip_roles = defaultdict(set)
protocolos_identificados = defaultdict(set)
ip_mac_map = defaultdict(set)
portas_abertas = set()

timestamps = []

print("[+] Iniciando análise dos pacotes...")

for pkt in packets:
    if hasattr(pkt, 'time'):
        try:
            timestamps.append(float(pkt.time))
        except Exception:
            continue

    if Ether in pkt and IP in pkt:
        ip_src = pkt[IP].src
        mac_src = pkt[Ether].src
        if ip_src and mac_src:
            ip_mac_map[ip_src].add(mac_src)

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

        if flags == 0x02:
            scan_suspeitos.add(src)
            ip_roles[src].add("atacante")

        if flags == 0x12:
            portas_abertas.add(sport)

        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            try:
                text = payload.decode('utf-8', errors='ignore')
                if "User-Agent:" in text:
                    for line in text.split("\n"):
                        if "User-Agent:" in line:
                            agent = line.split("User-Agent:",1)[1].strip()
                            user_agents[agent] += 1

                if any(kw in text.lower() for kw in ['password', 'senha', 'pass', 'login', 'authorization']):
                    credenciais_expostas.append((src, dst, text[:200]))
                    ip_roles[src].add("possível vazamento de credencial")

                if len(payload) > 100:
                    ip_dados_enviados[src] += len(payload)
                    if len(payload) > 5000:
                        ip_roles[src].add("possível exfiltração de dados")

            except Exception:
                pass

        if dport in [21]:
            protocolos_identificados[src].add("FTP")
        elif dport in [25, 587]:
            protocolos_identificados[src].add("SMTP")
        elif dport in [110, 995]:
            protocolos_identificados[src].add("POP3")
        elif dport == 143:
            protocolos_identificados[src].add("IMAP")

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

                if len(qname) > 50 and any(c.isdigit() for c in qname):
                    c2_suspeitos.add(qname)
                    ip_roles[src].add("possível comunicação C2")
        except Exception:
            pass

    if pkt.haslayer(ICMP) and IP in pkt:
        icmp_hosts.add(pkt[IP].src)

    if pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        arp_hosts.add(src_ip)
        ip_mac_map[src_ip].add(src_mac)

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

    if c2_suspeitos:
        f.write("\n### Possíveis domínios de C2 detectados:\n")
        for dom in c2_suspeitos:
            f.write(f"- {dom}\n")

    if ip_dados_enviados:
        f.write("\n### Possível exfiltração de dados (volume por IP origem):\n")
        for ip, total in ip_dados_enviados.most_common():
            if total > 5000:
                f.write(f"- {ip}: {total} bytes enviados\n")

    f.write("\n## 5. Consultas DNS\n")
    for query in dns_queries:
        f.write(f"- {query}\n")

    f.write("\n## 6. Portas mais acessadas\n")
    for porta, count in porta_counter.most_common(10):
        f.write(f"- Porta {porta}: {count} vezes\n")

    f.write("\n## 6.1 Portas possivelmente abertas (SYN-ACK)\n")
    for porta in sorted(portas_abertas):
        f.write(f"- Porta {porta}\n")

    f.write("\n## 7. User-Agents incomuns detectados\n")
    for agent, count in user_agents.most_common():
        if any(k in agent.lower() for k in ['python', 'curl', 'nmap', 'bot', 'scanner', 'wget']):
            f.write(f"- {agent}: {count} vezes\n")

    f.write("\n## 8. Credenciais possivelmente expostas\n")
    for src, dst, trecho in credenciais_expostas:
        f.write(f"- {src} -> {dst}: {trecho}\n")

    f.write("\n## 9. Protocolos Específicos Detectados\n")
    for ip, protocolos in protocolos_identificados.items():
        f.write(f"- {ip}: {', '.join(protocolos)}\n")

    f.write("\n## 10. Classificação por IP (Comportamento)\n")
    for ip, roles in ip_roles.items():
        f.write(f"- {ip}: {', '.join(roles)}\n")

    f.write("\n## 11. Conclusões\n")
    if scan_suspeitos:
        f.write("- Recomendado investigar IPs envolvidos em varredura TCP.\n")
    if c2_suspeitos:
        f.write("- Verificar possíveis domínios de C2.\n")
    if ip_dados_enviados:
        f.write("- Avaliar IPs com grande volume de envio (possível exfiltração).\n")
    if credenciais_expostas:
        f.write("- Foram encontrados indícios de credenciais trafegando sem proteção.\n")

    f.write("\n## 12. Endereços Físicos Detectados\n")
    for ip, macs in ip_mac_map.items():
        for mac in macs:
            f.write(f"- {ip} -> {mac}\n")

print(f"[✓] Relatório Markdown salvo como '{relatorio_path}'")
