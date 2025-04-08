# extrair_arquivos_pcap.py
import sys
import os
from scapy.all import rdpcap, Raw, TCP, IP
from collections import defaultdict

# Assinaturas de arquivos por magic bytes
MAGIC_BYTES = {
    b'%PDF': '.pdf',
    b'PK\x03\x04': '.zip',
    b'\x89PNG': '.png',
    b'GIF89a': '.gif',
    b'GIF87a': '.gif',
    b'\xff\xd8\xff': '.jpg',
    b'Rar!': '.rar',
    b'\x7fELF': '.elf',
    b'MZ': '.exe',
    b'\x25\x21PS': '.ps',
    b'II*\x00': '.tif',
    b'BM': '.bmp',
    b'{\"': '.json',
    b'<html': '.html',
    b'<!DOCT': '.html'
}

def detectar_extensao(dados):
    for assinatura, extensao in MAGIC_BYTES.items():
        if assinatura in dados:
            return extensao
    return '.bin'

if len(sys.argv) != 2:
    print("Uso: python extrair_arquivos_pcap.py <arquivo.pcap>")
    sys.exit(1)

pcap_path = sys.argv[1]
output_dir = "arquivos_extraidos"
os.makedirs(output_dir, exist_ok=True)

print(f"[+] Lendo {pcap_path}...")
packets = rdpcap(pcap_path)

fluxos = defaultdict(list)

print("[+] Agrupando fluxos TCP com payload...")
for pkt in packets:
    if IP in pkt and TCP in pkt and Raw in pkt:
        ip = pkt[IP]
        tcp = pkt[TCP]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        fluxos[key].append(pkt)

print(f"[+] Total de fluxos com payload: {len(fluxos)}")

count = 0
for (src, sport, dst, dport), pkts in fluxos.items():
    payloads = b""
    for pkt in pkts:
        try:
            payloads += bytes(pkt[Raw].load)
        except Exception:
            continue

    if len(payloads) > 100:
        count += 1
        ext = detectar_extensao(payloads)
        filename = f"fluxo_{count}_{src}_{sport}_to_{dst}_{dport}{ext}"
        path = os.path.join(output_dir, filename)
        with open(path, "wb") as f:
            f.write(payloads)
        print(f"[✓] Arquivo salvo: {path}")

print("[✓] Extração concluída.")

