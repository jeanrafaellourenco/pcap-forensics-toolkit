# pip install scapy
from scapy.all import rdpcap, TCP, IP
import sys

def decode_tcp_flags(flags):
    flag_map = {
        "FIN": 0x01,
        "SYN": 0x02,
        "RST": 0x04,
        "PSH": 0x08,
        "ACK": 0x10,
        "URG": 0x20,
    }
    return [name for name, bit in flag_map.items() if flags & bit]

def analisar_pcap(pcap_file, output_file="resultado.txt"):
    print(f"[+] Carregando pacotes do arquivo '{pcap_file}'...")
    pacotes = rdpcap(pcap_file)
    print(f"[+] {len(pacotes)} pacotes carregados.")
    
    saida = []

    for i, pkt in enumerate(pacotes):
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
            flags = decode_tcp_flags(tcp.flags)

            bloco = (
                f"== PACOTE TCP {i+1} ==\n"
                f"Origem     : {ip.src}:{tcp.sport}\n"
                f"Destino    : {ip.dst}:{tcp.dport}\n"
                f"Flags TCP  : {', '.join(flags)}\n"
                + "-" * 30
            )

            print(bloco)
            saida.append(bloco)

    # Salvar no arquivo
    print(f"[+] Salvando resultados em '{output_file}'...")
    with open(output_file, "w") as f:
        f.write("\n".join(saida))
    print("[✓] Análise finalizada com sucesso.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python leitor_pcap_scapy.py <arquivo.pcap>")
    else:
        analisar_pcap(sys.argv[1])
