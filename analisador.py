import socket
import struct
import re
import sys

def decode_tcp_flags(flag_byte):
    flags = {
        "URG": bool(flag_byte & 0x20),
        "ACK": bool(flag_byte & 0x10),
        "PSH": bool(flag_byte & 0x08),
        "RST": bool(flag_byte & 0x04),
        "SYN": bool(flag_byte & 0x02),
        "FIN": bool(flag_byte & 0x01),
    }
    return [name for name, active in flags.items() if active]

def parse_packet_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            hex_input = f.read()
    except Exception as e:
        print(f"Erro ao abrir o arquivo: {e}")
        return

    # Limpa todos os caracteres não hexadecimais
    hex_clean = re.sub(r'[^0-9a-fA-F]', '', hex_input)
    raw_bytes = bytes.fromhex(hex_clean)

    if len(raw_bytes) < 54:
        print("Pacote muito curto para análise completa.")
        return

    # IP Header
    ip_header = raw_bytes[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    # TCP Header
    tcp_header = raw_bytes[34:54]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    src_port = tcph[0]
    dst_port = tcph[1]
    flags_byte = tcph[5]

    flags = decode_tcp_flags(flags_byte)

    print("== Análise do Pacote ==")
    print(f"IP de origem      : {src_ip}")
    print(f"Porta de origem   : {src_port}")
    print(f"IP de destino     : {dst_ip}")
    print(f"Porta de destino  : {dst_port}")
    print(f"Flags TCP ativas  : {', '.join(flags) if flags else 'Nenhuma'}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python analisador_tcp_arquivo.py <arquivo.txt>")
    else:
        parse_packet_from_file(sys.argv[1])

