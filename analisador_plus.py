import socket
import struct
import re
import sys
import urllib.parse

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

    hex_clean = re.sub(r'[^0-9a-fA-F]', '', hex_input)
    raw_bytes = bytes.fromhex(hex_clean)

    if len(raw_bytes) < 20:
        print("Pacote muito curto para análise completa.")
        return

    # Detectar dinamicamente onde começa o cabeçalho IP (versão 4 ou 6)
        ip_offset = None
    for i in range(min(32, len(raw_bytes))):
        if raw_bytes[i] >> 4 in (4, 6):
            ip_offset = i
            break

    if ip_offset is None:
        print("[!] Não foi possível detectar início do cabeçalho IP corretamente.")
        return

    ip_header = raw_bytes[ip_offset:ip_offset + 20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    tos = iph[1]
    total_length = iph[2]
    identification = iph[3]
    flags_fragment = iph[4]
    ttl = iph[5]
    protocol = iph[6]
    checksum = iph[7]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    print("========= Pacote IP ============")
    print(f"Versão                : {version}")
    print(f"Header Length         : {ihl * 4} bytes")
    print(f"Tipo de Serviço (ToS) : {tos}")
    print(f"Total Length          : {total_length}")
    print(f"Identificação         : {identification}")
    print(f"Flags/Fragment Offset : {flags_fragment:#06x}")
    print(f"TTL                   : {ttl}")
    print(f"Protocolo             : {protocol} ({'TCP' if protocol == 6 else 'UDP' if protocol == 17 else 'ICMP' if protocol == 1 else 'ICMPv6' if protocol == 58 else 'Desconhecido'})")
    print(f"Checksum              : {checksum:#06x}")
    print(f"IP de Origem          : {src_ip}")
    print(f"IP de Destino         : {dst_ip}")
    print("===============================\n")

    if protocol == 1 or protocol == 58:  # ICMP ou ICMPv6
        icmp_offset = ip_offset + ihl * 4
        if len(raw_bytes) >= icmp_offset + 4:
            icmp_header = struct.unpack('!BBH', raw_bytes[icmp_offset:icmp_offset + 4])
            icmp_type = icmp_header[0]
            icmp_code = icmp_header[1]
            icmp_checksum = icmp_header[2]

            print("== Cabeçalho ICMP ==")
            print(f"Tipo      : {icmp_type}")
            print(f"Código    : {icmp_code}")
            print(f"Checksum  : {icmp_checksum:#06x}")
        else:
            print("[!] Cabeçalho ICMP incompleto.")

        payload_start = ip_offset + (ihl * 4)
        if len(raw_bytes) > payload_start:
            payload = raw_bytes[payload_start:]
            try:
                text = payload.decode('utf-8', errors='ignore')
                print("Payload (UTF-8)    :")
                print("----------------------")
                print(text.strip() if text.strip() else "[Payload vazio ou não imprimível]")
                print("----------------------")
            except Exception as e:
                print(f"Erro ao decodificar payload: {e}")
        else:
            print("Payload            : Nenhum payload detectado")
        return

    if protocol != 6:
        print("[!] Protocolo não é TCP. Análise do cabeçalho TCP ignorada.")

        payload_start = ip_offset + (ihl * 4)
        if len(raw_bytes) > payload_start:
            payload = raw_bytes[payload_start:]
            try:
                text = payload.decode('utf-8', errors='ignore')
                print("Payload (UTF-8)    :")
                print("----------------------")
                print(text.strip() if text.strip() else "[Payload vazio ou não imprimível]")
                print("----------------------")
            except Exception as e:
                print(f"Erro ao decodificar payload: {e}")
        else:
            print("Payload            : Nenhum payload detectado")
        return

    if len(raw_bytes) < ip_offset + 20 + 20:
        print("Pacote muito curto para análise TCP.")
        return

    tcp_header = raw_bytes[ip_offset + 20:ip_offset + 40]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    src_port = tcph[0]
    dst_port = tcph[1]
    flags_byte = tcph[5]

    flags = decode_tcp_flags(flags_byte)

    print("== Análise do Cabeçalho TCP ==")
    print(f"Porta de origem   : {src_port}")
    print(f"Porta de destino  : {dst_port}")
    print(f"Flags TCP ativas  : {', '.join(flags) if flags else 'Nenhuma'}")

    payload_start = ip_offset + (ihl * 4) + ((tcph[4] >> 4) * 4)
    if len(raw_bytes) > payload_start:
        payload = raw_bytes[payload_start:]
        try:
            text = payload.decode('utf-8', errors='ignore')

            referer_match = re.search(r'Referer:\s*(.*)', text, re.IGNORECASE)
            if referer_match:
                referer = referer_match.group(1).strip()
                print(f"Referer HTTP      : {referer}")
            else:
                print("Referer HTTP      : Não encontrado")

            useragent_match = re.search(r'User-Agent:\s*(.*)', text, re.IGNORECASE)
            if useragent_match:
                useragent = useragent_match.group(1).strip()
                print(f"User-Agent HTTP   : {useragent}")
            else:
                print("User-Agent HTTP   : Não encontrado")

            print("Payload (UTF-8)    :")
            print("----------------------")
            print(text.strip() if text.strip() else "[Payload vazio ou não imprimível]")
            print("----------------------")

            creds_match = re.search(r'username=([^&]+)&password=([^&\s]+)', text)
            if creds_match:
                raw_user = creds_match.group(1)
                raw_pass = creds_match.group(2)
                user = urllib.parse.unquote_plus(raw_user)
                passwd = urllib.parse.unquote_plus(raw_pass)
                print(f"\n[✓] Credenciais detectadas:")
                print(f"Usuário : {user}")
                print(f"Senha   : {passwd}")

        except Exception as e:
            print(f"Erro ao decodificar payload: {e}")
    else:
        print("Payload            : Nenhum payload detectado")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python analisador_tcp_arquivo.py <arquivo.txt>")
    else:
        parse_packet_from_file(sys.argv[1])
