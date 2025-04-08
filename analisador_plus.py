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

    if len(raw_bytes) < 54:
        print("Pacote muito curto para análise completa.")
        return

    ip_header = raw_bytes[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

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

    # Verifica se há payload HTTP
    payload_start = 54
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

            # Decodifica campos username e password se existirem
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
