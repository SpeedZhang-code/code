import socket
import os
from scapy.all import rdpcap, IP,TCP



def connect_server(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"已連接至 {host}:{port}")
    return client_socket



def send_pcap(sock, file_path):
    if not os.path.exists(file_path): 
        return
    
    with open(file_path, "rb") as f:
        data = f.read()
        sock.sendall(len(data).to_bytes(8, 'big'))
        sock.sendall(data)
    print(f"PCAP 檔案傳送完成")



def playback(sock, target_file, CLIENT_IP):
    packets = rdpcap(target_file)
    total = len(packets)
    i = 0
    TARGET_SERVER_IP = None # 動態鎖定 Server IP
    
    
    while i < total:
        pkt = packets[i]
        #print(f"DEBUG: 正在處理第 {i+1} 個封包, Flags: {pkt[TCP].flags}, Payload: {len(pkt[TCP].payload)}")
        # if not pkt.haslayer(IP):
        #    i += 1
        #    continue
        
        # 過濾掉無關的背景流量
        if (pkt[IP].src != CLIENT_IP and pkt[IP].dst != CLIENT_IP):
            i += 1
            continue
        
        if (pkt[IP].proto != 6): # 只處理 TCP 封包
            i += 1
            continue
        
        if pkt[TCP].flags == 'A' and len(pkt[TCP].payload) == 0:
            i += 1
            #print(f"{pkt[TCP].show()}")
            continue
        
        #print(f"封包 [{i+1}/{total}] | {pkt[IP].src} -> {pkt[IP].dst} | TCP Flags: {pkt[TCP].flags} | Payload Size: {len(pkt[TCP].payload)} bytes")

        # 鎖定 Server IP (第一個由 CLIENT_IP 發出的目的地)
        if TARGET_SERVER_IP is None and pkt[IP].src == CLIENT_IP:
            TARGET_SERVER_IP = pkt[IP].dst
            print(f"[*] 鎖定目標伺服器: {TARGET_SERVER_IP}")
        
        # 我方發送 (Src 是我)
        if pkt[IP].src == CLIENT_IP:
            raw_pkt = bytes(pkt[TCP].payload)  # 只發送 TCP Payload
            sock.sendall(raw_pkt)
            
            transport_header = bytes(pkt[TCP].payload)[:8].hex()
            print(f"->發送封包 [{i+1}] | Payload: 0x{transport_header} | 大小: {len(raw_pkt)} bytes")
            #print(f"{pkt[TCP].show2()}")
            #print(pkt[TCP].flags)
            #print(f"{pkt[TCP].flags}")
            #print(int(pkt[TCP].flags)) 
            #print(f"TCP Flags list: {list(pkt[TCP].flags)}")
            #print(f"  L___TCP Flags repr: {repr(pkt[TCP].flags)}")
            i += 1
        
        # 等對方回應 (Src 是伺服器，且 Dst 是我)
        elif pkt[IP].src == TARGET_SERVER_IP and pkt[IP].dst == CLIENT_IP:
            expected_size = len(bytes(pkt[TCP].payload))
            #print(f"<- 預期接收封包 [{i+1}] | 來自: {pkt[IP].src} | 長度: {expected_size}")
            
            received_data = b""
            while len(received_data) < expected_size:
                chunk = sock.recv(expected_size - len(received_data))
                if not chunk:
                    print("連線中斷")
                    return
                received_data += chunk
            
            print(f"<-成功接收回應 [{i+1}] ({len(received_data)} bytes) | Payload: 0x{received_data[:8].hex()} bytes")
            
            i += 1
        
        else:
            # 雖然與 CLIENT_IP 相關，但方向不符 (例如自發廣播)，則跳過192.168.1.1->192.168.0.226
            i += 1




if __name__ == "__main__":
    target_file = r"C:\Users\USER\Desktop\quic_socket\tcp3.pcap"
    CLIENT_IP = "192.168.0.226"
    SERVER_IP = "140.116.154.146"
    HOST_IP = "127.0.0.1"
    PORT = 65432 
    sock = connect_server(HOST_IP, PORT)

    #send_pcap(sock, target_file)

    playback(sock, target_file, CLIENT_IP)
    sock.close()
    print("連線已關閉")

