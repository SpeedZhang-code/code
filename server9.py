import socket
import io
from scapy.all import rdpcap, IP, Ether,TCP

def connect_server(host='127.0.0.1', port=65432):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Server 啟動，監聽 {host}:{port}...")
    conn, addr = s.accept()
    print(f"已從 {addr} 建立連線")
    return conn, s

#pcap_cache = []

# # 使用 makefile 像讀取檔案一樣讀取 Socket
# def receive_pcap(client_socket):
#     global pcap_cache
#     f = client_socket.makefile('rb') # 建立一個模擬檔案的包裝
#     header = f.read(8)
#     if not header: return
    
#     file_size = int.from_bytes(header, 'big')
#     full_data = f.read(file_size) # makefile 的 read(n) 會自動幫你處理迴圈直到讀滿 n 位元組
    
#     pcap_cache = rdpcap(io.BytesIO(full_data))



def run_server_playback(conn,target_file):
    #global pcap_cache
    pcap_cache = rdpcap(target_file)
    current_idx = 0
    total = len(pcap_cache)
    SERVER_IP = None

    while current_idx < total:
        pkt = pcap_cache[current_idx]
    
        #if not pkt.haslayer(IP):
        #    current_idx += 1
        #    continue
        
        # 決定誰是 Server (以第一個封包的 Dst 作為 Server IP)
        if SERVER_IP is None:
            SERVER_IP = pkt[IP].dst
            print(f"[*] 識別 SERVER_IP: {SERVER_IP}")
        
        if (pkt[IP].proto != 6): # 只處理 TCP 封包
            current_idx += 1
            continue
        
        if pkt[TCP].flags == 'A' and len(pkt[TCP].payload) == 0:
            current_idx += 1
            continue
        
        # 接收模式 (當 PCAP 顯示目的地是 Server 時)
        if pkt[IP].dst == SERVER_IP:
            expected_size = len(bytes(pkt[TCP].payload))
            #print(f"<- 預期接收 Client 封包 [{current_idx+1}] | 預期長度: {expected_size}")
            
            received_data = b""
            while len(received_data) < expected_size:
                chunk = conn.recv(expected_size - len(received_data))
                if not chunk:
                    print("!!! Client 已斷開連線")
                    return
                received_data += chunk
            
            # 驗證接收到的資料長度
            print(f"<-成功接收回應 [{current_idx+1}] ({len(received_data)} bytes) | Payload: 0x{received_data[:8].hex()}")
            current_idx += 1
        
        # 發送模式 (當 PCAP 顯示來源是 Server 時)
        elif pkt[IP].src == SERVER_IP:
            raw_pkt = bytes(pkt[TCP].payload)  # 只發送 TCP Payload
            conn.sendall(raw_pkt)
            
            transport_header = bytes(pkt[TCP].payload)[:8].hex()
            print(f"-> 回傳 Server 封包 [{current_idx+1}] | Payload: 0x{transport_header} | 大小: {len(raw_pkt)} bytes")
            current_idx += 1
            
        else:
            # 若出現不屬於這兩者 IP 的封包則跳過
            current_idx += 1



if __name__ == "__main__":
    target_file = r"C:\Users\USER\Desktop\quic_socket\tcp3.pcap"
    conn, server_sock = connect_server()
    #receive_pcap(conn)
    
    #print("PCAP 接收完成，等待後續 Playback 連線...")

    run_server_playback(conn,target_file)
    
    server_sock.close()
    print("連線已關閉，Server 結束")

