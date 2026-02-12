# code


預期的使用過程
server.py --thread-num=10 --port 50000
client.py --pcap /tmp/a.pcap --subnet 192.168.0.0/24

1.server要有thread，告知Status，設置client連接的數量。<br>
2.server要有port的提供，決定client要用那個Port去連[50000-51000]。<br>
3.client可以自己輸入pcap檔位置。<br>
4.client可以自己輸入subnet網域，或是判斷誰是client_ip。<br>

---

筆記:CIDR、Argparse

---

Server Usage<br>
server.py [OPTIONS]
<br><br>
OPTIONS<br>
--thread-num：同時處理請求的 Thread 數量<br>
--process-num：啟動的 Worker Process 數量<br>
--port：Server 監聽的起始 Port 號<br>

Client Usage<br>
client.py [OPTIONS]
OPTIONS<br>
--pcap：讀取的 pcap 檔<br>
--subnet：Client IP subnet (default: 192.168.0.0/24)<br>
<br>

# **PRC - pcap.replay**

啟動 PCAP 檔案的回放功能。Server 會讀取指定的檔案並將封包根據原始時間戳記（或指定速率

### JSON RPC Request:

```json

### JSON RPC Request:

{
  "v": 1,
  "method": "pcap.replay",
  "params": {
    "speed": 1.0,
    "subnet": "192.168.0.0/24"
  }
}

### JSON RPC Response:
{"r": {"port": 50001, "task_id": "99b2-xf22"}}

```




# RPC - Error

### Server is busy

```json
{
  "e": {
    "c": 2,
    "m": "server busy"
  }
}
```





<img width="960" height="540" alt="封包模擬2" src="https://github.com/user-attachments/assets/7c20f49a-3ed7-4f40-8c9a-e10a3adb4609" />


