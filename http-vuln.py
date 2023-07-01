import pandas as pd
from scapy.all import rdpcap, IP, TCP
import re
from tqdm import tqdm

# Initialise DataFrame pour stocker les informations sensibles détectées
sensitive_info_df = pd.DataFrame(columns=["timestamp", "info", "ip_src", "ip_dst"])

def process_packet(packet):
    global sensitive_info_df
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(IP):
        payload = str(packet[TCP].payload)
        sensitive_info = re.search(r"(pass|password|user|username|login|mdp|mail)", payload, re.I)
        if sensitive_info:
            print(f"[SENSITIVE INFO DETECTED]: {payload}")
            # Append the info to the DataFrame
            sensitive_info_df = sensitive_info_df.append({"timestamp": packet.time, "info": payload, "ip_src": packet[IP].src, "ip_dst": packet[IP].dst}, ignore_index=True)

# Lecture du fichier pcap
packets = rdpcap('lyria.pcapng')  # Remplacez par le nom de votre fichier pcap

# Créez une barre de progression avec tqdm
progress = tqdm(total=len(packets), desc="Processing packets", ncols=70)

for packet in packets:
    process_packet(packet)
    # Mettez à jour la barre de progression après chaque paquet
    progress.update()

# Fermez la barre de progression à la fin
progress.close()

# Écrit les informations sensibles détectées dans un fichier CSV après avoir terminé l'écoute du réseau
sensitive_info_df.to_csv('sensitive_info.csv', index=False)
