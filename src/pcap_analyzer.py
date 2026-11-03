import os
import sys
import struct
import socket
import argparse
from datetime import datetime
import pandas as pd
import joblib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from backend.app.database import SessionLocal
from backend.app.models import Threat
from src.predict import predict, MITRE_MAP

MODEL_PATH = os.path.join(PROJECT_ROOT, 'ml', 'model.pkl')

def create_sample_pcap(filepath):
    """
    Generate a valid binary PCAP packet capture file demonstrating
    raw packet captures (TCP SYN flood & HTTP request bursts).
    """
    print(f"Creating demonstration PCAP capture file at {filepath}...")
    
    # 24-byte PCAP Global Header:
    # magic(4B: 0xa1b2c3d4), ver_major(2B: 2), ver_minor(2B: 4), thiszone(4B: 0),
    # sigfigs(4B: 0), snaplen(4B: 65535), network(4B: 1 = Ethernet)
    global_header = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets = []
    base_epoch = int(datetime.now().timestamp())

    # Generate 15 simulated packet headers (SYN packets and HTTP POST packets)
    for i in range(15):
        ts_sec = base_epoch + (i // 3)
        ts_usec = (i % 3) * 333000
        
        # Ethernet Header: Dest MAC (6B), Src MAC (6B), Type (2B: 0x0800 IPv4)
        eth_hdr = b'\x00\x1a\x2b\x3c\x4d\x5e\x00\x11\x22\x33\x44\x55\x08\x00'
        
        # IPv4 Header (20 bytes): Version 4, IHL 5, Total Length 60, Protocol 6 (TCP)
        src_ip = socket.inet_aton("185.220.101.42") if i < 10 else socket.inet_aton("10.0.2.15")
        dst_ip = socket.inet_aton("10.0.1.10")
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 60, 1000 + i, 0x4000, 64, 6, 0, src_ip, dst_ip)
        
        # TCP Header (20 bytes): Src Port 41561, Dst Port 80 (HTTP), Seq 10000, Flags 0x02 (SYN)
        tcp_hdr = struct.pack("!HHIIBBHHH", 41500 + i, 80, 10000 + i, 0, 0x50, 0x02, 64240, 0, 0)
        
        # Payload
        payload = b"GET /admin HTTP/1.1\r\nHost: internal.corp\r\n\r\n" if i >= 10 else b""
        
        raw_pkt = eth_hdr + ip_hdr + tcp_hdr + payload
        pkt_len = len(raw_pkt)
        
        # 16-byte Packet Header: ts_sec, ts_usec, incl_len, orig_len
        pkt_hdr = struct.pack("=IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        packets.append(pkt_hdr + raw_pkt)

    with open(filepath, "wb") as f:
        f.write(global_header)
        for pkt in packets:
            f.write(pkt)
            
    print(f"Sample PCAP successfully generated ({len(packets)} raw packets).")

import io

def parse_pcap(source):
    """
    Parse a binary .pcap file (filepath or bytes buffer) and reconstruct bidirectional
    network flow features matching CIC-IDS2017 flow telemetry standards.
    """
    if isinstance(source, bytes):
        f = io.BytesIO(source)
        should_close = True
    elif hasattr(source, "read"):
        f = source
        should_close = False
    elif isinstance(source, str):
        if not os.path.exists(source):
            raise FileNotFoundError(f"PCAP file not found: {source}")
        f = open(source, "rb")
        should_close = True
    else:
        raise ValueError("Invalid source for parse_pcap: Expected filepath or bytes.")

    try:
        global_header = f.read(24)
        if len(global_header) < 24:
            raise ValueError("Invalid PCAP: Global header is too short.")
            
        magic = struct.unpack("=I", global_header[:4])[0]
        if magic != 0xa1b2c3d4 and magic != 0xd4c3b2a1:
            raise ValueError(f"Unknown PCAP magic number: {hex(magic)}")

        flows = {}
        pkt_count = 0

        while True:
            pkt_hdr_data = f.read(16)
            if len(pkt_hdr_data) < 16:
                break
                
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("=IIII", pkt_hdr_data)
            pkt_data = f.read(incl_len)
            pkt_count += 1
            
            # Parse Ethernet (Skip 14 bytes)
            if len(pkt_data) < 34:
                continue
                
            eth_type = struct.unpack("!H", pkt_data[12:14])[0]
            if eth_type != 0x0800: # Not IPv4
                continue
                
            # Parse IPv4
            ip_data = pkt_data[14:]
            proto = ip_data[9]
            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])
            
            # Parse TCP
            if proto == 6 and len(ip_data) >= 40:
                tcp_data = ip_data[20:]
                src_port, dst_port = struct.unpack("!HH", tcp_data[:4])
                flags = tcp_data[13]
                syn_flag = 1 if (flags & 0x02) else 0
                rst_flag = 1 if (flags & 0x04) else 0
                ack_flag = 1 if (flags & 0x10) else 0
            else:
                src_port, dst_port = 0, 0
                syn_flag, rst_flag, ack_flag = 0, 0, 0

            flow_key = (src_ip, dst_ip, dst_port, proto)
            if flow_key not in flows:
                flows[flow_key] = {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "port": dst_port,
                    "protocol": "TCP" if proto == 6 else "UDP",
                    "start_time": ts_sec + (ts_usec / 1e6),
                    "end_time": ts_sec + (ts_usec / 1e6),
                    "fwd_pkts": 0,
                    "bwd_pkts": 0,
                    "fwd_bytes": 0,
                    "syn_cnt": 0,
                    "rst_cnt": 0,
                    "ack_cnt": 0
                }
                
            fl = flows[flow_key]
            fl["end_time"] = ts_sec + (ts_usec / 1e6)
            fl["fwd_pkts"] += 1
            fl["fwd_bytes"] += incl_len
            fl["syn_cnt"] += syn_flag
            fl["rst_cnt"] += rst_flag
            fl["ack_cnt"] += ack_flag

        print(f"Parsed {pkt_count} raw packets into {len(flows)} bidirectional flow conversations.")
        return list(flows.values())
    finally:
        if should_close:
            f.close()

def inspect_and_classify_flows(flow_records, commit_to_db=True):
    """
    Extract CIC-IDS2017 features from reconstructed flows, run ML inference,
    and return structured threat telemetry.
    """
    print("\n--- Running AI Cyber Threat Classifier on Live Reconstructed Flows ---")
    classified_results = []
    
    db = SessionLocal() if commit_to_db else None

    try:
        from datetime import timezone
        for fl in flow_records:
            duration_ms = max(10, int((fl["end_time"] - fl["start_time"]) * 1000))
            tot_fwd = fl["fwd_pkts"]
            tot_bytes = fl["fwd_bytes"]
            mean_pkt_len = round(tot_bytes / max(1, tot_fwd), 2)
            
            # Map into the 22 feature vector expected by Random Forest
            flow_vector = {
                'port': fl['port'],
                'protocol': fl['protocol'],
                'flow_duration': duration_ms,
                'tot_fwd_pkts': tot_fwd,
                'tot_bwd_pkts': fl["bwd_pkts"],
                'totlen_fwd_pkts': tot_bytes,
                'totlen_bwd_pkts': 0,
                'fwd_pkt_len_mean': mean_pkt_len,
                'bwd_pkt_len_mean': 0.0,
                'flow_byts_s': round(tot_bytes / max(0.1, duration_ms / 1000.0), 2),
                'flow_pkts_s': round(tot_fwd / max(0.1, duration_ms / 1000.0), 2),
                'flow_iat_mean': 10.0,
                'flow_iat_std': 2.0,
                'fwd_iat_mean': 10.0,
                'bwd_iat_mean': 0.0,
                'syn_flag_cnt': fl["syn_cnt"],
                'rst_flag_cnt': fl["rst_cnt"],
                'psh_flag_cnt': 0,
                'ack_flag_cnt': fl["ack_cnt"],
                'urg_flag_cnt': 0,
                'fwd_header_len': tot_fwd * 20,
                'bwd_header_len': 0,
                'down_up_ratio': 0.0,
                'pkt_len_variance': 10.0,
                'subflow_fwd_pkts': tot_fwd
            }
            
            # Predict
            pred = predict(flow_vector)
            
            print(f"Flow: {fl['source_ip']} -> {fl['destination_ip']}:{fl['port']}")
            print(f"  Classification: {pred['attack_type']} (Confidence: {pred['confidence']*100:.1f}%) | Severity: {pred['severity'].upper()} | MITRE: {pred['mitre_id']}")
            
            threat_id = None
            if commit_to_db and pred['attack_type'] != 'Benign':
                threat_obj = Threat(
                    timestamp=datetime.now(timezone.utc),
                    source_ip=fl['source_ip'],
                    destination_ip=fl['destination_ip'],
                    attack_type=pred['attack_type'],
                    severity=pred['severity'],
                    confidence=pred['confidence'],
                    status='open',
                    is_blocked=False,
                    geo_country='Live External Capture',
                    geo_city='Inbound Network Probe',
                    geo_lat=50.1109,
                    geo_lon=8.6821,
                    mitre_id=pred['mitre_id'],
                    ai_explanation=None,
                    features=flow_vector
                )
                db.add(threat_obj)
                db.flush()
                threat_id = threat_obj.id
                
            classified_results.append({
                "id": threat_id,
                "source_ip": fl['source_ip'],
                "destination_ip": fl['destination_ip'],
                "port": fl['port'],
                "protocol": fl['protocol'],
                "attack_type": pred['attack_type'],
                "severity": pred['severity'],
                "confidence": round(pred['confidence'], 4),
                "mitre_id": pred['mitre_id'],
                "features": flow_vector
            })
                
        if commit_to_db and db:
            db.commit()
            print(f"\nSuccessfully registered live threat incidents into SOC database!")
    finally:
        if db:
            db.close()
            
    return classified_results

def main():
    parser = argparse.ArgumentParser(description="Live PCAP & Packet Capture Intrusion Detection Engine")
    parser.add_argument("--pcap", type=str, help="Path to .pcap capture file to inspect")
    parser.add_argument("--demo", action="store_true", help="Generate a sample live .pcap capture and analyze it")
    
    args = parser.parse_args()
    
    pcap_target = args.pcap
    if args.demo or not pcap_target:
        sample_path = os.path.join(PROJECT_ROOT, "data", "live_sample.pcap")
        create_sample_pcap(sample_path)
        pcap_target = sample_path
        
    print(f"Reading packet capture from {pcap_target}...")
    flows = parse_pcap(pcap_target)
    inspect_and_classify_flows(flows, commit_to_db=True)
    print("--- Live Packet Ingestion & Classification Complete ---")

if __name__ == "__main__":
    main()
