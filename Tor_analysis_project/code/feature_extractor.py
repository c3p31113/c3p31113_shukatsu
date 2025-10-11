from scapy.all import rdpcap, TCP, IP
import pandas as pd
import sys
import os

def extract_features(pcap_file, local_ip="192.168.202.136"):
    """pcapファイルから特徴量を抽出し、CSVとして保存する関数"""

    print(f"[*] Processing {pcap_file}...")

    # pcapファイルを読み込む
    packets = rdpcap(pcap_file)

    feature_list = []

    for pkt in packets:
        # IP層とTCP層を持つパケットのみを対象とする
        if IP in pkt and TCP in pkt:
            ip_layer = pkt[IP]

            # 特徴量を抽出
            timestamp = float(pkt.time)
            packet_length = len(pkt)

            # 通信方向を判定 (ローカルIPを基準に)
            if ip_layer.src == local_ip:
                direction = "outgoing" # 送信
            else:
                direction = "incoming" # 受信

            feature_list.append({
                "timestamp": timestamp,
                "length": packet_length,
                "direction": direction,
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst
            })

    if not feature_list:
        print("[-] No TCP/IP packets found.")
        return

    # PandasのDataFrameに変換
    df = pd.DataFrame(feature_list)

    # 最初のパケットのタイムスタンプを基準に、相対時間を計算
    df['relative_time'] = df['timestamp'] - df['timestamp'].iloc[0]

    # CSVファイルとして保存
    output_filename = os.path.splitext(pcap_file)[0] + ".csv"
    df.to_csv(output_filename, index=False)

    print(f"[+] Features extracted and saved to {output_filename}")


# --- メイン処理 ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 feature_extractor.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]

    # 先生の環境のローカルIPアドレス（WSL2のIP）を指定
    # tsharkの結果から '192.168.202.136' であることを確認済み
    MY_LOCAL_IP = "192.168.202.136"

    extract_features(pcap_file_path, local_ip=MY_LOCAL_IP)
