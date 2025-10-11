import pandas as pd
import numpy as np
import os

def create_advanced_features(dataset_path, output_path, window_size=10):
    """
    タイムウィンドウを用いて高度な特徴量を生成する関数
    """
    print(f"[*] Loading dataset from {dataset_path}...")
    # is_outgoing列が読み込まれるように、元のml_dataset.csvを読み込む
    df_raw = pd.read_csv(os.path.join("data", "ml_dataset.csv"))

    # タイムスタンプを基準にソート
    df = df_raw.sort_values('relative_time').reset_index(drop=True)

    # タイムウィンドウのIDを各パケットに割り振る
    df['window_id'] = (df['relative_time'] // window_size).astype(int)

    # ウィンドウごとに集計するための準備
    grouped = df.groupby('window_id')
    
    advanced_features = []
    
    print(f"[*] Engineering features for each {window_size}s window...")
    for window_id, group in grouped:
        
        start_time = group['relative_time'].min()
        packet_count = len(group)
        if packet_count < 2:
            continue

        avg_packet_size = group['length'].mean()
        std_packet_size = group['length'].std()
        max_packet_size = group['length'].max()

        # ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼ 修正箇所 ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
        # 'direction'ではなく'is_outgoing'列を参照する
        outgoing_count = (group['is_outgoing'] == 1).sum()
        incoming_count = (group['is_outgoing'] == 0).sum()
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ 修正箇所 ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
        direction_ratio = outgoing_count / (incoming_count + 1e-6)

        inter_arrival_times = group['relative_time'].diff().dropna()
        avg_iat = inter_arrival_times.mean()
        std_iat = inter_arrival_times.std()
        
        label = group['label'].mode()[0]

        advanced_features.append({
            'start_time': start_time,
            'packet_count': packet_count,
            'avg_packet_size': avg_packet_size,
            'std_packet_size': std_packet_size,
            'max_packet_size': max_packet_size,
            'direction_ratio': direction_ratio,
            'avg_iat': avg_iat,
            'std_iat': std_iat,
            'label': label
        })
    
    final_df = pd.DataFrame(advanced_features)
    final_df = final_df.fillna(0)

    final_df.to_csv(output_path, index=False)
    print(f"[+] Advanced feature dataset saved to {output_path}")

# --- メイン処理 ---
if __name__ == "__main__":
    INPUT_DATASET = os.path.join("data", "ml_dataset.csv")
    OUTPUT_DATASET = os.path.join("data", "ml_dataset_advanced.csv")
    
    create_advanced_features(INPUT_DATASET, OUTPUT_DATASET)
