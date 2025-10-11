import pandas as pd
import os

def prepare_dataset(normal_csv, c2_csv, output_file):
    """2つのCSVを読み込み、ラベルを付けて統合する関数"""
    
    print("[*] Loading datasets...")
    df_normal = pd.read_csv(normal_csv)
    df_c2 = pd.read_csv(c2_csv)
    
    # ラベル付け (0: normal, 1: C2)
    # これがモデルにとっての「正解」になります
    df_normal['label'] = 0
    df_c2['label'] = 1
    
    print("[*] Combining datasets...")
    # 2つのデータフレームを縦に結合
    combined_df = pd.concat([df_normal, df_c2], ignore_index=True)
    
    # 不要なカラムを削除（今回はシンプルにするため）
    combined_df = combined_df.drop(columns=['src_ip', 'dst_ip', 'timestamp'])
    
    # 簡単な特徴量を追加
    # パケットが送信か受信か (1 or 0)
    combined_df['is_outgoing'] = combined_df['direction'].apply(lambda x: 1 if x == 'outgoing' else 0)
    combined_df = combined_df.drop(columns=['direction'])
    
    # ファイルに保存
    combined_df.to_csv(output_file, index=False)
    print(f"[+] Combined and prepared dataset saved to {output_file}")

# --- メイン処理 ---
if __name__ == "__main__":
    DATA_DIR = "data"
    NORMAL_FILE = os.path.join(DATA_DIR, "normal_browsing_01.csv")
    C2_FILE = os.path.join(DATA_DIR, "c2_traffic_01.csv")
    OUTPUT_FILE = os.path.join(DATA_DIR, "ml_dataset.csv")
    
    prepare_dataset(NORMAL_FILE, C2_FILE, OUTPUT_FILE)
