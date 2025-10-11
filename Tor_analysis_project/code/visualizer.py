import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os

def visualize_traffic(csv_file):
    """CSVデータを読み込み、トラフィックを可視化する関数"""
    
    print(f"[*] Visualizing {csv_file}...")
    
    df = pd.read_csv(csv_file)
    
    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax = plt.subplots(figsize=(15, 7))
    
    # 散布図を作成
    # x軸: 相対時間, y軸: パケット長, 色: 通信方向
    sns.scatterplot(data=df, x='relative_time', y='length', hue='direction', 
                    palette={'incoming': 'blue', 'outgoing': 'red'}, s=50, alpha=0.7, ax=ax)
    
    ax.set_title(f'Packet Traffic Pattern: {os.path.basename(csv_file)}', fontsize=16)
    ax.set_xlabel('Time (seconds)', fontsize=12)
    ax.set_ylabel('Packet Length (bytes)', fontsize=12)
    ax.legend(title='Direction')
    
    # PNGファイルとして保存
    output_filename = os.path.splitext(csv_file)[0] + ".png"
    plt.savefig(output_filename, dpi=300)
    
    print(f"[+] Graph saved to {output_filename}")
    # plt.show() # GUI環境で直接表示したい場合はこのコメントを外す

# --- メイン処理 ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 visualizer.py <path_to_csv_file>")
        sys.exit(1)
        
    csv_file_path = sys.argv[1]
    visualize_traffic(csv_file_path)
