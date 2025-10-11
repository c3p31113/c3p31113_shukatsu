import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import shap
import matplotlib.pyplot as plt
import os

def analyze_model_with_shap(dataset_path):
    """モデルを訓練し、SHAPで分析する関数（修正版）"""
    
    print("[*] Loading dataset and training model...")
    df = pd.read_csv(dataset_path)
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    print("[*] Calculating SHAP values...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer(X_test) # ここでSHAP値を計算

    # --- SHAPプロットの作成と保存（モダンな方法） ---
    
    # 1. 特徴量の重要度プロット (Bar Chart)
    # shap_values[:,:,1] は、ラベル'1' (C2) に対する貢献度を示す
    plt.figure()
    shap.plots.bar(shap_values[:,:,1], show=False)
    bar_plot_path = os.path.join(os.path.dirname(dataset_path), "shap_summary_bar.png")
    plt.savefig(bar_plot_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"[+] Feature importance bar plot saved to {bar_plot_path}")

    # 2. 詳細なサマリープロット (Beeswarm Plot)
    plt.figure()
    shap.plots.beeswarm(shap_values[:,:,1], show=False)
    beeswarm_plot_path = os.path.join(os.path.dirname(dataset_path), "shap_summary_beeswarm.png")
    plt.savefig(beeswarm_plot_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"[+] SHAP beeswarm plot saved to {beeswarm_plot_path}")

# --- メイン処理 ---
if __name__ == "__main__":
    DATASET_FILE = os.path.join("data", "ml_dataset.csv")
    analyze_model_with_shap(DATASET_FILE)
