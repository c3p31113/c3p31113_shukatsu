import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt
import os

def train_and_evaluate(dataset_path):
    """データセットを読み込み、モデルを訓練・評価する関数"""
    
    print("[*] Loading dataset...")
    df = pd.read_csv(dataset_path)
    
    # 特徴量 (X) と ラベル (y) に分割
    # X: 学習に使うデータ (時間, パケット長など)
    # y: 正解ラベル (0 or 1)
    X = df.drop('label', axis=1)
    y = df['label']
    
    # データを訓練用とテスト用に分割 (80%を訓練に、20%をテストに)
    # random_stateは再現性のために固定
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("[*] Training RandomForest model...")
    # ランダムフォレスト分類器を初期化して訓練
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    print("[*] Evaluating model...")
    # テストデータで予測を実行
    y_pred = model.predict(X_test)
    
    # --- 評価結果の表示 ---
    # 1. 正確度 (Accuracy)
    accuracy = accuracy_score(y_test, y_pred)
    print("\n--- Model Evaluation Results ---")
    print(f"✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # 2. 分類レポート (Classification Report)
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'C2']))
    
    # 3. 混同行列 (Confusion Matrix)
    print("\n🔠 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    # 混同行列をヒートマップとして可視化・保存
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Predicted Normal', 'Predicted C2'], 
                yticklabels=['Actual Normal', 'Actual C2'])
    plt.title('Confusion Matrix')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    
    output_filename = os.path.join(os.path.dirname(dataset_path), "confusion_matrix.png")
    plt.savefig(output_filename)
    print(f"\n[+] Confusion matrix visualization saved to {output_filename}")


# --- メイン処理 ---
if __name__ == "__main__":
    DATASET_FILE = os.path.join("data", "ml_dataset.csv")
    train_and_evaluate(DATASET_FILE)
