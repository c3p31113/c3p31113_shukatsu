import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt
import os

def train_and_evaluate_final(dataset_path):
    print(f"[*] Loading advanced dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("[*] Training FINAL RandomForest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    print("[*] Evaluating FINAL model...")
    y_pred = model.predict(X_test)
    
    print("\n--- FINAL Model Evaluation Results ---")
    accuracy = accuracy_score(y_test, y_pred)
    print(f"✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'C2']))
    
    print("\n🔠 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Predicted Normal', 'Predicted C2'], 
                yticklabels=['Actual Normal', 'Actual C2'])
    plt.title('FINAL Confusion Matrix (Advanced Features)')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    
    output_filename = os.path.join(os.path.dirname(dataset_path), "confusion_matrix_final.png")
    plt.savefig(output_filename)
    print(f"\n[+] FINAL confusion matrix saved to {output_filename}")

if __name__ == "__main__":
    DATASET_FILE = os.path.join("data", "ml_dataset_advanced.csv")
    train_and_evaluate_final(DATASET_FILE)
