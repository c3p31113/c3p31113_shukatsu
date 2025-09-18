# src/core_ai/scenario_generator_ai.py
from .ollama_manager import OllamaManager
import json

class ScenarioGeneratorAI:
    def __init__(self):
        self.ollama = OllamaManager()
        self.model = "gemma3:latest"

    def generate_red_team_prompt(self, technique_id, technique_name, technique_desc, digital_twin_state):
        """
        ATT&CK技術とデジタルツインの状態から、Red Team用の具体的な攻撃プロンプトを生成する。
        """
        print(f"⚪️ Director AI: Generating scenario for ATT&CK Technique {technique_id} ({technique_name})...")
        
        # ★★★ 核心的な修正点：プロンプトをより強力で、手本を示す形式に変更 ★★★
        prompt = f"""
        あなたはRed Teamの作戦を立案する、優秀なシナリオライターです。あなたの任務は、以下の技術情報とターゲット情報を解釈し、Red Team AIが実行すべき、創造的で具体的な「作戦命令書」を自然言語で作成することです。

        【INPUT 1: 攻撃技術情報】
        - ID: {technique_id}
        - 名称: {technique_name}
        - 説明: {technique_desc}

        【INPUT 2: ターゲット環境情報】
        {json.dumps(digital_twin_state, indent=2, ensure_ascii=False)}

        【思考プロセス】
        1. まず、INPUT 1の攻撃技術の目的を深く理解します。
        2. 次に、INPUT 2のターゲット環境の中に、その目的を達成するために利用できそうな要素（特定のフォルダパス、利用可能なコマンドなど）を見つけ出します。
        3. 最後に、それらを組み合わせて、Red Team AIが誤解しようのない、明確なステップバイステップの作戦命令を物語形式で記述します。

        【厳守ルール】
        - **INPUT 2の生データをそのまま出力してはいけません。必ずあなたの言葉で、新しい「作戦命令書」を生成してください。**
        - Red Team AIが最終的にJSON形式でコマンドを出力しやすいように、実行すべき具体的なコマンドの例を命令書に含めてください。

        【作戦命令書の出力例】
        ```
        Red Teamへ、新たな作戦命令を伝達する。

        **作戦名:** Silent Echo
        **目標:** ターゲットのローカルシステムから機密情報を収集する準備として、検知されずに情報を一時保管する（ATT&CK T1005）。

        **実行手順:**
        1. ターゲット環境の `C:\\Users\\tanaka\\AppData\\Local\\Temp` フォルダは、一時的なデータ退避場所として最適である。
        2. PowerShellを使用し、`Documents` フォルダ内に存在するファイルの一覧を取得し、その結果を `C:\\Users\\tanaka\\AppData\\Local\\Temp\\file_list.txt` という名前で出力せよ。
        3. この操作は、`powershell.exe -c "Get-ChildItem C:\\Users\\tanaka\\OneDrive\\ドキュメント > C:\\Users\\tanaka\\AppData\\Local\\Temp\\file_list.txt"` のようなコマンドで実現可能だ。

        健闘を祈る。
        ```

        【あなたの出力】
        """
        
        # このAIコールはプロンプトを生成するだけなので、サニタイズは不要
        return self.ollama.generate(self.model, prompt)