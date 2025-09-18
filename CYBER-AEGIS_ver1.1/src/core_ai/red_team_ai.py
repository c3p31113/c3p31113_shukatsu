# src/core_ai/red_team_ai.py
import re
import json
from .ollama_manager import OllamaManager
from src.tools.google_search import search as google_search

class RedTeamAI:
    def __init__(self, fast_mode=False):
        self.ollama = OllamaManager()
        self.model = "gemma3:latest"
        self.fast_mode = fast_mode

    def _sanitize_and_load_json(self, raw_text):
        """
        優秀なAIの分析に基づき、AIの応答をサニタイズし、JSONとして読み込む。
        """
        try:
            match = re.search(r'\{[\s\S]*\}', raw_text)
            if not match:
                # JSONが見つからない場合、思考の証跡だけを含むエラーJSONを返す
                return {"error": "JSON Object Not Found", "reasoning": raw_text}
            json_str = match.group(0)
            # 不正なバックスラッシュを強制的にエスケープ
            json_str = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r'\\\\', json_str)
            # 制御文字など、JSONに不要な文字を削除
            json_str = ''.join(c for c in json_str if c.isprintable() or c in '\n\r\t')
            # 稀に発生する末尾のカンマに対応
            json_str = re.sub(r',\s*\}', '}', json_str)
            json_str = re.sub(r',\s*\]', ']', json_str)
            return json.loads(json_str)
        except Exception as e:
            print(f"Error: AIのJSON応答のサニタイズまたは解析に失敗しました。エラー: {e}, 応答: {raw_text}")
            return {"error": "JSON Sanitize/Parse Failed", "raw_response": raw_text}

    def _think(self, prompt):
        response_str = self.ollama.generate(self.model, prompt)
        json_data = self._sanitize_and_load_json(response_str)
        
        reasoning = response_str.split('{')[0].strip()
        json_data['reasoning'] = reasoning
        return json_data

    def run_reconnaissance(self, current_arena_state, action_history):
        print("🔴 Red Team AI [Kill Chain 1/7]: Reconnaissance...")
        prompt = f"""
        あなたはRed Teamの偵察担当です。以下の情報を分析し、攻撃の足がかりとなる最も重要な情報をJSON形式で要約してください。
        【入力情報】
        - アリーナの状態: {current_arena_state}
        - これまでの行動サマリー: {action_history if action_history else "まだ行動していない。"}
        【思考の証跡】
        あなたの思考プロセスを簡潔に記述してください。
        【出力フォーマット】
        ```json
        {{
          "vulnerable_software": "（例: Example Vulnerable App 1.2.3）",
          "last_action_failed": "（true または false）",
          "failure_reason": "（失敗した場合の原因を簡潔に記述）",
          "summary": "（「Example Appが脆弱。前回の配送はBlue Teamに隔離され失敗」のような、状況の要約）"
        }}
        ```
        """
        return self._think(prompt)

    def run_weaponization(self, recon_results):
        print("🔴 Red Team AI [Kill Chain 2/7]: Weaponization...")
        vulnerable_software = recon_results.get("vulnerable_software", "N/A")
        prompt = f"""
        あなたはRed Teamの兵器開発担当です。偵察結果に基づき、攻撃計画を立案し、そのために必要な情報を収集するためのGoogle検索クエリを生成してください。
        【偵察結果】
        - 注目すべき脆弱なソフトウェア: {vulnerable_software}
        - 状況サマリー: {recon_results.get("summary")}
        【思考の証跡】
        あなたの思考プロセスを簡潔に記述してください。
        【出力フォーマット】
        ```json
        {{
          "hypothesis": "（例: Example App 1.2.3のリモートコード実行脆弱性を悪用する）",
          "google_search_query": "（例: Example App 1.2.3 RCE exploit PoC）"
        }}
        ```
        """
        weaponization_plan = self._think(prompt)
        
        search_results_text = "N/A"
        if weaponization_plan and weaponization_plan.get("google_search_query"):
            query = weaponization_plan["google_search_query"]
            try:
                search_results = google_search(queries=[query])
                if search_results and search_results[0].results:
                    search_results_text = ""
                    for r in search_results[0].results[:2]:
                        search_results_text += f"- Title: {r.source_title}\\nSnippet: {r.snippet}\\n"
            except Exception as e:
                search_results_text = f"Google検索エラー: {e}"
        
        weaponization_plan['search_results'] = search_results_text
        return weaponization_plan

    def run_delivery(self, arena_filesystem, recon_results, weaponization_results):
        print("🔴 Red Team AI [Kill Chain 3/7]: Delivery...")
        # ★★★ 核心的な修正点 ★★★
        prompt = f"""
        あなたはRed Teamの輸送担当です。以下の情報を基に、開発した武器をターゲットに送り込むための戦術を決定してください。
        【書き込み可能な実在ディレクトリ】
        {json.dumps(arena_filesystem, indent=2, ensure_ascii=False)}
        【武器化レポート】
        - 仮説: {weaponization_results.get("hypothesis")}
        【思考の証跡】
        ステップ1: 上記の「書き込み可能な実在ディレクトリ」リストの中から、武器を隠すのに最も適した場所を1つ選び、その理由を記述せよ。
        ステップ2: ステップ1で選んだパスを使い、最終的なJSONコマンドを作成せよ。
        【絶対厳守ルール】
        - `destination`のパスは、必ず上記の「書き込み可能な実在ディレクトリ」リストの中から選ぶこと。
        - **リストにないパスを絶対に発明してはならない。**
        - **ファイルパスは、必ずドライブ文字（例: `C:`）から始まる完全な形式で記述すること。**
        - 配送するファイル名は`exploit.exe`とすること。
        - **JSON内のWindowsパスでは、バックスラッシュ（`\\`）を二重（`\\\\`）にエスケープすること。**
        【出力フォーマット】
        ```json
        {{
          "tactic": "T1105",
          "parameters": {{
            "url": "（考案したURL）",
            "destination": "（**リスト内から選んだ実在パス**\\\\exploit.exe）"
          }}
        }}
        ```
        """
        return self._think(prompt)
    
    def run_exploitation(self, weapon_path):
        print("🔴 Red Team AI [Kill Chain 4/7]: Exploitation...")
        # ★★★ 核心的な修正点 ★★★
        prompt = f"""
        あなたはRed Teamの実行担当です。配送に成功した武器を実行し、ターゲットシステムに侵入してください。
        【配送された武器】
        - ファイルパス: {weapon_path}
        【思考の証跡】
        あなたの思考プロセスを簡潔に記述してください。
        【絶対厳守ルール】
        - `script_path`には、上記ファイルパスを正確に指定する。
        - **ファイルパスは、必ずドライブ文字（例: `C:`）から始まる完全な形式で記述すること。**
        - **JSON内のWindowsパスでは、バックスラッシュ（`\\`）を二重（`\\\\`）にエスケープすること。**
        【出力フォーマット】
        ```json
        {{
          "tactic": "T1059",
          "parameters": {{
            "script_path": "{weapon_path.replace('\\', '\\\\')}"
          }}
        }}
        ```
        """
        return self._think(prompt)