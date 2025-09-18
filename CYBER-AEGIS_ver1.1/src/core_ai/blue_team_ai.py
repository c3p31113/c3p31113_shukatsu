# src/core_ai/blue_team_ai.py
import re
import json
from .ollama_manager import OllamaManager
from src.tools.google_search import search as google_search

class BlueTeamAI:
    def __init__(self, fast_mode=False):
        self.ollama = OllamaManager()
        self.model = "gemma3:latest"
        self.fast_mode = fast_mode

    def _sanitize_and_load_json(self, raw_text):
        """
        AIが生成するあらゆるJSONフォーマットの揺れを吸収する、最終バージョンのサニタイズ関数。
        """
        try:
            # 最も外側にある '{' と '}' を探し、その中身だけを抽出する最も堅牢な方法
            start = raw_text.find('{')
            end = raw_text.rfind('}')
            if start == -1 or end == -1 or end < start:
                raise ValueError("AI response does not contain a valid JSON object structure.")
            
            json_str = raw_text[start:end+1]

            # 末尾の余分なカンマを削除する（JSON5に近い挙動を許容）
            json_str = re.sub(r',\s*([\}\]])', r'\1', json_str)
            
            return json.loads(json_str)
        except Exception as e:
            print(f"Error: AI JSON response sanitization or parsing failed. Error: {e}, Response: {raw_text}")
            return {"error": "JSON Sanitize/Parse Failed", "raw_response": raw_text}

    def _think(self, prompt):
        response_str = self.ollama.generate(self.model, prompt)
        json_data = self._sanitize_and_load_json(response_str)
        reasoning = response_str.split('{')[0].strip()
        json_data['reasoning'] = reasoning
        return json_data

    # ... (_phase1_detection_and_query, _phase2_response, generate_defense_action は変更なし) ...
    def _phase1_detection_and_query(self, arena_logs):
        print("🔵 Blue Team AI [Phase 1/2]: Threat Detection...")
        prompt = f"""
        あなたはEDRのアナリストです。以下のイベントログを分析し、最も注意すべき不審な活動を1つ特定し、調査クエリを生成してください。
        【入力イベントログ】
        {arena_logs}
        【思考の証跡】
        あなたの思考プロセスを簡潔に記述してください。
        【絶対厳守ルール】
        - **上記ログに記録されたイベントのみを分析の根拠とすること。ログにない事象を推測したり創作したりしてはならない。**
        - **JSON内のWindowsパスでは、バックスラッシュ（`\\`）を二重（`\\\\`）にエスケープすること。**
        - **ファイルパスは、必ずドライブ文字（例: `C:`）から始まる完全な形式で記述すること。**
        【出力フォーマット】
        ```json
        {{
          "detected_threat": "（例: 新しいファイル 'exploit.exe' が 'C:\\\\Users\\\\...\\\\exploit.exe' に作成された）",
          "google_search_query": "（例: what is exploit.exe malware）"
        }}
        ```
        """
        return self._think(prompt)

    def _phase2_response(self, threat_summary, search_results_text, arena_logs):
        print("🔵 Blue Team AI [Phase 2/2]: Response Decision...")
        prompt = f"""
        あなたはインシデント対応の責任者です。以下の情報を基に、脅威を無力化するための最適なアクションを1つだけ決定し、**ただ一つのJSONオブジェクト**として出力してください。
        【状況】
        - **検知した脅威:** {threat_summary}
        - **Google検索による調査結果:** {search_results_text if search_results_text else "追加情報なし"}
        - **参照すべきイベントログ:**
        {arena_logs}
        【思考の証跡】
        あなたの思考プロセスを簡潔に記述してください。
        【絶対厳守ルール】
        - **ログに記録された事実のみに基づいてアクションを決定すること。ログにない事象を推測したり創作したりしてはならない。**
        - `action`が`terminate_process`の場合、`parameters`のキーは**必ず`"pid"`**とし、値はログから抽出した**整数（integer）**とすること。
        - `action`が`quarantine_file`の場合、`parameters`のキーは**必ず`"filepath"`**とし、値はログから抽出した**ドライブ文字を含む完全なファイルパス**とすること。
        - **JSON内のWindowsパスでは、バックスラッシュ（`\\`）を二重（`\\\\`）にエスケープすること。**
        - **解説や例を含めず、最終的なアクションを指示するJSONオブジェクトのみを厳密に出力すること。**

        【出力フォーマット例】
        - ファイルを隔離する場合:
        ```json
        {{
          "action": "quarantine_file",
          "parameters": {{
            "filepath": "C:\\\\Users\\\\tanaka\\\\Downloads\\\\exploit.exe"
          }}
        }}
        ```
        - プロセスを停止する場合:
        ```json
        {{
          "action": "terminate_process",
          "parameters": {{
            "pid": 1000
          }}
        }}
        ```
        """
        return self._think(prompt)

    def generate_defense_action(self, arena_logs):
        threat_indicators = ["PROCESS_CREATE_SUCCESS", "FILE_CREATE_SUCCESS"]
        if not any(indicator in arena_logs for indicator in threat_indicators):
            return {"action": "no_action", "parameters": {}}

        detection_result = self._phase1_detection_and_query(arena_logs)
        search_results_text = ""
        if detection_result and detection_result.get("google_search_query"):
            query = detection_result["google_search_query"]
            try:
                search_results = google_search(queries=[query])
                if search_results and search_results[0].results:
                    for r in search_results[0].results[:2]:
                        search_results_text += f"- {r.source_title}: {r.snippet}\\n"
            except Exception as e:
                search_results_text = f"Google検索エラー: {e}"
        
        threat_summary = detection_result.get("detected_threat", "N/A") if detection_result else "N/A"
        final_action = self._phase2_response(threat_summary, search_results_text, arena_logs)
        
        return final_action if final_action else {"action": "no_action", "parameters": {}}