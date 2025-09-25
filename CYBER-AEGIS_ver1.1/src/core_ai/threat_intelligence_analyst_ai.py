# src/core_ai/threat_intelligence_analyst_ai.py
from .ollama_manager import OllamaManager
from src.tools import google_search
import json
import re

class ThreatIntelligenceAnalystAI:
    def __init__(self):
        self.ollama = OllamaManager()
        self.model = "gemma3:latest"

    def _sanitize_and_load_json(self, raw_text):
        try:
            # ★★★ 修正点：リスト形式のJSONにも対応 ★★★
            # まず、最も外側にある '[' と ']' または '{' と '}' を探す
            start_brace = raw_text.find('{')
            start_bracket = raw_text.find('[')
            
            # 先に見つかった方を開始点とする
            if start_brace != -1 and (start_bracket == -1 or start_brace < start_bracket):
                start = start_brace
                end = raw_text.rfind('}')
            elif start_bracket != -1:
                start = start_bracket
                end = raw_text.rfind(']')
            else:
                raise ValueError("No JSON object or array found")

            if start == -1 or end == -1 or end < start:
                raise ValueError("Invalid JSON/Array structure")
            
            json_str = raw_text[start:end+1]
            json_str = re.sub(r',\s*([\}\]])', r'\1', json_str)
            return json.loads(json_str)
        except Exception as e:
            print(f"Error: Analyst AI JSON response parsing failed. Error: {e}")
            return None

    def research_and_build_profile(self, software_list):
        if not software_list:
            software_list = [{"name": "Windows Defender"}]

        software_names = ", ".join([s.get("name", "Unknown") for s in software_list])
        print(f"  [Analyst AI] Starting research for: {software_names}...")

        query_prompt = f"""
        あなたは、サイバー脅威インテリジェンスの専門家です。以下のセキュリティ製品について、その防御能力を評価するためのGoogle検索クエリを3つ生成してください。
        特に、PowerShell攻撃や署名のない実行ファイルのダウンロードに対する振る舞いに焦点を当ててください。
        対象製品: {software_names}
        厳守ルール：出力は["query1", "query2", ...]というJSONリスト形式のみで回答すること。
        """
        
        response_str = self.ollama.generate(self.model, query_prompt)
        queries = self._sanitize_and_load_json(response_str)

        if not isinstance(queries, list):
            print("  [Analyst AI] Failed to generate search queries, using fallback.")
            queries = [f"{software_names} review"]

        print(f"  [Analyst AI] Executing Google searches...")
        search_results = google_search.search(queries=queries)
        
        evidence_text = ""
        for result in search_results:
            if result.results:
                for item in result.results:
                    evidence_text += f"Source: {item.source_title}\nSnippet: {item.snippet}\n\n"
        
        if not evidence_text:
            evidence_text = "No specific data found. Please rely on general knowledge."

        print(f"  [Analyst AI] Building rulebook based on research evidence...")
        rule_prompt = f"""
        あなたは、サイバー脅威インテリジェンスの専門家です。以下の調査結果（エビデンス）を基に、セキュリティ製品「{software_names}」の振る舞いをモデル化する「レベル2」の防御ルールブックを生成してください。
        【調査結果（エビデンス）】
        {evidence_text}
        【思考プロセス】
        1. 調査結果を読み解き、PowerShellや署名のない.exeファイルに対する防御能力を評価する。
        2. 「alert」（警告）または「block」（ブロック）というアクションを決定する。
        3. 調査結果から、そのアクションの成功確率を推定し、「confidence」（0.0～1.0）として数値化する。
        4. 発動条件（trigger）を定義する。
        5. 最終的な結果を、厳密なJSON形式で出力する。
        【出力フォーマット例】
        ```json
        {{
            "name": "{software_names}",
            "rules": [
                {{
                    "action": "alert",
                    "trigger_process": "powershell.exe",
                    "confidence": 0.85,
                    "source": "AV-Comparatives report showed 85% detection for fileless threats."
                }}
            ]
        }}
        ```
        """
        final_response_str = self.ollama.generate(self.model, rule_prompt)
        final_profile = self._sanitize_and_load_json(final_response_str)

        if not final_profile:
             print("  [Analyst AI] Failed to generate profile, using fallback.")
             return {"name": software_names, "rules": [{"action": "alert", "trigger_process": "powershell.exe", "confidence": 0.75, "source": "Fallback Rule"}]}

        print(f"  [Analyst AI] Research complete. Profile for '{final_profile.get('name')}' built successfully.")
        return final_profile
