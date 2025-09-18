# src/core/intelligence_manager.py

import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from src.core_ai.ollama_manager import OllamaManager
from src.threat_intel.orion_investigator import OrionInvestigator
from src.utils.config_manager import ConfigManager
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

class IntelligenceManager:
    def __init__(self):
        self.config = ConfigManager()
        self.model_name = self.config.get('AI', 'model', fallback='gemma3:latest')
        self.ai_manager = OllamaManager(model=self.model_name)
        self.orion = OrionInvestigator()
        self.google_api_key = self.config.get('API_KEYS', 'google_api_key', fallback=None)
        self.cse_id = self.config.get('API_KEYS', 'google_cse_id', fallback=None)

        if self.google_api_key and self.cse_id:
            try:
                self.search_service = build("customsearch", "v1", developerKey=self.google_api_key)
            except Exception as e:
                self.search_service = None
                print(f"[IntelligenceManager] Google Searchサービスの初期化エラー: {e}")
        else:
            self.search_service = None
            print("[IntelligenceManager] 警告: Google Custom SearchのAPIキーまたはエンジンIDが設定されていません。")
            
        self.ip_regex = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
        self.domain_regex = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+)')
        self.email_regex = re.compile(r'[\w\.-]+@[\w\.-]+')
        self.product_regex = re.compile(r'([A-Z][a-zA-Z0-9]+(?:\s[A-Z][a-zA-Z0-9]+)*)')

    def _investigate_targets_parallel(self, targets):
        all_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_info = {}

            for ip in targets.get("ips", []):
                full_url = f"http://{ip}/"
                tasks = {
                    "VirusTotal": executor.submit(self.orion.check_virustotal_ip, ip),
                    "DNSBL": executor.submit(self.orion.check_dnsbl, ip),
                    "Google Safe Browsing": executor.submit(self.orion.check_google_safeBrowse, full_url),
                    "abuse.ch": executor.submit(self.orion.check_abusech, ip, full_url),
                    "AlienVault OTX": executor.submit(self.orion.check_otx, ip, 'IPv4'),
                    "Shodan": executor.submit(self.orion.check_shodan, ip),
                    "Insecam": executor.submit(self.orion.check_insecam, ip),
                    "GreyNoise": executor.submit(self.orion.check_greynoise, ip),
                    "MISP": executor.submit(self.orion.check_misp, ip),
                    "IPQualityScore": executor.submit(self.orion.check_ipqs, ip),
                    "STIX/TAXII Feeds": executor.submit(self.orion.check_taxii_feeds, ip),
                    "Cisco Talos": executor.submit(self.orion.check_talos, ip),
                    "IntelX": executor.submit(self.orion.check_intelx, ip)
                }
                for name, future in tasks.items():
                    future_to_info[future] = (f"IP: {ip}", name)

            for domain in targets.get("domains", []):
                full_url = f"http://{domain}/"
                tasks = {
                    "WHOIS": executor.submit(self.orion.get_whois_info, domain),
                    "Google Safe Browsing": executor.submit(self.orion.check_google_safeBrowse, full_url),
                    "abuse.ch": executor.submit(self.orion.check_abusech, domain, full_url),
                    "AlienVault OTX": executor.submit(self.orion.check_otx, domain, 'domain'),
                    "MISP": executor.submit(self.orion.check_misp, domain),
                    "STIX/TAXII Feeds": executor.submit(self.orion.check_taxii_feeds, domain),
                    "IntelX": executor.submit(self.orion.check_intelx, domain)
                }
                for name, future in tasks.items():
                    future_to_info[future] = (f"Domain: {domain}", name)

            for product in targets.get("products", []):
                tasks = {"CISA KEV": executor.submit(self.orion.check_cisa_kev, product)}
                for name, future in tasks.items():
                    future_to_info[future] = (f"Product: {product}", name)

            for email in targets.get("emails", []):
                tasks = {"HaveIBeenPwned": executor.submit(self.orion.hibp_checker.check_email, email)}
                for name, future in tasks.items():
                    future_to_info[future] = (f"Email: {email}", name)

            for future in as_completed(future_to_info):
                target_id, check_name = future_to_info[future]
                if target_id not in all_results:
                    all_results[target_id] = {}
                try:
                    all_results[target_id][check_name] = future.result()
                except Exception as exc:
                    print(f'  > [ERROR] {target_id}の{check_name}調査で例外が発生: {exc}')
                    all_results[target_id][check_name] = {'error': str(exc)}
        
        return all_results
    
    def _is_password_query(self, query: str):
        password_keywords = ["password", "パスワード", "pass", "パス"]
        lower_query = query.lower()
        if any(keyword in lower_query for keyword in password_keywords):
            return True
        return False

    def _extract_password_with_ai(self, query: str):
        system_prompt = "あなたは、与えられた文章からパスワードとして調査すべき単語だけを抽出し、その単語のみを返す、最高のテキスト解析AIです。余計な言葉は一切返してはいけません。"
        prompt = f"""
        以下の文章から、漏洩調査の対象となるパスワード部分だけを抜き出して、その単語だけを返してください。
        文章: "{query}"
        抽出結果:
        """
        try:
            extracted = self.ai_manager.generate_response(prompt, system_prompt)
            cleaned = re.sub(r'["\'`「」]', '', extracted).strip()
            return cleaned
        except Exception as e:
            print(f"  > [ERROR] AIによるパスワード抽出中にエラーが発生: {e}")
            return None

    def _investigate_password(self, query: str):
        print("  > Password query detected. Engaging AI for extraction...")
        password_to_check = self._extract_password_with_ai(query)
        if not password_to_check:
            return "AIによるパスワードの抽出に失敗しました。お手数ですが、調査したいパスワードのみを入力して、再度お試しください。"
        print(f"  > [HIBP] AI extracted password for check: '{password_to_check}'")
        result = self.orion.check_pwned_password(password_to_check)
        if "error" in result:
            return f"エラーが発生しました: {result['error']}"
        elif result.get("status") == "PWNED":
            source = result.get("source", "不明なデータベース")
            details = result.get("details", "")
            return f"### 漏洩パスワード調査結果\n\n**警告:** パスワード「**{password_to_check}**」は、**{source}**で発見されました。\n\n**詳細:** {details}\n\n**直ちに使用を中止し、より強力なパスワードに変更することを強く推奨します。**"
        else:
            return f"### 漏洩パスワード調査結果\n\n**安全:** パスワード「**{password_to_check}**」は、我々のデータベース及び既知のデータ侵害では発見されませんでした。"

    def _is_geopolitical_query(self, query: str):
        geopolitical_keywords = ["geopolitical", "地政学", "国際情勢", "トレンド", "傾向", "ニュース", "gdelt"]
        lower_query = query.lower()
        if any(keyword in lower_query for keyword in geopolitical_keywords):
            return True
        return False

    def _investigate_geopolitical(self, query: str):
        print("  > Geopolitical query detected. Engaging GDELT Checker...")
        system_prompt = "あなたは、与えられた文章から、地政学的なニュースを検索するための、最も重要なキーワードを1〜3個抽出し、スペースで区切って返すAIです。"
        prompt = f"文章: 「{query}」\n\nキーワード:"
        keyword = self.ai_manager.generate_response(prompt, system_prompt).strip()
        if not keyword:
            return "分析すべきキーワードを特定できませんでした。"
        result = self.orion.get_geopolitical_news(keyword)
        if "error" in result:
            return f"GDELTの調査中にエラーが発生しました: {result['error']}"
        system_prompt_report = "あなたは、与えられた地政学ニュースのリストを分析し、サイバーセキュリティの専門家として、その背景にある脅威の可能性を簡潔に報告するAIアナリストです。"
        prompt_report = f"""
        以下の最新ニュースリストを分析し、ユーザーの質問「{query}」に対する、専門家としての考察を報告してください。

        # 最新ニュースリスト:
        {json.dumps(result, indent=2, ensure_ascii=False)}

        # 報告書:
        """
        return self.ai_manager.generate_response(prompt_report, system_prompt_report)

    def get_response(self, user_query):
        print(f"\n--- New Request ---\nUser Query: {user_query}")
        
        if self._is_password_query(user_query):
            return self._investigate_password(user_query)

        if self._is_geopolitical_query(user_query):
            return self._investigate_geopolitical(user_query)

        print("Stage 1: Extracting targets...")
        targets = {
            "ips": set(self.ip_regex.findall(user_query)),
            "domains": set(self.domain_regex.findall(user_query)) - set(self.ip_regex.findall(user_query)),
            "emails": set(self.email_regex.findall(user_query)),
            "products": set(self.product_regex.findall(user_query))
        }
        has_target = any(bool(v) for v in targets.values())
        
        if has_target:
            print(f"  > Targets detected. Starting parallel investigation...")
            internal_results = self._investigate_targets_parallel(targets)
            print(f"  > Internal investigation complete.")
            prompt = f"""
# あなたの思考プロセス
1.  **事実確認**: まず、以下の「内部調査結果」JSONを隅々まで読み、どの情報ソースから、どのような結果が得られたかを正確に把握せよ。エラーが出ている項目も、「エラーが出た」という事実として認識せよ。
2.  **意味の解釈**: 各項目が何を意味するかを、あなたの持つ専門知識を基に解釈せよ。
    - `VirusTotal`の`summary`は、いくつのセキュリティソフトが脅威と判定したかを示す。
    - `DNSBL`の`status: "LISTED"`は、そのIPがスパム送信元としてブラックリストに載っていることを意味する。
    - `Google Safe Browsing`の`判定: "危険"`は、そのサイトが不正なサイトとしてGoogleに認識されていることを示す。
    - `abuse.ch`の`URLHaus`や`ThreatFox`は、マルウェアとの関連性を示す。
    - `AlienVault OTX`の`関連脅威レポート数`は、他の研究者からどの程度注目されている脅威かを示す。
    - `Shodan`は、そのIPでどのようなサービス（ポート）が外部に公開されているかを示す。脆弱性(CVE)がリストにあれば特に危険である。
    - `GreyNoise`の`ノイズ判定: true`は、攻撃ではなく、インターネット全体の背景ノイズ（調査スキャン等）である可能性が高いことを示す。
    - `Cisco Talos`の`判定`は、世界最大級のネットワークを持つCisco社の評価であり、信頼性が高い。
    - `STIX/TAXII Feeds`で`判定: "危険"`の場合、そのIPやドメインは、**Anomali LIMOなどの公開脅威情報フィードで悪意あると報告されている**ことを意味する。
    - `IPQualityScore`で`判定: "匿名化"`の場合、そのIPは**VPNやProxyを経由しており、真の攻撃元を隠蔽している**可能性が高い。
    - `MISP`で`判定: "危険"`の場合、そのIPは**世界中のセキュリティ組織が共有する脅威情報データベースに登録されている**ことを意味し、極めて信頼性の高い危険信号である。
3.  **結論の導出**: 上記の解釈を総合し、調査対象が「安全」「不審」「危険」のどれに該当するか、最終的な結論を導き出せ。単一の「危険」判定だけで結論を急ぐのではなく、複数の情報ソースを比較検討し、総合的な視点で判断せよ。例えば、「VirusTotalでは危険判定だが、GreyNoiseではノイズ判定」の場合、「悪意ある攻撃の可能性は低いが、注意が必要」といった多角的な結論を出すこと。
4.  **報告書の執筆**: 導き出した結論を、以下の構成で、専門用語を避けつつも具体的で、説得力のある報告書として執筆せよ。
    - **【最重要ルール】**: 報告書の冒頭で、まず「**結論**」を先に述べよ。「8.8.8.8はGoogleのDNSサーバーであり、安全です」のように、ユーザーが最も知りたい答えを最初に提示すること。
    - **【追加ルール】**: 専門家として、ユーザーが次に取るべき**具体的なアクション**（例えば「このIPからの通信はブロックしてください」「このサイトにはアクセスしないでください」など）を明確に推奨せよ。

# ユーザーからの質問: "{user_query}"
# 内部調査結果 (分析対象の全データ): {json.dumps(internal_results, indent=2, ensure_ascii=False)}
# 生成すべき報告書の構成:
## [調査対象]に関する調査報告書
**結論:** (ここに「安全」「不審」「危険」の判定と、その最も重要な根拠を1〜2文で記述)
**詳細分析:**
* **VirusTotal:** (分析結果を記述)
* **DNSBL:** (分析結果を記述)
* (他の全ての情報ソースの結果を、それぞれ箇条書きで記述)
* **総合評価:** (全ての情報を踏まえた、最終的な分析内容を記述)
**推奨される対策:**
* (ユーザーが取るべき具体的なアクションを箇条書きで記述)
"""
            system_prompt = "あなたは、JSON形式の技術的な調査データを解釈し、サイバーセキュリティの専門家として、人間にとって自然で分かりやすい報告書を作成する、最高峰のAIアナリストです。"
            return self.ai_manager.generate_response(prompt, system_prompt)
        
        else:
            print("  > No specific target detected. Engaging Web Search or General Knowledge intelligence...")
            search_results_text = self._perform_web_search(user_query)
            if "エラーが発生しました" in search_results_text or "設定されていません" in search_results_text:
                print("  > Web search failed. Falling back to general knowledge mode.")
                system_prompt = "あなたは、サイバーセキュリティに関するあらゆる質問に、専門家として誠実に答えるAIアシスタントです。"
                prompt = f"ユーザーが「{user_query}」と質問しています。あなたの持つ専門知識を総動員し、この質問に対して最も的確で分かりやすい回答を生成してください。"
                return self.ai_manager.generate_response(prompt, system_prompt)
            else:
                system_prompt = "あなたは、提示されたWeb検索結果を正確に要約し、ユーザーの質問に答えるプロの調査員です。"
                prompt = f"ユーザーは「{user_query}」と質問しています。以下のWeb検索結果を基に、質問への回答を分かりやすく生成してください。\n\n# Web検索結果:\n{search_results_text}"
                return self.ai_manager.generate_response(prompt, system_prompt)

    def _perform_web_search(self, query):
        if not self.search_service:
            return "Web検索機能は設定されていません。"
        try:
            print(f"  > Searching the web for: '{query}'")
            res = self.search_service.cse().list(q=query, cx=self.cse_id, num=3).execute()
            print("  > Web search complete.")
            snippets = [f"【タイトル】{item.get('title', '')}\n【内容】{item.get('snippet', '')}" for item in res.get('items', [])]
            return "\n\n".join(snippets) if snippets else "関連する情報は見つかりませんでした。"
        except HttpError as e:
            return f"Web検索中にAPIエラーが発生しました: {e.reason}"
        except Exception as e:
            return f"Web検索中に予期せぬエラーが発生しました: {e}"
            
    def generate_conversation_title(self, first_user_message, first_ai_message):
        prompt = f"""
        以下の会話の要点を5〜10単語程度の日本語の短いタイトルにしてください。
        ユーザー: 「{first_user_message}」
        AI: 「{first_ai_message}」
        タイトル:
        """
        try:
            title = self.ai_manager.generate_response(prompt)
            cleaned_title = title.strip().replace('"', '').replace('「', '').replace('」', '')
            return cleaned_title if cleaned_title else "名称未設定のチャット"
        except Exception as e:
            print(f"Error generating title with Ollama: {e}")
            return "名称未設定のチャット"