# CYBER-AEGIS/src/collectors/github_collector.py

import requests
import re
from datetime import datetime
from src.utils.config_manager import ConfigManager

class GithubCollector:
    
    API_BASE_URL = "https://api.github.com"
    
    def __init__(self):
        self.config = ConfigManager()
        self.github_token = self.config.get('API_KEYS', 'github_token', fallback=None)
        
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.github_token:
            self.headers["Authorization"] = f"Bearer {self.github_token}"

    def fetch_leaks(self, keywords):
        if not keywords:
            print("[GithubCollector] No keywords provided for scanning.")
            return []

        all_leaks = []
        for keyword in keywords:
            if not keyword: continue
            try:
                # ページネーションを実装したメソッドを呼び出す
                all_leaks.extend(self._search_keyword_paginated(keyword))
            except Exception as e:
                print(f"[GithubCollector] An unexpected error occurred while searching for '{keyword}': {e}")
        return all_leaks

    def _search_keyword_paginated(self, keyword, max_pages=3):
        """
        指定されたキーワードで検索し、複数ページの結果を取得する。
        max_pages: 取得する最大ページ数 (API制限対策)
        """
        leaks = []
        # ★★★ ここは変更なし ★★★
        search_url = f"{self.API_BASE_URL}/search/code"
        params = {'q': f'"{keyword}" in:file', 'sort': 'indexed', 'order': 'desc', 'per_page': 100}
        
        search_headers = self.headers.copy()
        search_headers["Accept"] = "application/vnd.github.v3.text-match+json"

        current_page = 1
        # ★★★ 次のページがある限りループする処理を追加 ★★★
        while search_url and current_page <= max_pages:
            try:
                response = requests.get(search_url, headers=search_headers, params=params, timeout=30)
                response.raise_for_status()
                
                # ★★★ データを整形するロジックは変更なし ★★★
                results = response.json()
                for item in results.get('items', []):
                    leaks.append({
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "source": "GitHub", "keyword": keyword,
                        "repository": item.get('repository', {}).get('full_name', 'N/A'),
                        "file_path": item.get('path', 'N/A'),
                        "url": item.get('html_url', '#'),
                        "matches": [match.get('fragment', '') for match in item.get('text_matches', [])]
                    })
                
                # ★★★ 次のページのURLを取得する処理を追加 ★★★
                link_header = response.headers.get('Link')
                next_url_match = re.search(r'<([^>]+)>;\s*rel="next"', link_header) if link_header else None
                
                if next_url_match:
                    search_url = next_url_match.group(1)
                    params = None # 2ページ目以降はURLに全パラメータが含まれるため不要
                    current_page += 1
                    print(f"[GithubCollector] Fetching page {current_page-1} for keyword '{keyword}'...")
                else:
                    search_url = None # 次のページがなければループを終了

            # ★★★ エラー処理を改善 ★★★
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    print(f"[GithubCollector] GitHub APIのレート制限(403)に達した可能性があります。")
                else:
                    print(f"[GithubCollector] HTTPエラーが発生しました: {e}")
                break 
            except requests.RequestException as e:
                print(f"[GithubCollector] APIリクエストに失敗しました: {e}")
                break
        
        return leaks

    def get_file_content(self, repo_full_name, file_path):
        # ★★★ このメソッドは一切変更ありません ★★★
        content_url = f"{self.API_BASE_URL}/repos/{repo_full_name}/contents/{file_path}"
        try:
            response = requests.get(content_url, headers=self.headers, timeout=30)
            response.raise_for_status()
            content_data = response.json()
            
            if 'content' in content_data:
                import base64
                decoded_content = base64.b64decode(content_data['content']).decode('utf-8', errors='ignore')
                return decoded_content, None
            else:
                return None, "ファイルの内容を取得できませんでした（ディレクトリの可能性があります）。"
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None, "ファイルが見つかりません。"
            if e.response.status_code == 403:
                 return None, "GitHub APIのレート制限に達した可能性があります。"
        except requests.RequestException as e:
            return None, f"ネットワークエラー: {e}"
        return None, "不明なエラー"