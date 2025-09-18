# CYBER-AEGIS/src/collectors/x_collector.py

import requests
from datetime import datetime
from src.utils.config_manager import ConfigManager

class XCollector:
    API_BASE_URL = "https://api.twitter.com/2/tweets/search/recent"
    
    def __init__(self):
        self.config = ConfigManager()
        self.bearer_token = self.config.get('API_KEYS', 'x_bearer_token', fallback=None)
        if not self.bearer_token:
            raise ValueError("X Bearer Token not found in config.ini")
        self.headers = {"Authorization": f"Bearer {self.bearer_token}"}

    def fetch_leaks(self, keywords):
        if not keywords:
            return []
        
        formatted_keywords = []
        for k in keywords:
            if k.startswith('"') and k.endswith('"'):
                formatted_keywords.append(k)
            else:
                formatted_keywords.append(f'"{k}"')
        
        query_keywords = " OR ".join(formatted_keywords)
        full_query = f'({query_keywords}) -is:retweet'

        try:
            return self._search_query(full_query, keywords)
        except Exception as e:
            print(f"[XCollector] 予期せぬエラーが発生しました: {e}")
            return []

    def _search_query(self, query, original_keywords):
        leaks = []
        params = {
            'query': query,
            'tweet.fields': 'created_at,author_id',
            'expansions': 'author_id',
            'user.fields': 'username',
            'max_results': 100
        }
        
        try:
            response = requests.get(self.API_BASE_URL, headers=self.headers, params=params, timeout=30)
            response.raise_for_status() # ここで4xx, 5xxエラーが発生するとHTTPErrorが投げられる
            results = response.json()
            
            users = {user['id']: user for user in results.get('includes', {}).get('users', [])}
            
            for tweet in results.get('data', []):
                author_id = tweet.get('author_id')
                author_username = users.get(author_id, {}).get('username', 'N/A')
                tweet_id = tweet.get('id')
                tweet_text = tweet.get('text', '')
                
                matched_keyword = "N/A"
                for kw in original_keywords:
                    clean_kw = kw.strip('"')
                    if clean_kw.lower() in tweet_text.lower():
                        matched_keyword = kw
                        break

                leaks.append({
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "source": "X (Twitter)", "keyword": matched_keyword,
                    "author": author_username, "tweet_text": tweet_text,
                    "url": f"https://twitter.com/{author_username}/status/{tweet_id}",
                    "tweet_created_at": tweet.get('created_at')
                })
        
        # ★★★ ここを修正: HTTPエラーを名指しでキャッチする ★★★
        except requests.exceptions.HTTPError as e:
            # HTTPエラーの場合、e.responseは常に存在し、ステータスコードが確認できる
            if e.response.status_code == 429:
                print(f"[XCollector] X APIのレート制限(429)に達しました。15分ほど待ってから再試行してください。")
            elif e.response.status_code == 400:
                print(f"[XCollector] APIリクエストの形式が不正(400)です。クエリを確認してください: {query}")
            else:
                print(f"[XCollector] HTTPエラーが発生しました: {e}")

        except requests.exceptions.RequestException as e:
            # タイムアウトや接続エラーなど、HTTP以外のネットワークエラー
            print(f"[XCollector] ネットワーク関連のエラーが発生しました: {e}")
        
        return leaks