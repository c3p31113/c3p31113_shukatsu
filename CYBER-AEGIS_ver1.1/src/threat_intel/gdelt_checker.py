# src/threat_intel/gdelt_checker.py

import requests
import json

class GdeltChecker:
    def __init__(self):
        # GDELT 2.0 DOC APIのエンドポイント
        self.base_url = "https://api.gdeltproject.org/api/v2/doc/doc"

    def get_geopolitical_news(self, keyword: str):
        """
        GDELT APIを使用して、指定されたキーワードに関連する地政学的なニュースを取得します。
        """
        print(f"  > [GDELT] Querying for geopolitical news related to: '{keyword}'")
        
        # APIクエリのパラメータを設定
        # 例: "cyber attack" と "Japan" の両方を含む記事を検索
        params = {
            'query': f'"{keyword}"',
            'mode': 'artlist', # 記事のリストを取得
            'maxrecords': 5,  # 最新5件の記事に絞る
            'sort': 'datedesc', # 日付の新しい順
            'format': 'json'
        }

        try:
            response = requests.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            articles = data.get('articles', [])

            if not articles:
                return {
                    "判定": "情報なし",
                    "詳細": f"GDELTデータベース内で、キーワード「{keyword}」に関連する最近の主要なニュースは見つかりませんでした。"
                }

            # 取得した記事の概要を作成
            summary = [f"- {article.get('title')} (Source: {article.get('sourcecountry')} / {article.get('domain')})" for article in articles]
            summary_text = "\n".join(summary)

            return {
                "判定": "情報あり",
                "検出数": len(articles),
                "最新ニュース概要": summary_text,
            }

        except requests.RequestException as e:
            return {"error": f"GDELT APIへのリクエスト中にエラーが発生しました: {e}"}