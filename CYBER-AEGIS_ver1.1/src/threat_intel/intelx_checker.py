# src/threat_intel/intelx_checker.py

import requests
from src.utils.config_manager import ConfigManager
import time

class IntelxChecker:
    def __init__(self):
        self.config = ConfigManager()
        self.api_key = self.config.get('API_KEYS', 'intelx_api_key', fallback=None)
        # ▼▼▼ あなたの発見に基づき、APIのベースURLを正しいものに修正します ▼▼▼
        self.base_url = "https://free.intelx.io"
        # ▲▲▲ ▲▲▲

    def search_indicator(self, indicator: str):
        """
        IntelX.io APIを使用して、指定されたインジケータを検索します。
        """
        if not self.api_key:
            return {"error": "config.iniにIntelXのAPIキー(intelx_api_key)が設定されていません。"}

        print(f"  > [IntelX] Querying for indicator: {indicator}")
        
        headers = {'x-key': self.api_key}
        search_endpoint = f"{self.base_url}/intelligent/search"
        payload = {
            "term": indicator,
            "maxresults": 10,
            "media": 0,
            "sort": 2,
            "terminate": []
        }

        try:
            # 検索リクエストを送信
            response = requests.post(search_endpoint, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            
            search_data = response.json()
            search_id = search_data.get('id')
            if not search_id:
                return {"判定": "情報なし", "詳細": "検索は成功しましたが、結果IDが返されませんでした。"}

            # 結果を取得
            # (無料APIでは結果取得が制限されている可能性があるため、ループで待機します)
            result_endpoint = f"{self.base_url}/intelligent/search/result?id={search_id}"
            for _ in range(5): # 最大5回リトライ
                results_response = requests.get(result_endpoint, headers=headers, timeout=30)
                if results_response.status_code == 200:
                    break
                time.sleep(2) # 2秒待機
            results_response.raise_for_status()

            records = results_response.json().get('records', [])
            
            if not records:
                return {"判定": "安全", "詳細": f"IntelXのデータベース内で「{indicator}」に関する情報は見つかりませんでした。"}

            summary = [f"- {record.get('name', 'No Title')} (Source: {record.get('bucket', 'N/A')})" for record in records[:3]]
            summary_text = "\n".join(summary)

            return {
                "判定": "情報あり",
                "検出数": len(records),
                "結果概要": summary_text,
                "詳細": f"IntelXのデータベース内で「{indicator}」に関する情報が{len(records)}件見つかりました。"
            }

        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return {"判定": "安全", "詳細": "IntelXのデータベース内で情報は見つかりませんでした。"}
            return {"error": f"IntelX APIへのリクエスト中にHTTPエラー: {e.response.status_code} {e.response.text}"}
        except requests.RequestException as e:
            return {"error": f"IntelX APIへのリクエスト中にエラーが発生しました: {e}"}