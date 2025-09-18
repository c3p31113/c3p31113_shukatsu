# src/threat_intel/abusech_checker.py

import requests
import json
from src.utils.config_manager import ConfigManager

class AbuseChChecker:
    def __init__(self, timeout=15):
        self.config = ConfigManager()
        # ▼▼▼ Auth-KeyはThreatFoxとURLHausで共通して使用します ▼▼▼
        self.auth_key = self.config.get('API_KEYS', 'threatfox_api_key', fallback=None)
        
        self.urlhaus_api_url = "https://urlhaus-api.abuse.ch/v1/host/"
        self.threatfox_api_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.timeout = timeout

    def check_urlhaus(self, host):
        """URLHausでホスト（ドメインまたはIP）をチェックする"""
        if not self.auth_key:
            # URLHausはキーが無くても一部機能は使えますが、エラー回避のためキー必須とします
            return {"error": "config.iniにThreatFoxのAPIキー(threatfox_api_key)が設定されていません。"}

        # ▼▼▼【最終修正】URLHausにも、ThreatFoxと同じAuth-Keyをヘッダーに含める ▼▼▼
        headers = {'Auth-Key': self.auth_key}
        
        try:
            # POSTするデータは 'host' で問題ありません
            response = requests.post(self.urlhaus_api_url, data={'host': host}, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            if data.get('query_status') == 'ok' and data.get('urls'):
                return {"判定": "危険", "詳細": f"{len(data['urls'])}件のマルウェア配布URLが検出されました。"}
            # 'no_results' は、そのホストに関する情報がないという正常な応答です
            elif data.get('query_status') == 'no_results':
                 return {"判定": "安全", "詳細": "マルウェア配布URLは検出されませんでした。"}
            else:
                 return {"判定": "安全", "詳細": "マルウェア配布URLは検出されませんでした。"}
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                 return {"error": f"URLHaus APIエラー: {e.response.status_code}, {e.response.text}"}
            return {"error": f"URLHaus APIへのリクエスト中にエラー: {e}"}

    def check_threatfox(self, indicator):
        """ThreatFoxで侵害指標(IOC)をチェックする"""
        if not self.auth_key:
            return {"error": "config.iniにThreatFoxのAPIキー(threatfox_api_key)が設定されていません。"}
        
        headers = {'Auth-Key': self.auth_key}
        payload = {
            'query': 'search_ioc',
            'search_term': indicator
        }
        try:
            response = requests.post(self.threatfox_api_url, json=payload, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            if data.get('query_status') == 'ok' and data.get('data'):
                return {"判定": "危険", "詳細": f"{len(data['data'])}件の関連マルウェア情報が検出されました。"}
            elif data.get('query_status') in ['ioc_not_found', 'no_result']:
                 return {"判定": "安全", "詳細": "関連マルウェア情報は検出されませんでした。"}
            else:
                 return {"判定": "不明", "詳細": f"APIからの予期せぬ応答: {data.get('query_status', 'N/A')}"}
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                return {"error": f"ThreatFox APIエラー: {e.response.status_code}, {e.response.text}"}
            return {"error": f"ThreatFox APIへのリクエスト中にエラー: {e}"}