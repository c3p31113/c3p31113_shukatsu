# src/threat_intel/greynoise_checker.py

import requests
from src.utils.config_manager import ConfigManager

class GreyNoiseChecker:
    def __init__(self, timeout=15):
        self.config = ConfigManager()
        self.api_key = self.config.get('API_KEYS', 'greynoise_api_key', fallback=None)
        self.api_url = "https://api.greynoise.io/v3/community/"
        self.timeout = timeout

    def check_ip(self, ip_address):
        """GreyNoise Community APIでIPアドレスをチェックする"""
        if not self.api_key:
            return {"error": "config.iniにGreyNoiseのAPIキー(greynoise_api_key)が設定されていません。"}
        
        url = self.api_url + ip_address
        headers = {
            "key": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            print(f"  > [GreyNoise] Querying for IP: {ip_address}")
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 404:
                return {"判定": "情報なし", "詳細": "このIPはGreyNoiseの観測範囲にありません。"}
            
            response.raise_for_status()
            data = response.json()

            return {
                "ノイズ判定": data.get('noise', False),
                "分類": data.get('classification', 'N/A'),
                "詳細": data.get('message', 'N/A')
            }
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                return {"error": f"GreyNoise APIエラー: {e.response.status_code}"}
            return {"error": f"GreyNoise APIへのリクエスト中にエラー: {e}"}