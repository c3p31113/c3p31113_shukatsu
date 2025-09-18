# src/threat_intel/otx_checker.py

import requests
from src.utils.config_manager import ConfigManager

class OTXChecker:
    def __init__(self, timeout=15):
        self.config = ConfigManager()
        self.api_key = self.config.get('API_KEYS', 'otx_api_key', fallback=None)
        self.base_url = "https://otx.alienvault.com/api/v1/indicators/"
        self.timeout = timeout

    def get_indicator_details(self, indicator, indicator_type):
        """OTXでIPアドレス、ドメイン、URLの評判をチェックする"""
        if not self.api_key:
            return {"error": "config.iniにOTXのAPIキー(otx_api_key)が設定されていません。"}
        
        # ▼▼▼【最終修正】最も信頼性の高い「総合受付(/general)」に問い合わせる方式に戻し、解析をより正確に ▼▼▼
        endpoint = f"{indicator_type}/{indicator}/general"
        url = self.base_url + endpoint
        headers = {'X-OTX-API-KEY': self.api_key}
        
        try:
            print(f"  > [OTX] Querying for {indicator_type}: {indicator}")
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            # 脅威レポート（パルス）の件数を、pulse_infoから正確に取得
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            
            return {
                "判定": "危険" if pulse_count > 0 else "安全",
                "関連脅威レポート数": pulse_count,
                "詳細": f"{pulse_count}件の関連脅威レポート（パルス）が検出されました。"
            }
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 404:
                    return {"判定": "安全", "詳細": "関連する脅威レポートは見つかりませんでした。"}
                return {"error": f"OTX APIエラー: {e.response.status_code}"}
            return {"error": f"OTX APIへのリクエスト中にエラー: {e}"}