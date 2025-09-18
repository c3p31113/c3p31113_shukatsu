# src/threat_intel/spur_checker.py

import requests
from src.utils.config_manager import ConfigManager

class SpurChecker:
    def __init__(self, timeout=15):
        self.config = ConfigManager()
        self.api_key = self.config.get('API_KEYS', 'spur_api_key', fallback=None)
        self.api_url = "https://api.spur.us/v2/context/"
        self.timeout = timeout

    def check_ip(self, ip_address):
        """Spur.us APIでIPアドレスのコンテキスト（VPN/Proxy利用状況など）をチェックする"""
        if not self.api_key:
            return {"error": "config.iniにSpur.usのAPIキー(spur_api_key)が設定されていません。"}
        
        url = self.api_url + ip_address
        headers = {
            "Token": self.api_key,
            "Content-Type": "application/json"
        }
        
        try:
            print(f"  > [Spur.us] Querying for IP: {ip_address}")
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 404:
                return {"判定": "情報なし", "詳細": "このIPはSpur.usのデータベースにありません。"}
            
            response.raise_for_status()
            data = response.json()

            # 匿名化サービスの利用状況を判定
            is_vpn = data.get('vpn', {}).get('value', False)
            is_proxy = data.get('proxy', {}).get('value', False)
            
            summary = []
            if is_vpn:
                summary.append("VPN")
            if is_proxy:
                summary.append("Proxy")

            return {
                "VPN利用の可能性": is_vpn,
                "Proxy利用の可能性": is_proxy,
                "判定": "匿名化" if summary else "通常",
                "詳細": f"匿名化サービスの利用状況: {', '.join(summary) if summary else '検出されず'}"
            }
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                return {"error": f"Spur.us APIエラー: {e.response.status_code}"}
            return {"error": f"Spur.us APIへのリクエスト中にエラー: {e}"}