# src/threat_intel/ipqs_checker.py

import requests
from src.utils.config_manager import ConfigManager

class IpqsChecker:
    def __init__(self, timeout=15):
        self.config = ConfigManager()
        self.api_key = self.config.get('API_KEYS', 'ipqs_api_key', fallback=None)
        self.base_url = "https://www.ipqualityscore.com/api/json/ip/"
        self.timeout = timeout

    def check_ip(self, ip_address):
        """IPQualityScore APIでIPアドレスをチェックする"""
        if not self.api_key:
            return {"error": "config.iniにIPQualityScoreのAPIキー(ipqs_api_key)が設定されていません。"}
        
        url = f"{self.base_url}{self.api_key}/{ip_address}"
        
        try:
            print(f"  > [IPQS] Querying for IP: {ip_address}")
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            if not data.get('success', False):
                return {"error": f"IPQS APIからのエラー: {data.get('message', '不明なエラー')}"}

            is_proxy = data.get('proxy', False)
            is_vpn = data.get('vpn', False)
            is_tor = data.get('tor', False)
            
            summary = []
            if is_proxy: summary.append("Proxy")
            if is_vpn: summary.append("VPN")
            if is_tor: summary.append("Tor")
            
            return {
                "判定": "匿名化" if summary else "通常",
                "リスクスコア": data.get('fraud_score', 'N/A'),
                "ボットの可能性": data.get('bot_status', False),
                "詳細": f"匿名化サービスの利用状況: {', '.join(summary) if summary else '検出されず'}",
                "国": data.get('country_code', 'N/A'),
                "ISP": data.get('ISP', 'N/A')
            }
        except requests.RequestException as e:
            return {"error": f"IPQS APIへのリクエスト中にエラーが発生しました: {e}"}