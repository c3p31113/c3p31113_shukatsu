# src/threat_intel/shodan_checker.py

import shodan
import time
from src.utils.config_manager import ConfigManager

class ShodanChecker:
    def __init__(self, max_retries=2, retry_delay=2):
        self.config = ConfigManager()
        self.api_key = self.config.get('API_KEYS', 'shodan_api_key', fallback=None)
        if self.api_key:
            self.api = shodan.Shodan(self.api_key)
        else:
            self.api = None
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def check_ip(self, ip_address):
        """ShodanでIPアドレスの公開情報を調査する（リトライ機能付き）"""
        if not self.api:
            return {"error": "config.iniにShodanのAPIキー(shodan_api_key)が設定されていません。"}
        
        for attempt in range(self.max_retries):
            try:
                print(f"  > [Shodan] Querying for IP: {ip_address} (Attempt {attempt + 1})")
                host_info = self.api.host(ip_address)
                
                open_ports = host_info.get('ports', [])
                services = [f"{s.get('port')}/{s.get('_shodan', {}).get('module', 'N/A')}" for s in host_info.get('data', [])]
                
                return {
                    "組織": host_info.get('org', 'N/A'),
                    "国": host_info.get('country_name', 'N/A'),
                    "公開ポート": open_ports,
                    "検知されたサービス": services,
                    "脆弱性(CVE)": host_info.get('vulns', []),
                    "詳細": f"{len(open_ports)}個の公開ポートが検出されました。"
                }
            except shodan.APIError as e:
                # 403 Forbiddenなどの回復不能なエラーは、リトライせずに終了
                if "Access denied" in str(e) or "Invalid API key" in str(e):
                     return {"error": f"Shodan APIキーが無効か、利用制限に達しました: {e}"}
                
                # その他のAPIエラーはリトライの対象
                print(f"  > [Shodan] API Error: {e}. Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
            except Exception as e:
                 # 接続エラーなどもリトライの対象
                print(f"  > [Shodan] Unexpected Error: {e}. Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)

        return {"error": f"Shodanでの調査に{self.max_retries}回失敗しました。"}