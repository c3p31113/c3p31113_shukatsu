import json
import os
# ▼▼▼【最終修正】「収集係」を呼び出すために、コレクターをインポート ▼▼▼
from src.collectors.cisa_kev_collector import CisaKevCollector

class CisaKevChecker:
    def __init__(self, cache_dir='cache'):
        self.cache_file = os.path.join(cache_dir, 'cisa_kev.json')
        self.vulnerabilities = self._load_kev_data()

    def _load_kev_data(self):
        """
        キャッシュされたCISA KEV JSONファイルを読み込む。
        もしファイルが存在しない場合は、コレクターを呼び出して自動で取得する。
        """
        if not os.path.exists(self.cache_file):
            print(f"  > [CISA KEV] Cache file not found. Running collector automatically...")
            
            # ▼▼▼【最終修正】収集係を呼び出し、最新の教科書をダウンロード ▼▼▼
            collector = CisaKevCollector()
            # fetch_threat_feedは、最新データをダウンロードし、cacheフォルダに自動で保存してくれます
            collector.fetch_threat_feed()
        
        # ファイルが（再）生成されたはずなので、再度読み込みを試みる
        if not os.path.exists(self.cache_file):
             print(f"  > [CISA KEV] Failed to create cache file even after running collector.")
             return []

        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"  > [CISA KEV] Successfully loaded {len(data.get('vulnerabilities', []))} vulnerabilities from cache.")
            return data.get('vulnerabilities', [])
        except (json.JSONDecodeError, IOError) as e:
            print(f"  > [CISA KEV] Error reading cache file: {e}")
            return []

    def check_product(self, product_name):
        """指定された製品名がKEVカタログに含まれているかチェックする"""
        if not self.vulnerabilities:
            return {"error": "CISA KEVデータがロードされていません。"}
        
        found_vulns = []
        search_keywords = product_name.lower().split()
        
        for vuln in self.vulnerabilities:
            target_text = f"{vuln.get('vendorProject', '').lower()} {vuln.get('product', '').lower()}"
            
            if all(keyword in target_text for keyword in search_keywords):
                found_vulns.append({
                    "cveID": vuln.get('cveID'),
                    "vulnerabilityName": vuln.get('vulnerabilityName'),
                    "dateAdded": vuln.get('dateAdded'),
                    "requiredAction": vuln.get('requiredAction')
                })
        
        if found_vulns:
            return {
                "判定": "危険",
                "検出数": len(found_vulns),
                "詳細": f"製品「{product_name}」に関連する、悪用が確認された脆弱性が{len(found_vulns)}件見つかりました。",
                "脆弱性リスト": found_vulns
            }
        else:
            return {
                "判定": "安全",
                "詳細": f"製品「{product_name}」に関連する、悪用が確認された脆弱性は見つかりませんでした。"
            }