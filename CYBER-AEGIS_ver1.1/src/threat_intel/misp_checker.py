# src/threat_intel/misp_checker.py
from pymisp import PyMISP
from src.utils.config_manager import ConfigManager

class MispChecker:
    def __init__(self):
        self.config = ConfigManager()
        misp_url = self.config.get('API_KEYS', 'misp_url', fallback=None)
        misp_key = self.config.get('API_KEYS', 'misp_api_key', fallback=None)
        
        if misp_url and misp_key:
            try:
                # MISPサーバーへの接続を初期化
                self.misp = PyMISP(misp_url, misp_key, ssl=False) # 自己署名証明書を許可
                print("  > [MISP] Successfully connected to MISP instance.")
            except Exception as e:
                print(f"  > [MISP] Error connecting to MISP: {e}")
                self.misp = None
        else:
            self.misp = None

    def search(self, indicator):
        """MISPで侵害指標(IOC)を検索する"""
        if not self.misp:
            return {"error": "config.iniにMISPのURLまたはAPIキーが設定されていません。"}
        
        try:
            print(f"  > [MISP] Querying for indicator: {indicator}")
            # MISPのsearch関数を使って、指定した指標を検索
            result = self.misp.search(controller='attributes', value=indicator)
            
            events = result.get('Attribute', [])
            if events:
                return {
                    "判定": "危険",
                    "関連イベント数": len(events),
                    "詳細": f"{len(events)}件の関連イベントがMISPで検出されました。"
                }
            else:
                return {
                    "判定": "安全",
                    "詳細": "MISPに関連する脅威情報は検出されませんでした。"
                }
        except Exception as e:
            return {"error": f"MISPでの調査中にエラーが発生しました: {e}"}