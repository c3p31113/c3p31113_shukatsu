from taxii2client.v20 import Server
from stix2 import Filter

class StixTaxiiChecker:
    def __init__(self):
        self.server_url_primary = "https://cti.mitre.org/taxii/"
        self.server_url_secondary = "https://otx.anomali.com/taxii/"
        self.collection_id = "95ecc380-afe9-11e4-9b6c-751b66dd541e" 
        self.server = None
        self.api_root = None
        # ▼▼▼ 変更点 ▼▼▼
        # 接続失敗を記録するフラグを追加します
        self.initial_connection_failed = False
        # ▲▲▲ 変更点 ▲▲▲
        self._connect()

    def _connect(self):
        urls = [self.server_url_primary, self.server_url_secondary]
        for url in urls:
            try:
                print(f"  > [STIX/TAXII] Attempting to connect to {url}...")
                self.server = Server(url, timeout=10)
                
                if 'anomali' in url:
                    self.api_root = next((root for root in self.server.api_roots if root.title == 'default'), None)
                else:
                    self.api_root = next((root for root in self.server.api_roots if 'Enterprise ATT&CK' in root.title), None)

                if self.api_root:
                    print(f"  > [STIX/TAXII] Connection successful to {url}.")
                    self.initial_connection_failed = False
                    return True # 成功したらループを抜ける
            except Exception as e:
                print(f"  > [STIX/TAXII] Warning: Could not connect to {url} on startup: {e}")
        
        # ▼▼▼ 変更点 ▼▼▼
        # すべての接続に失敗した場合にフラグを立てます
        print("  > [STIX/TAXII] Critical: Could not connect to any TAXII server. Disabling further checks.")
        self.initial_connection_failed = True
        self.server = None
        self.api_root = None
        return False
        # ▲▲▲ 変更点 ▲▲▲

    def search_indicator(self, indicator_value):
        # ▼▼▼ 変更点 ▼▼▼
        # 初期接続に失敗していたら、調査をスキップして即座にエラーを返します
        if self.initial_connection_failed:
            return {"error": "初期接続に失敗したため、STIX/TAXII調査はスキップされました。"}
        # ▲▲▲ 変更点 ▲▲▲

        if not self.server:
             # このロジックは、万が一初期接続後に接続が切れた場合のためのもの
            if not self._connect():
                return {"error": "TAXIIサーバーへの再接続に失敗しました。"}
        
        try:
            print(f"  > [STIX/TAXII] Querying for: {indicator_value}")
            collection = next((c for c in self.api_root.collections if c.id == self.collection_id), None)
            
            if not collection:
                 return {"判定": "情報なし", "詳細": f"このサーバー({self.server.url})に指定されたコレクションはありません。"}

            filt = [Filter('name', '=', indicator_value)]
            results = collection.get_objects(filter=filt)
            
            if results and results.get('objects'):
                return {"判定": "情報あり", "関連オブジェクト数": len(results['objects']), "詳細": f"TAXIIフィードで {len(results['objects'])}件の関連オブジェクトが検出されました。"}
            else:
                return {"判定": "情報なし", "詳細": "TAXIIフィードに関連する脅威情報は検出されませんでした。"}
        except Exception as e:
            self.server = None
            self.api_root = None
            return {"error": f"STIX/TAXIIでの調査中にエラーが発生しました: {e}."}