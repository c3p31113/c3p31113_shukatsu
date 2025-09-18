# src/threat_intel/hibp_checker.py

import requests
import hashlib
import os
from pybloom_live import BloomFilter

class HIBPChecker:
    def __init__(self):
        self.base_url = "https://api.pwnedpasswords.com/range/"
        self.bloom_filter = self._load_bloom_filter()

    def _load_bloom_filter(self):
        """
        あなたがrealhuman_phill.txtから生成した、
        巨大辞書の「索引」であるpasswords.bloomをメモリにロードする。
        """
        bloom_path = os.path.join('cache', 'passwords.bloom')
        try:
            print(f"  > [HIBP] 巨大パスワード辞書の索引 '{bloom_path}' を読み込んでいます...")
            with open(bloom_path, 'rb') as f:
                bloom = BloomFilter.fromfile(f)
            print(f"  > [HIBP] 索引の読み込み完了。")
            return bloom
        except FileNotFoundError:
            print(f"  > [HIBP] 警告: 巨大パスワード辞書の索引 '{bloom_path}' が見つかりませんでした。APIチェックのみを実行します。")
            return None
        except Exception as e:
            print(f"  > [HIBP] 索引の読み込み中にエラーが発生しました: {e}")
            return None

    def check_password(self, password):
        if not password:
            return {"error": "パスワードが指定されていません。"}

        # --- ステップ1 (超高速): 内部索引(ブルームフィルタ)をチェック ---
        if self.bloom_filter and password in self.bloom_filter:
            return {
                "status": "PWNED",
                "details": "このパスワードは、内部の巨大漏洩パスワードデータベースで発見されました。",
                "source": "Internal Dictionary (Bloom Filter)"
            }
        
        # --- ステップ2 (中速): HIBP k-Anonymity APIをチェック ---
        try:
            print(f"  > [HIBP] 内部索引には見つかりませんでした。Have I Been Pwned APIに問い合わせます...")
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            response = requests.get(f"{self.base_url}{prefix}", timeout=15)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
                    return {"status": "PWNED", "details": f"このパスワードは、過去のデータ侵害で{count:,}回発見されています。", "count": count, "source": "Have I Been Pwned"}
            
            return {"status": "SAFE", "details": "このパスワードは、内部データベースおよび既知のデータ侵害では発見されませんでした。"}

        except requests.RequestException as e:
            return {"error": f"Pwned Passwords APIへのリクエスト中にエラーが発生しました: {e}"}