import requests
import time
import schedule
import random
import string

# TorのSOCKS5プロキシ設定
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# C2通信のターゲットURL（テスト用）
# このサイトはPOSTリクエストを受け付けてくれるテスト用のものです
TARGET_URL = "https://httpbin.org/post"

def generate_random_data(length=16):
    """ランダムな文字列データを生成する関数"""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def c2_beacon():
    """C2通信（ビーコン）を送信する関数"""
    try:
        # 送信するデータを作成（例: 'hostname=kali-pc&data=abcdefghijklmnop'）
        payload = {
            'hostname': 'kali-pc',
            'data': generate_random_data()
        }

        print(f"[*] Sending C2 beacon to {TARGET_URL}...")
        # Torプロキシ経由でPOSTリクエストを送信
        response = requests.post(TARGET_URL, proxies=proxies, data=payload, timeout=30)

        print(f"[+] Beacon sent successfully. Status: {response.status_code}")
        # print(f"[+] Response: {response.json()}") # 詳細なレスポンスを見たい場合はコメントアウトを外す

    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to send beacon: {e}")

# --- メイン処理 ---
print("C2 Simulator Started. Press Ctrl+C to stop.")
# 60秒ごとにc2_beacon関数を実行するようスケジュール
schedule.every(60).seconds.do(c2_beacon)

# 最初のビーコンをすぐに送信
c2_beacon()

# スケジュールを無限ループで実行
while True:
    schedule.run_pending()
    time.sleep(1)
