import time
from service.service_manager import ServiceManager

def main():
    """
    バックグラウンドサービスを起動し、実行し続けるためのメイン関数。
    """
    print("Initializing AEGIS Core Service...")
    
    # サービス管理の司令塔を呼び出す
    manager = ServiceManager()
    
    # 全てのバックグラウンドサービスを開始する
    manager.start()
    
    print("AEGIS Core Service is now running in the background.")
    print("Press Ctrl+C to stop the service gracefully.")
    
    try:
        # サービスが動き続けるように、メインプログラムをここで待機させる
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # ユーザーが Ctrl+C を押したら、安全にサービスを停止する
        print("\nCtrl+C detected. Shutting down AEGIS Core Service...")
        manager.stop()
        print("AEGIS Core Service has been stopped.")

if __name__ == '__main__':
    main()