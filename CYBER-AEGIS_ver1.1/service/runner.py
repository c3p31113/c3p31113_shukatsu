import ctypes
import os
import sys
import traceback
import time

def is_admin():
    """現在のプロセスが管理者権限を持っているか確認する"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """サービスを 'python -m service.runner' として管理者権限で再実行する"""
    executable = sys.executable
    params = f"-m {os.path.basename(os.path.dirname(__file__))}.runner"

    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        return ret > 32
    except Exception:
        traceback.print_exc()
        return False

def start_main_service():
    """ServiceManagerをインポートしてサービスを開始し、終了シグナルを監視する"""
    print("管理者権限で実行中。サービスの初期化を開始します...")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        
    from service.service_manager import ServiceManager
    
    manager = ServiceManager()
    try:
        manager.start()
        
        # --- ▼▼▼【重要修正点①】▼▼▼ ---
        # GUIからの終了合図（shutdown.flag）を監視するループ
        while manager.running:
            if os.path.exists('shutdown.flag'):
                print("[Runner] GUIからの終了シグナルを検知しました。")
                break  # ループを抜けてfinallyブロックの停止処理へ
            time.sleep(2)  # 2秒ごとにチェック
        # --- ▲▲▲ 修正ここまで ▲▲▲ ---

    except KeyboardInterrupt:
        print("手動でのシャットダウンシグナルを検知しました。サービスを停止します...")
    finally:
        manager.stop()
        print("サービスは正常に停止しました。")

if __name__ == '__main__':
    # --- ▼▼▼【重要修正点②】▼▼▼ ---
    # 起動時に、前回の終了時に作成された可能性のある
    # shutdown.flag ファイルを削除し、意図しない即時終了を防ぐ
    if os.path.exists('shutdown.flag'):
        os.remove('shutdown.flag')
    # --- ▲▲▲ 修正ここまで ▲▲▲ ---

    if is_admin():
        start_main_service()
    else:
        print("管理者権限が必要です。UACプロンプトを要求します...")
        if not run_as_admin():
            print("管理者権限の昇格に失敗しました、またはユーザーによってキャンセルされました。")
            input("何かキーを押して終了してください...")