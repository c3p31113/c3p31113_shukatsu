# CYBER-AEGIS/src/utils/notifier.py
from win10toast_click import ToastNotifier
import logging
import threading

class Notifier:
    """
    Windowsのデスクトップ通知を管理するクラス。
    オリジナルの安定した実装に戻し、GUIスレッドとの競合を避ける。
    """
    def __init__(self):
        self.toaster = ToastNotifier()

    def show_notification(self, title, message, duration=10):
        """
        デスクトップ通知を表示する。
        GUIをブロックしないように、常に別スレッドで安全に実行する。
        """
        def _show():
            try:
                # threaded=True は時として不安定なため、スレッド管理は自分で行う
                self.toaster.show_toast(
                    title=title,
                    msg=message,
                    duration=duration,
                    threaded=False
                )
            except Exception as e:
                # 通知機能は失敗してもアプリケーション全体に影響を与えない
                logging.error(f"通知の表示に失敗しました: {e}", exc_info=True)

        # GUIスレッドからの呼び出しでも問題が起きないように、
        # threadingを使用してバックグラウンドでの実行を確実にする
        thread = threading.Thread(target=_show)
        thread.daemon = True
        thread.start()

# シングルトンインスタンス
notifier = Notifier()