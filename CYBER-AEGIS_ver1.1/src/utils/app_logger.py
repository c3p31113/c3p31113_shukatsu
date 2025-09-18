# CYBER-AEGIS/src/utils/app_logger.py

import logging
from logging.handlers import RotatingFileHandler
import os
import sys

# プロジェクトのルートディレクトリを基準にログファイルのパスを設定
log_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'logs'))
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

log_file_path = os.path.join(log_directory, 'cyber_aegis.log')

# ロガーの重複登録を防ぐためのチェック
if 'aegis_logger' in logging.Logger.manager.loggerDict:
    logger = logging.getLogger('aegis_logger')
else:
    logger = logging.getLogger('aegis_logger')
    logger.setLevel(logging.INFO)
    
    # 既存のハンドラを全て削除
    if logger.hasHandlers():
        logger.handlers.clear()

    # ファイルハンドラ: ログをファイルに書き込む
    # ログファイルは5MBごとに新しいファイルに切り替わり、最大5つまでバックアップを保持
    fh = RotatingFileHandler(log_file_path, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    fh.setLevel(logging.INFO)

    # コンソールハンドラ: ログをターミナル（コンソール）に表示する
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)

    # ログのフォーマットを定義
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    # ハンドラをロガーに追加
    logger.addHandler(fh)
    logger.addHandler(ch)

# シングルトンパターンとして、Loggerクラスではなく設定済みのloggerインスタンスを提供する
# これにより、どのファイルからでも同じ設定のロガーを簡単に利用できる
class Logger:
    def __init__(self):
        # このクラスは、実際には上記で設定されたグローバルなloggerインスタンスを返すだけ
        self._logger = logging.getLogger('aegis_logger')

    def info(self, message):
        self._logger.info(message)

    def warning(self, message):
        self._logger.warning(message)

    def error(self, message):
        self._logger.error(message)
        
    def critical(self, message):
        self._logger.critical(message)

# グローバルなインスタンスを作成
# 他のファイルからは `from src.utils.app_logger import app_logger` のようにして利用する
app_logger = Logger()