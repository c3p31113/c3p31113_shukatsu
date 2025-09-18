# CYBER-AEGIS/src/threat_intel/yara_scanner.py
import yara
import os
import time
from src.utils.app_logger import Logger

class YaraScanner:
    def __init__(self, rules_path):
        self.logger = Logger()
        if not os.path.isdir(rules_path):
            self.logger.error(f"YARA rules path does not exist: {rules_path}")
            raise FileNotFoundError(f"YARA rules path not found: {rules_path}")

        all_filepaths = {}
        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith((".yar", ".yara")):
                    filepath = os.path.join(root, file)
                    namespace = os.path.splitext(file)[0]
                    all_filepaths[namespace] = filepath

        if not all_filepaths:
            self.logger.warning("No YARA rule files found. The scanner will be inactive.")
            self.rules = yara.compile(source='rule dummy { condition: false }')
            return

        self.logger.info(f"Found {len(all_filepaths)} YARA rule files. Starting final validation and compilation...")

        valid_sources = {}
        invalid_file_count = 0
        
        dummy_externals = {
            'filename': '', 'filepath': '', 'extension': '', 'filetype': '', 'owner': ''
        }

        for namespace, filepath in all_filepaths.items():
            content = None
            try:
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    with open(filepath, 'r', encoding='latin-1') as f:
                        content = f.read()

                if content:
                    yara.compile(source=content, externals=dummy_externals)
                    valid_sources[namespace] = content
                else:
                    raise ValueError("File content is empty.")

            except Exception as e:
                self.logger.warning(f"Skipping invalid YARA rule file '{os.path.basename(filepath)}'. Reason: {e}")
                invalid_file_count += 1
        
        if not valid_sources:
            self.logger.error("No valid YARA rule files could be compiled. The scanner will be inactive.")
            self.rules = yara.compile(source='rule dummy { condition: false }')
            return

        try:
            self.logger.info(f"Compiling a final ruleset from {len(valid_sources)} valid source(s).")
            self.rules = yara.compile(sources=valid_sources, externals=dummy_externals)
            self.logger.info("YARA scanner initialized successfully.")
            if invalid_file_count > 0:
                self.logger.warning(f"Total files skipped due to errors: {invalid_file_count}")

        except yara.Error as e:
            self.logger.error(f"A critical error occurred during the final YARA compilation: {e}")
            raise e

    def scan_file(self, file_path, timeout=30):
        """
        ファイルの中身(データ)を直接読み取り、YARAに渡すことで、ファイルロック問題を根本的に解決する。
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            self.logger.warning(f"Scan target does not exist or is not a file: {file_path}")
            return []
        
        start_time = time.time()
        file_data = None
        
        # ステップ1: タイムアウト(30秒)まで、ファイルの読み取り権限を待ち続ける
        while time.time() - start_time < timeout:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                break  # 読み取り成功！ループを抜ける
            except (PermissionError, FileNotFoundError):
                time.sleep(1) # 失敗した場合は1秒待機してリトライ
            except Exception as e:
                 self.logger.error(f"An unexpected error occurred while reading {file_path}: {e}")
                 return []
        
        if file_data is None:
            self.logger.error(f"Scan timed out for file {file_path} after {timeout} seconds. The file remained locked or inaccessible.")
            return []

        # ステップ2: 読み取ったデータを使ってスキャンを実行
        try:
            file_extension = os.path.splitext(file_path)[1]
            matches = self.rules.match(
                data=file_data, # ファイルパスではなく、ファイルの中身そのものを渡す
                externals={
                    'filename': os.path.basename(file_path),
                    'filepath': file_path,
                    'extension': file_extension if file_extension else '',
                    'owner': ''
                }
            )
            if matches:
                self.logger.warning(f"YARA rule matched for file: {file_path}")
                for match in matches:
                    self.logger.warning(f"  Rule: {match.rule}, Meta: {match.meta}")
            return matches

        except Exception as e:
            self.logger.error(f"An unexpected error occurred during YARA data scan for {file_path}: {e}")
            return []