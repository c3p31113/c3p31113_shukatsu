import configparser
import os

class ConfigManager:
    def __init__(self, config_path='config.ini'):
        self.config_path = config_path
        self.config = configparser.ConfigParser(interpolation=None)
        
        if not os.path.exists(self.config_path):
            self.create_default_config()
        self.config.read(self.config_path, encoding='utf-8')

    def create_default_config(self):
        # このメソッドは一切変更ありません。
        self.config['AI'] = {'model': 'gemma:2b'}
        self.config['DATABASE'] = {'path': 'aegis.db'}
        self.config['FileMonitorExclusions'] = {
            'directories': '/AppData/, /Windows/, /Program Files/, /Program Files (x86)/',
            'extensions': '.log, .tmp, .cache, .json',
            'processes': 'svchost.exe, msedge.exe, Discord.exe'
        }
        self.config['Automation'] = {
            'auto_defense_enabled': 'false'
        }
        with open(self.config_path, 'w', encoding='utf-8') as configfile:
            self.config.write(configfile)

    def get(self, section, option, fallback=None):
        # このメソッドは一切変更ありません。
        return self.config.get(section, option, fallback=fallback)

    def get_boolean(self, section, option, fallback=False):
        # このメソッドは一切変更ありません。
        return self.config.getboolean(section, option, fallback=fallback)

    def get_list(self, section, option):
        # このメソッドは一切変更ありません。
        value = self.get(section, option, fallback='')
        return [item.strip() for item in value.split(',') if item.strip()]

    def set(self, section, option, value):
        # このメソッドは一切変更ありません。
        if not self.config.has_section(section):
            self.config.add_section(section)
        if isinstance(value, bool):
            value = str(value).lower()
        self.config.set(section, option, value)

    def add_to_list(self, section, option, new_values):
        """設定ファイルのカンマ区切りリストに、新しい値を重複なく追加する"""
        if not isinstance(new_values, list):
            new_values = [new_values]
            
        current_list = self.get_list(section, option)
        updated = False
        for value in new_values:
            if value not in current_list:
                current_list.append(value)
                updated = True
        
        if updated:
            self.set(section, option, ",".join(current_list))
            self.save()
            print(f"[ConfigManager] Updated '{option}' with new values: {new_values}")

    def save(self):
        # このメソッドは一切変更ありません。
        with open(self.config_path, 'w', encoding='utf-8') as configfile:
            self.config.write(configfile)

    # ★★★ この新しいメソッドをクラスの末尾に追加 ★★★
    def get_stix_taxii_settings(self):
        """STIX/TAXIIチェッカーの設定を読み込む"""
        settings = {}
        if self.config.has_section('STIX_TAXII'):
            servers_str = self.config.get('STIX_TAXII', 'servers', fallback='')
            settings['servers'] = [s.strip() for s in servers_str.split(',') if s.strip()]
            settings['collection_id'] = self.config.get('STIX_TAXII', 'collection_id', fallback=None)
            settings['timeout'] = self.config.getint('STIX_TAXII', 'timeout', fallback=10)
            settings['retries'] = self.config.getint('STIX_TAXII', 'retries', fallback=3)
            settings['retry_delay'] = self.config.getint('STIX_TAXII', 'retry_delay', fallback=5)
            settings['proxy_http'] = self.config.get('STIX_TAXII', 'proxy_http', fallback=None)
            settings['proxy_https'] = self.config.get('STIX_TAXII', 'proxy_https', fallback=None)
        return settings