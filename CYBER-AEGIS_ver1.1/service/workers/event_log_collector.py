import win32evtlog
import time
import os
import xml.etree.ElementTree as ET
import json
import sys

# プロジェクトのルートディレクトリをPythonのパスに追加
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.config_manager import ConfigManager

class EventLogCollector:
    def __init__(self):
        self.running = False
        config = ConfigManager()

        log_dir = os.path.join(project_root, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_filename = config.get('log_monitoring', 'log_file', fallback='security_events.log')
        self.output_log_file = os.path.join(log_dir, log_filename)
        print(f"[EventLogCollector] ログ出力ファイル: {self.output_log_file}")

        self.log_channels = ['Security', 'Application', 'Microsoft-Windows-PowerShell/Operational']

        include_ids_str = config.get('EventLogFiltering', 'include_event_ids', fallback='')
        if include_ids_str:
            self.include_event_ids = {int(eid.strip()) for eid in include_ids_str.split(',')}
            print(f"[EventLogCollector] イベントIDによるフィルタリングが有効です: {self.include_event_ids}")
        else:
            self.include_event_ids = None
            print("[EventLogCollector] イベントIDフィルターが無効です。全てのイベントを収集します。")

        self.last_record_ids = {channel: 0 for channel in self.log_channels}

    def start(self):
        self.running = True
        print("Windowsイベントログ収集サービスを開始しました。")
        # 起動時に各チャンネルの最新ログIDを取得して、古いログを無視するようにする
        for channel in self.log_channels:
            try:
                query_handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection)
                events = win32evtlog.EvtNext(query_handle, 1)
                if events:
                    xml_content = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
                    self.last_record_ids[channel] = int(ET.fromstring(xml_content).find('{http://schemas.microsoft.com/win/2004/08/events/event}System').find('{http://schemas.microsoft.com/win/2004/08/events/event}EventRecordID').text)
            except win32evtlog.error:
                pass # チャンネルが存在しない場合は何もしない

        while self.running:
            for channel in self.log_channels:
                self.process_channel(channel)
            time.sleep(5)

    def stop(self):
        self.running = False
        print("Windowsイベントログ収集サービスを停止しました。")

    def process_channel(self, channel):
        try:
            query_handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection)
            
            events_to_process = []
            while self.running:
                events = win32evtlog.EvtNext(query_handle, 100)
                if not events:
                    break
                
                for event in events:
                    xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    record_id = int(ET.fromstring(xml_content).find('{http://schemas.microsoft.com/win/2004/08/events/event}System').find('{http://schemas.microsoft.com/win/2004/08/events/event}EventRecordID').text)
                    
                    if record_id > self.last_record_ids.get(channel, 0):
                        events_to_process.append(event)
                    else:
                        break
                else:
                    continue
                break

            if not events_to_process:
                return

            latest_id_in_batch = 0
            with open(self.output_log_file, 'a', encoding='utf-8') as f:
                for event in reversed(events_to_process):
                    xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    parsed_event = self.parse_event_xml(xml_content, channel)

                    if parsed_event:
                        event_id = parsed_event.get("winlog", {}).get("event_id")
                        # --- ▼ここから修正 (フィルターロジックを確実に動作させる) ---
                        if self.include_event_ids:
                            if event_id in self.include_event_ids:
                                f.write(json.dumps(parsed_event, ensure_ascii=False) + '\r\n')
                        else: # フィルターが設定されていない場合は全て書き込む
                            f.write(json.dumps(parsed_event, ensure_ascii=False) + '\r\n')
                        # --- ▲ここまで修正 ---
                    
                    record_id = parsed_event.get("winlog", {}).get("record_id", 0)
                    if record_id > latest_id_in_batch:
                        latest_id_in_batch = record_id
            
            if latest_id_in_batch > 0:
                self.last_record_ids[channel] = latest_id_in_batch
            
        except win32evtlog.error:
            pass
        except Exception as e:
            print(f"CRITICAL: チャンネル '{channel}' の処理中に予期せぬエラー: {e}")

    def parse_event_xml(self, xml_content, channel):
        try:
            root = ET.fromstring(xml_content)
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            system_part = root.find('e:System', ns)
            event_id = int(system_part.find('e:EventID', ns).text)
            record_id = int(system_part.find('e:EventRecordID', ns).text) # record_idを追加
            provider = system_part.find('e:Provider', ns).get('Name')
            
            event_data_part = root.find('e:EventData', ns)
            event_data = {}
            if event_data_part is not None:
                for data in event_data_part.findall('e:Data', ns):
                    key = data.get('Name')
                    value = data.text
                    if key:
                        event_data[key] = value

            user_data_part = root.find('e:UserData', ns)
            if user_data_part is not None:
                 for elem in user_data_part.iter():
                     if '}' in elem.tag:
                         key = elem.tag.split('}')[-1]
                         event_data[key] = elem.text

            return {
                "winlog": {
                    "channel": channel,
                    "provider_name": provider,
                    "event_id": event_id,
                    "record_id": record_id, # record_idを追加
                    "event_data": event_data
                }
            }
        except Exception:
            return None