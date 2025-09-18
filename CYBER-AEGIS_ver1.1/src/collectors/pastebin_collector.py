import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from src.utils.config_manager import ConfigManager
import time
import random

class PastebinCollector:
    def __init__(self):
        self.config = ConfigManager()
        self.archive_url = "https://pastebin.com/archive"
        self.raw_url_template = "https://pastebin.com/raw/{paste_id}"
        # ★★★ 待機時間をより積極的に短縮 ★★★
        self.base_delay_seconds = 2 

    def fetch_leaks(self, keywords):
        all_leaks = []
        
        print("[PastebinCollector] Fetching recent pastes from the archive...")
        recent_pastes = self._get_recent_paste_ids()
        if not recent_pastes:
            return []
            
        # ★★★ 一度にスキャンする上限を撤廃 ★★★
        print(f"[PastebinCollector] Found {len(recent_pastes)} pastes. Scanning all of them.")
        
        for paste in recent_pastes:
            # ★★★ 短縮された、人間らしい不規則な待機 ★★★
            human_like_delay = self.base_delay_seconds + random.uniform(0, 3)
            print(f"[PastebinCollector] Waiting for {human_like_delay:.2f}s before scraping paste: {paste['id']}")
            time.sleep(human_like_delay)

            content = self._get_paste_content(paste['id'])
            if content:
                self._process_content(paste, content, keywords, all_leaks)
            
        return all_leaks

    def _get_recent_paste_ids(self):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(self.archive_url, headers=headers, timeout=20)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'lxml')
            paste_table = soup.find('table', class_='maintable')
            
            pastes = []
            if paste_table:
                for row in paste_table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if len(cols) > 1:
                        link = cols[0].find('a')
                        if link and link['href']:
                            paste_id = link['href'].strip('/')
                            title = link.text
                            pastes.append({'id': paste_id, 'title': title})
            return pastes
        except requests.RequestException as e:
            print(f"[PastebinCollector] Error fetching archive page: {e}")
            return None

    def _get_paste_content(self, paste_id):
        try:
            url = self.raw_url_template.format(paste_id=paste_id)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()
            return response.text
        except requests.RequestException:
            return None

    def _process_content(self, paste_info, content, keywords, all_leaks):
        content_lower = content.lower()
        for keyword in keywords:
            if keyword.lower() in content_lower:
                all_leaks.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "Pastebin",
                    "keyword": keyword,
                    "title": paste_info.get('title', 'No Title'),
                    "url": f"https://pastebin.com/{paste_info['id']}",
                    "content_preview": content[:200] + "..."
                })
                break

def run_pastebin_collector_sync():
    config = ConfigManager()
    keywords_str = config.get('SNS_MONITOR', 'pastebin_keywords', fallback='')
    keywords = [k.strip() for k in keywords_str.split(',') if k.strip()]
    if not keywords:
        return []
    
    collector = PastebinCollector()
    return collector.fetch_leaks(keywords)