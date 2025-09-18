# src/threat_intel/orion_investigator.py

import re
import whois
import requests
import socket
from src.utils.config_manager import ConfigManager
from .hibp_checker import HIBPChecker 
from .dnsbl_checker import DNSBLChecker
from .abusech_checker import AbuseChChecker
from .otx_checker import OTXChecker
from .shodan_checker import ShodanChecker
from .insecam_checker import InsecamChecker
from .greynoise_checker import GreyNoiseChecker
from .talos_checker import TalosChecker
from .cisa_kev_checker import CisaKevChecker
from .misp_checker import MispChecker
from .ipqs_checker import IpqsChecker
from .nicter_analyzer import NicterAnalyzer
from .stix_taxii_checker import StixTaxiiChecker
from .intelx_checker import IntelxChecker
from .gdelt_checker import GdeltChecker # GdeltCheckerをインポート

class OrionInvestigator:
    def __init__(self):
        self.config = ConfigManager()
        self.gcp_api_key = self.config.get('API_KEYS', 'gcp_api_key', fallback=None)
        self.virustotal_api_key = self.config.get('API_KEYS', 'virustotal_api_key', fallback=None)
        self.gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gcp_api_key}"
        self.hibp_checker = HIBPChecker() 
        self.dnsbl_checker = DNSBLChecker()
        self.abusech_checker = AbuseChChecker()
        self.otx_checker = OTXChecker()
        self.shodan_checker = ShodanChecker()
        self.insecam_checker = InsecamChecker()
        self.greynoise_checker = GreyNoiseChecker()
        self.talos_checker = TalosChecker()
        self.cisa_kev_checker = CisaKevChecker()
        self.misp_checker = MispChecker()
        self.ipqs_checker = IpqsChecker()
        self.nicter_analyzer = NicterAnalyzer()
        self.stix_taxii_checker = StixTaxiiChecker()
        self.intelx_checker = IntelxChecker()
        self.gdelt_checker = GdeltChecker() # GdeltCheckerを初期化

    def check_talos(self, ip_address: str):
        return self.talos_checker.check_ip(ip_address)

    def check_intelx(self, indicator: str):
        return self.intelx_checker.search_indicator(indicator)

    def get_geopolitical_news(self, keyword: str):
        """GdeltCheckerを呼び出すための新しいメソッド"""
        return self.gdelt_checker.get_geopolitical_news(keyword)

    def check_virustotal_ip(self, ip_address):
        if not self.virustotal_api_key: return {"error": "config.iniにVirusTotalのAPIキー(virustotal_api_key)が設定されていません。"}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.virustotal_api_key}
        try:
            print(f"  > [Orion] Querying VirusTotal for IP: {ip_address}")
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total_engines = sum(stats.values())
            return {
                "malicious_votes": malicious_count, "suspicious_votes": suspicious_count,
                "total_engines": total_engines, "summary": f"{malicious_count + suspicious_count} / {total_engines} のエンジンが脅威を検出"
            }
        except requests.RequestException as e:
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
                return {"summary": "データ未登録"}
            return {"error": f"VirusTotal APIへのリクエスト中にエラー: {e}"}
            
    def check_abusech(self, host_or_ip, full_url):
        results = {"URLHaus": self.abusech_checker.check_urlhaus(full_url), "ThreatFox": self.abusech_checker.check_threatfox(host_or_ip)}
        return results

    def check_otx(self, indicator, indicator_type):
        return self.otx_checker.get_indicator_details(indicator, indicator_type)

    def check_shodan(self, ip_address):
        return self.shodan_checker.check_ip(ip_address)

    def check_insecam(self, ip_address):
        return self.insecam_checker.check_ip(ip_address)

    def check_greynoise(self, ip_address):
        return self.greynoise_checker.check_ip(ip_address)

    def check_cisa_kev(self, product_name):
        return self.cisa_kev_checker.check_product(product_name)

    def check_misp(self, indicator):
        return self.misp_checker.search(indicator)
        
    def check_ipqs(self, ip_address):
        return self.ipqs_checker.check_ip(ip_address)
        
    def get_nicter_trends(self):
        return self.nicter_analyzer.get_top_attack_trends()

    def check_taxii_feeds(self, indicator):
        return self.stix_taxii_checker.search_indicator(indicator)

    def get_whois_info(self, domain):
        if not domain: return {"error": "ドメイン名が指定されていません。"}
        try:
            w = whois.whois(domain)
            whois_data = {
                "ドメイン名": w.domain_name, "登録業者": w.registrar, "作成日時": str(w.creation_date),
                "有効期限": str(w.expiration_date), "最終更新日": str(w.last_updated), "ネームサーバー": w.name_servers,
                "ステータス": w.status, "登録者メールアドレス": w.emails, "登録組織": w.org, "国": w.country,
            }
            return {k: v for k, v in whois_data.items() if v is not None and v}
        except Exception as e:
            return {"error": f"WHOIS情報の取得中にエラーが発生しました: {e}"}

    def check_google_safeBrowse(self, url_to_check):
        if not self.gcp_api_key: return {"error": "config.iniにGCP APIキー(gcp_api_key)が設定されていません。"}
        if not url_to_check: return {"error": "URLが指定されていません。"}
        payload = {
            "client": {"clientId": "cyber-aegis", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url_to_check}]
            }
        }
        try:
            response = requests.post(self.gsb_url, json=payload, timeout=15)
            response.raise_for_status()
            data = response.json()
            if 'matches' in data:
                return {"判定": "危険", "詳細": data['matches']}
            else:
                return {"判定": "安全", "詳細": "Google Safe Browseでは脅威は検出されませんでした。"}
        except requests.RequestException as e:
            return {"error": f"Google Safe Browse APIへのリクエスト中にエラーが発生しました: {e}"}

    def check_pwned_password(self, password):
        return self.hibp_checker.check_password(password)

    def check_dnsbl(self, ip_address):
        try:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
                socket.inet_aton(ip_address)
                return self.dnsbl_checker.check_ip(ip_address)
            else:
                return {"error": "有効なIPv4アドレスではありません。"}
        except (socket.error, TypeError):
            return {"error": "有効なIPv4アドレスではありません。"}