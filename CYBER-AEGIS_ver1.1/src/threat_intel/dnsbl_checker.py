import dns.resolver
import socket

class DNSBLChecker:
    def __init__(self):
        # ★★★ 調査対象のブラックリストを、ブランドごとに整理して追加 ★★★
        self.zones = {
            "Spamhaus": [
                "sbl.spamhaus.org",
                "xbl.spamhaus.org",
                "zen.spamhaus.org"
            ],
            "SpamCop": [
                "bl.spamcop.net"
            ],
            "Barracuda": [
                "b.barracudacentral.org"
            ]
        }

    def check_ip(self, ip_address):
        all_results = {}
        is_listed_anywhere = False
        
        try:
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
            
            # ★★★ 全てのブランドの、全てのリストに一括で問い合わせる ★★★
            for brand, zone_list in self.zones.items():
                brand_results = {}
                for zone in zone_list:
                    query = f"{reversed_ip}.{zone}"
                    try:
                        dns.resolver.resolve(query, 'A')
                        brand_results[zone] = {"listed": True}
                        is_listed_anywhere = True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        brand_results[zone] = {"listed": False}
                all_results[brand] = brand_results
        
        except Exception as e:
            return {"error": f"DNSBLチェック中にエラーが発生しました: {e}"}
        
        summary = {
            "status": "LISTED" if is_listed_anywhere else "OK",
            "details": all_results
        }
        return summary