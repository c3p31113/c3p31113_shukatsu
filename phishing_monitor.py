import logging
import socket
import requests
import whois
import ssl
from datetime import datetime

logging.basicConfig(level=logging.INFO)

domains_to_monitor = [
    "gmkortodontia.com",
    "jzxyyq.com",
    # 新規監視ドメインをここに追加
]

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        logging.warning(f"[!] DNS error for {domain}: {e}")
        return None

def check_http_status(domain):
    url = f"https://{domain}/"
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        return r.status_code, r.url
    except Exception as e:
        logging.warning(f"[!] HTTP error for {domain}: {e}")
        return None, None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        logging.warning(f"[!] WHOIS error for {domain}: {e}")
        return None

def check_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = cert.get('issuer', ())
            issuer_details = []
            for rdn in issuer:
                for attr in rdn:
                    issuer_details.append(f"{attr[0]}: {attr[1]}")
            issuer_str = ", ".join(issuer_details) if issuer_details else "不明"
            not_after = cert.get('notAfter', '不明')
            expire_dt = None
            if not_after != '不明':
                expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return issuer_str, expire_dt
    except Exception as e:
        logging.warning(f"[!] SSL error for {domain}: {e}")
        return "不明", None

def generate_report(domains):
    now = datetime.now()
    report_lines = []
    report_lines.append("# 詐欺サイト監視レポート\n")
    report_lines.append(f"作成日時: {now.strftime('%Y-%m-%d %H:%M:%S')}\n")

    for d in domains:
        ip = resolve_domain(d)
        http_status, redirect_url = check_http_status(d)
        w = get_whois_info(d)
        issuer, ssl_expire = check_ssl_info(d)

        report_lines.append(f"## ドメイン: {d}")
        report_lines.append(f"- IPアドレス: {ip if ip else 'DNS解決失敗'}")
        if http_status:
            report_lines.append(f"- HTTPステータス: {http_status} (リダイレクト先: {redirect_url})")
        else:
            report_lines.append(f"- HTTPステータス: 取得失敗")
        if w:
            report_lines.append(f"- WHOIS更新日: {w.updated_date}")
            report_lines.append(f"- WHOIS有効期限: {w.expiration_date}")
            report_lines.append(f"- レジストラ: {w.registrar}")
        else:
            report_lines.append(f"- WHOIS情報: 取得失敗")
        report_lines.append(f"- SSL発行者: {issuer}")
        report_lines.append(f"- SSL有効期限: {ssl_expire.strftime('%Y-%m-%d %H:%M:%S') if ssl_expire else '不明'}\n")

    return "\n".join(report_lines)

def main():
    logging.info("=== 監視スクリプト開始 ===")
    report = generate_report(domains_to_monitor)
    print(report)
    logging.info("=== 監視スクリプト終了 ===")

if __name__ == "__main__":
    main()
