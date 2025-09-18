# phishing_monitor.py

import requests
import socket
import ssl
import datetime
import logging
import whois
from OpenSSL import crypto

logging.basicConfig(level=logging.INFO)

MONITORED_DOMAINS = [
    "gmkortodontia.com",
    "jzxyyq.com",
    "malicious-example.com"  # テスト用。存在しないドメイン。
]

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"DNS error: {e}"

def check_http(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        return r.status_code, r.url
    except Exception as e:
        return None, str(e)

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert(True)
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            issuer = dict(x509.get_issuer().get_components())
            issuer_str = issuer.get(b'O', b'unknown').decode()
            not_after = x509.get_notAfter().decode("ascii")
            expire_date = datetime.datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
            return issuer_str, expire_date.strftime("%b %d %H:%M:%S %Y GMT")
    except Exception as e:
        return f"SSL error: {e}", None

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "updated_date": w.updated_date,
            "expiration_date": w.expiration_date,
            "name": w.name,
            "address": w.address,
            "country": w.country,
            "phone": getattr(w, "phone", None),
            "email": w.emails if isinstance(w.emails, list) else [w.emails]
        }
    except Exception as e:
        return f"WHOIS error: {e}"

def generate_report(results):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines = [f"# 詐欺サイト監視レポート\n\n作成日時: {now}\n"]
    for domain, info in results.items():
        report_lines.append(f"## ドメイン: {domain}")
        for key, value in info.items():
            report_lines.append(f"- {key}: {value}")
        report_lines.append("")
    return "\n".join(report_lines)

def save_report_md(content):
    now = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"phishing_report_{now}.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    logging.info(f"Markdownレポートを保存しました: {filename}")

def main():
    logging.info("=== 監視スクリプト開始 ===")
    report_data = {}

    for domain in MONITORED_DOMAINS:
        logging.info(f"=== Monitoring {domain} ===")
        ip = resolve_ip(domain)
        status, redirect = check_http(domain)
        ssl_issuer, ssl_expire = get_ssl_info(domain)
        whois_data = get_whois(domain)

        if isinstance(whois_data, dict):
            whois_processed = {
                "WHOIS更新日": whois_data.get("updated_date"),
                "WHOIS有効期限": whois_data.get("expiration_date"),
                "WHOIS登録者名": whois_data.get("name"),
                "WHOIS住所": whois_data.get("address"),
                "WHOIS電話番号": whois_data.get("phone"),
                "WHOISメールアドレス": whois_data.get("email")
            }
        else:
            whois_processed = {
                "WHOIS情報": whois_data
            }

        report_data[domain] = {
            "IPアドレス": ip,
            "HTTPステータス": f"{status} (リダイレクト先: {redirect})",
            **whois_processed,
            "SSL発行者": ssl_issuer,
            "SSL有効期限": ssl_expire
        }

    report = generate_report(report_data)
    print(report)
    save_report_md(report)
    logging.info("=== 監視スクリプト終了 ===")

if __name__ == "__main__":
    main()