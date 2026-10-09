import requests
import concurrent.futures
from core.output import save_txt, unique_list, debug_log
from core.utils import get_tool_timeout, reconstruct_url, is_valid_url

# =========================================================
# ☁️ CLOUD RECON MODULE (S3 / AZURE / GCP / DIGITALOCEAN)
# =========================================================

def check_bucket(platform_name, url, timeout=5, custom_headers=None):
    """
    Checks if a cloud bucket exists and is public.
    Returns dict with status, platform, and url or None.
    """
    try:
        req_headers = {"User-Agent": "Mozilla/5.0"}
        if custom_headers:
            for h in custom_headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    req_headers[k.strip()] = v.strip()
        r = requests.get(url, timeout=timeout, headers=req_headers)
        # 200 OK -> Likely public and listable
        if r.status_code == 200:
            status = "PUBLIC" if ("ListBucketResult" in r.text or "BlobList" in r.text or "<Contents>" in r.text) else "ALIVE"
            return {"status": status, "platform": platform_name, "url": url}
        # 403 Forbidden -> Exists but protected
        elif r.status_code == 403:
            return {"status": "PROTECTED", "platform": platform_name, "url": url}
        return None
    except Exception:
        return None


def run_cloud_recon(domain, paths, base_latency=5, custom_headers=None):
    print(f"\n[+] Running Cloud Recon for {domain} (Concurrent Engine)")
    
    http_timeout = min(5, max(3, base_latency))
    name = domain.split(".")[0]
    
    suffixes = [
        "", "backup", "dev", "staging", "test", "prod", 
        "public", "static", "assets", "data", "files",
        "archive", "internal", "web", "docs", "apps",
        "api", "logs", "db", "sql", "storage", "cloud",
        "private", "secure", "content", "resources"
    ]
    
    separators = ["", "-", "_", "."]
    bucket_names = set()
    bucket_names.add(name)
    bucket_names.add(domain.replace(".", "-"))
    
    for s in suffixes:
        if not s:
            continue
        for sep in separators:
            bucket_names.add(f"{name}{sep}{s}")
            bucket_names.add(f"{domain.split('.')[0]}{sep}{s}")

    platforms = {
        "AWS S3": "https://{name}.s3.amazonaws.com",
        "GCP Storage": "https://storage.googleapis.com/{name}",
        "Azure Blob": "https://{name}.blob.core.windows.net",
        "DO Spaces": "https://{name}.nyc3.digitaloceanspaces.com"
    }

    targets_to_check = []
    for b_name in bucket_names:
        for p_name, p_url in platforms.items():
            targets_to_check.append((p_name, p_url.format(name=b_name)))

    print(f"[?] Probing {len(targets_to_check)} cloud targets across 4 providers concurrently...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        future_to_target = {
            executor.submit(check_bucket, p_name, url, http_timeout, custom_headers): (p_name, url)
            for p_name, url in targets_to_check
        }
        for future in concurrent.futures.as_completed(future_to_target):
            res = future.result()
            if res:
                print(f"    ⭐ [{res['status']}] {res['platform']}: {res['url']}")
                results.append(res)

    # Sort and extract pure URLs
    cloud_urls = []
    report_lines = []
    for r in results:
        u = reconstruct_url(r["url"])
        if u and is_valid_url(u):
            cloud_urls.append(u)
            report_lines.append(f"[{r['status']}] {r['platform']}: {u}")

    cloud_urls = unique_list(cloud_urls)
    report_lines = unique_list(report_lines)

    cloud_dir = paths.get('cloud', paths['base'])
    save_txt(f"{cloud_dir}/cloud_assets.txt", cloud_urls)

    with open(f"{cloud_dir}/cloud_report.txt", "w") as f:
        f.write(f"☁️ CLOUD RECON REPORT: {domain}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"📂 Cloud Assets Discovered: {len(cloud_urls)}\n")
        f.write("-" * 60 + "\n")
        for line in report_lines:
            f.write(f"• {line}\n")

    if cloud_urls:
        print(f"[+] Cloud Recon complete. Found {len(cloud_urls)} assets.")
    else:
        print("[-] No cloud assets found.")

    return cloud_urls
