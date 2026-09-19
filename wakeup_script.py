# wakeup_script.py
import sys
import time
from playwright.sync_api import sync_playwright

# 从命令行获取要访问的 URL
if len(sys.argv) < 2:
    print("Error: Please provide a URL as a command-line argument.")
    sys.exit(1)

url = sys.argv[1]

print(f"Starting browser to wake up URL: {url}")

try:
    with sync_playwright() as p:
        # 启动一个无头浏览器 (不会显示界面)
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # 导航到指定的 URL，设置60秒超时
        print("Navigating to the page...")
        page.goto(url, timeout=60000)
        
        # 打印页面标题，确认加载成功
        print(f"Page title: '{page.title()}'")
        
        # 等待10秒钟，模拟用户正在查看页面，确保所有脚本都已加载
        print("Waiting for 10 seconds to simulate user activity...")
        time.sleep(10)
        
        print("Closing the browser.")
        browser.close()
        
        print("Wake-up call successful!")
        sys.exit(0)

except Exception as e:
    print(f"An error occurred during the browser automation: {e}")
    # 发生错误时，以失败状态码退出，这样 GitHub Actions 会标记为失败
    sys.exit(1)