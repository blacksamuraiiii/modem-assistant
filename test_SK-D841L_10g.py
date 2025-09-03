# 测试脚本 10G猫 SK-D841L/SK-D840L

import re
import time
import subprocess
import pandas as pd
import threading
import http.server
import socketserver
from playwright.sync_api import Playwright, sync_playwright, expect


def ping(host):
    result = subprocess.run(['ping', '-n', '1', host], capture_output=True, text=True)
    return result.returncode == 0


def get_mac_address(ip):
    """通过ARP命令获取指定IP的MAC地址"""
    try:
        # 执行ARP命令
        result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)

        if result.returncode == 0:
            # 解析ARP输出，查找MAC地址
            lines = result.stdout.split('\n')
            for line in lines:
                if ip in line:
                    # 先尝试破折号格式
                    mac_match = re.search(r'([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}', line)
                    if mac_match:
                        return mac_match.group(0).upper()

                    # 再尝试冒号格式
                    mac_match = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', line)
                    if mac_match:
                        return mac_match.group(0).upper().replace(':', '-')

            # 如果没有找到MAC地址，尝试更宽松的搜索
            for line in lines:
                if ip in line:
                    # 尝试更通用的MAC地址模式
                    mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                    if mac_match:
                        mac = mac_match.group(0)
                        # 统一转换为破折号格式
                        return mac.upper().replace(':', '-')

        return None
    except Exception as e:
        print(f"获取MAC地址失败: {e}")
        return None


def check_device_ready(current_num, total_count, next_address, default_ip, is_first_device=False):
    """检查设备是否就绪（网络连接和MAC地址验证）"""
    global previous_mac_address

    if not is_first_device:
        print(f"[{current_num}/{total_count}] 请切换到下一台设备, 10秒后自动继续...")
        time.sleep(10)

    # 清理arp缓存
    subprocess.run(['arp', '-d', default_ip], capture_output=True, text=True)

    # 等待网络连接，必须 ping 通才能继续
    while not ping(default_ip):
        print(f"[{current_num}/{total_count}] 等待网络连接...")
        time.sleep(3)

    # 获取当前设备的MAC地址
    current_mac = get_mac_address(default_ip)

    if current_mac:
        print(f"[{current_num}/{total_count}] 当前设备MAC地址: {current_mac}")

        # 检查是否与上一个设备相同（如果不是第一台设备）
        if not is_first_device and previous_mac_address and current_mac == previous_mac_address:
            print(f"[{current_num}/{total_count}] 设备未更换！！！请及时更换设备...")
            return check_device_ready(current_num, total_count, next_address, default_ip, is_first_device=False)

        # 更新MAC地址
        previous_mac_address = current_mac
        return current_mac

    else:
        print(f"[{current_num}/{total_count}] 无法获取设备MAC地址，继续执行...")
        return None


def run(playwright: Playwright, sn: str) -> None:
    browser = playwright.chromium.launch(headless=False)
    context = browser.new_context()
    page = context.new_page()
    page.goto("http://192.168.1.1/cgi-bin/luci")
    page.locator("#password").click()
    time.sleep(1)
    page.locator("#password").fill(DEFAULT_PASSWORD)
    page.get_by_role("button", name="确定").click()
    time.sleep(1)
    page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("a").filter(has_text=re.compile(r"^网络$")).click()
    time.sleep(1)
    page.locator("iframe[name=\"mainFrame\"]").content_frame.get_by_text("远程管理").click()
    time.sleep(1)
    page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#Menu3_NM_Loid").click()
    time.sleep(1)
    page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#LoidId_text").click()
    time.sleep(1)
    page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#LoidId_text").fill(sn)
    page.locator("iframe[name=\"mainFrame\"]").content_frame.get_by_role("button", name="确 定").click()
    time.sleep(1)

    # ---------------------
    context.close()
    browser.close()


# 读取xls文件
df = pd.read_excel('./在途单/江海学院在途装机清单.xls')

# 筛选条件：装机地址包含 '江海学院16幢1层'
target_str = '江海学院16幢1层'
filtered_df = df[df['装机地址'].str.contains(target_str, na=False)]

# 默认密码和IP地址
DEFAULT_PASSWORD = "***"
DEFAULT_IP = "192.168.1.1"

# 全局变量
previous_mac_address = None

# 循环写入
with sync_playwright() as playwright:
    total = len(filtered_df)
    for i, (index, row) in enumerate(filtered_df.iterrows()):
        sn = row['sn号']
        address = row['装机地址']
        short_address = target_str + address.split(target_str, 1)[1]

        # 检查设备是否就绪
        current_mac = check_device_ready(i+1, total, short_address, DEFAULT_IP, is_first_device=(i == 0))

        if current_mac:
            # 设备就绪，开始配置
            print(f"[{i+1}/{total}] 设备就绪，开始配置...")
            run(playwright, sn)
            print(f"[{i+1}/{total}] {short_address}已写入{sn}，已完成")
        else:
            # 设备检查失败，跳过配置
            print(f"[{i+1}/{total}] 设备检查失败，跳过配置")

        if i < total - 1:  # 不是最后一次
            # 下一个设备的检查会在check_device_ready中处理ARP清理
            pass

    print("任务已结束")