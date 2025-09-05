import re
import time
import subprocess
import pandas as pd
import os
import sys
import logging
from datetime import datetime
from playwright.sync_api import Playwright, sync_playwright
from gooey import Gooey, GooeyParser

# 设置标准输出编码为UTF-8
if sys.platform == 'win32' and sys.stdout is not None:
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        # 如果无法重新配置输出流，则跳过
        pass


def ping(host):
    if sys.platform == "win32":
        result = subprocess.run(['ping', '-n', '1', host], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        result = subprocess.run(['ping', '-n', '1', host], capture_output=True, text=True)
    return result.returncode == 0


def get_mac_address(ip):
    """通过ARP命令获取指定IP的MAC地址"""
    try:
        # 执行ARP命令
        if sys.platform == "win32":
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
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
        logging.warning(f"获取MAC地址失败: {e}")
        return None


def read_device_status(status_log):
    """读取设备状态日志"""
    device_records = {}
    
    if not os.path.exists(status_log):
        return device_records
    
    try:
        with open(status_log, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split('|')
                    if len(parts) >= 5:  # 时间戳|地址|SN|MAC|状态
                        timestamp = parts[0].strip()
                        short_address = parts[1].strip()
                        sn = parts[2].strip()
                        mac = parts[3].strip()
                        status = parts[4].strip()
                        
                        key = f"{short_address}|{sn}"
                        device_records[key] = {
                            'short_address': short_address,
                            'sn': sn,
                            'timestamp': timestamp,
                            'mac': mac,
                            'status': status
                        }
    except Exception as e:
        logging.error(f"读取状态日志文件时出错: {e}")
    
    return device_records


def write_device_status(status_log, short_address, sn, status, mac=None):
    """写入或更新设备状态"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    key = f"{short_address}|{sn}"
    
    try:
        # 读取现有记录
        device_records = read_device_status(status_log)
        
        # 更新或添加记录
        device_records[key] = {
            'short_address': short_address,
            'sn': sn,
            'timestamp': timestamp,
            'mac': mac or 'unknown',
            'status': status
        }
        
        # 按时间戳排序并写入文件
        with open(status_log, 'w', encoding='utf-8') as f:
            for record in sorted(device_records.values(), key=lambda x: x['timestamp']):
                f.write(f"{record['timestamp']}|{record['short_address']}|{record['sn']}|{record['mac']}|{record['status']}\n")
                
    except Exception as e:
        logging.error(f"写入状态日志文件时出错: {e}")


def run(playwright: Playwright, sn: str, modem_type: str, default_password, default_ip) -> bool:
    
    # 设置chromium路径（用于打包后的exe）
    executable_path = None
    if hasattr(sys, '_MEIPASS'):
        # 在打包环境中查找chromium
        chromium_path = os.path.join(sys._MEIPASS, 'chromium', 'chrome-win', 'chrome.exe')
        if os.path.exists(chromium_path):
            executable_path = chromium_path
    
    browser = None
    context = None
    
    try:
        # 所有设备都使用无头模式（不显示浏览器）
        browser = playwright.chromium.launch(headless=True, executable_path=executable_path)
        context = browser.new_context()
        page = context.new_page()
        
        page.goto(f"http://{default_ip}", timeout=10000)
        page.locator("#password").click()
        time.sleep(1)
        page.locator("#password").fill(default_password)
        page.get_by_role("button", name="确定").click()
        time.sleep(1)
        if modem_type == 'F610GV9(1G)':
            page.locator("iframe[name=\"mainFrame\"]").content_frame.get_by_role("cell", name="网络", exact=True).click()
            time.sleep(1)
            page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("a").filter(has_text="远程管理").click()
            time.sleep(1)
            page.locator("iframe[name=\"mainFrame\"]").content_frame.get_by_role("cell", name="宽带识别码认证").click()
            time.sleep(1)
            page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#LoidId_text").click()
            time.sleep(1)
            page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#LoidId_text").press("ControlOrMeta+a")
            time.sleep(1)
            page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#LoidId_text").fill(sn)
            time.sleep(1)
            page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#Loidpwd_checkbox").uncheck()
            time.sleep(1)
            page.locator("iframe[name=\"mainFrame\"]").content_frame.locator("#btnOK").click()
        elif modem_type == 'SK-D841L/SK-D840L(10G)':  
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
        
        return True
        
    except Exception as e:
        print(f"  -> 配置过程中出现错误: {str(e)}")
        return False
        
    finally:
        # 确保浏览器和上下文被正确关闭
        try:
            if context:
                context.close()
            if browser:
                browser.close()
        except:
            pass
             

def process_file(file_path, filter_condition, modem_type, default_password, default_ip):
    
    # 设置结果日志
    today = datetime.now().strftime('%Y%m%d')
    status_log = f"status_{today}.log"
    
    # 读取今天的设备状态
    device_records = read_device_status(status_log)
    
    # 读取xls文件并验证列名
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        logging.error(f"读取Excel文件失败: {e}")
        return
    
    # 验证必需的列名
    required_columns = ['装机地址', 'sn号']
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        logging.error(f"Excel文件缺少必需的列: {', '.join(missing_columns)}")
        logging.error(f"请确保Excel文件包含以下列: {', '.join(required_columns)}")
        return
    
    filtered_df = df[df['装机地址'].str.contains(filter_condition, na=False)]
    
    # 筛选需要处理的设备（只处理未成功配置的设备）
    devices_to_process = []
    skipped_count = 0
    
    for _, row in filtered_df.iterrows():
        address = row['装机地址']
        short_address = filter_condition + address.split(filter_condition, 1)[1]
        sn = row['sn号']
        key = f"{short_address}|{sn}"
        
        # 检查设备是否已经成功配置过
        if key in device_records and device_records[key]['status'] == 'success':
            skipped_count += 1
        else:
            devices_to_process.append({
                'index': len(devices_to_process) + 1,
                'row': row,
                'short_address': short_address,
                'sn': sn
            })
    
    total_count = len(filtered_df)
    process_count = len(devices_to_process)
    

    logging.info(f"找到 {total_count} 条匹配的记录，跳过 {skipped_count} 条已成功记录，开始处理 {process_count} 条记录...")

    if process_count == 0:
        logging.info("所有记录已处理完成！")
        return
    
    # 处理设备
    for i, device in enumerate(devices_to_process, 1):
        short_address = device['short_address']
        sn = device['sn']
        
        # 检查设备是否就绪（第一台设备也需要检查网络）
        logging.info(f"[{i}/{process_count}] 正在处理: {short_address} | SN: {sn}")
        
        # 检查设备是否就绪
        current_mac = check_device_ready(i, process_count, short_address, default_ip, is_first_device=(i == 1))
        
        if current_mac:
            # 设备就绪，启动playwright进行配置
            logging.info(f"[{i}/{process_count}] 设备就绪，开始配置...")
            
            with sync_playwright() as playwright:
                success = run(playwright, sn, modem_type, default_password, default_ip)
                status = 'success' if success else 'fail'
                
                logging.info(f"[{i}/{process_count}] [{'OK' if success else 'FAIL'}] {short_address} {'已写入' if success else '配置失败'} {sn}")
                write_device_status(status_log, short_address, sn, status, current_mac)
        else:
            # 设备检查失败，标记为失败
            logging.warning(f"[{i}/{process_count}] 设备检查失败，跳过配置")
            status = 'fail'
            write_device_status(status_log, short_address, sn, status)
        
        logging.info(f"[{i}/{process_count}] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        

    # 最终统计
    logging.info(f"处理完成！总共: {total_count}, 本次处理: {process_count}")


def check_device_ready(current_num, total_count, next_address, default_ip, is_first_device=False):
    """检查设备是否就绪（网络连接和MAC地址验证）"""
    global previous_mac_address
    
    if not is_first_device:
        logging.info(f"[{current_num}/{total_count}] 请切换到下一台设备, 10秒后自动继续...")
        time.sleep(10)

    # 清理arp缓存
    if sys.platform == "win32":
        subprocess.run(['arp', '-d', default_ip], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        subprocess.run(['arp', '-d', default_ip], capture_output=True, text=True)

    # 等待网络连接，必须 ping 通才能继续
    while not ping(default_ip):
        logging.info(f"[{current_num}/{total_count}] 等待网络连接...")
        # 检查停止标志（这里简化处理，实际应用中可能需要传递停止标志参数）
        time.sleep(3)
    
    # 获取当前设备的MAC地址
    current_mac = get_mac_address(default_ip)
    
    if current_mac:
        logging.info(f"[{current_num}/{total_count}] 当前设备MAC地址: {current_mac}")
        
        # 检查是否与上一个设备相同（如果不是第一台设备）
        if not is_first_device and previous_mac_address and current_mac == previous_mac_address:
            logging.warning(f"[{current_num}/{total_count}] 设备未更换！！！请及时更换设备...")
            return check_device_ready(current_num, total_count, next_address, default_ip, is_first_device=False)
                
        # 更新MAC地址
        previous_mac_address = current_mac
        return current_mac
    
    else:
        logging.warning(f"[{current_num}/{total_count}] 无法获取设备MAC地址，继续执行...")
        return None


@Gooey(
    program_name="光猫助手",
    language='chinese',
    show_config=False,
    show_restart_button=True,
    show_success_modal=False,
    auto_start=False,
    progress_regex=r"\[(\d+)/(\d+)\]",
    progress_expr="x[0] / x[1] * 100",
    hide_progress_msg=False,
    disable_progress_bar_animation=True,
    timing_options={
        'show_time_remaining': True,
        'hide_time_remaining_on_complete': False
    },
    use_legacy_titlebar=False,
    required_cols=1,
    optional_cols=1,
    dump_messages=True,
    use_cmd_args=True,
    encoding='utf-8',
    default_size=(800, 600)
)
def main():
    
    # 配置logging以在Gooey中正确显示输出
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logger = logging.getLogger()
    
    # 移除所有现有的handlers避免重复输出
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # 重定向stdout到logger（用于Gooey）
    class GooeyHandler(logging.Handler):
        def emit(self, record):
            try:
                # 确保输出是UTF-8编码
                message = self.format(record)
                if hasattr(sys.stdout, 'buffer'):
                    sys.stdout.buffer.write(message.encode('utf-8') + b'\n')
                    sys.stdout.buffer.flush()
                else:
                    print(message)
            except Exception:
                # 如果编码失败，使用安全的输出方式
                print(message)

    handler = GooeyHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)

    parser = GooeyParser(description="批量写SN号到指定型号光猫")
    parser.add_argument('file_path', metavar='Excel文件', widget='FileChooser', help='选择xls或xlsx文件，必须包含"装机地址"、"sn号"列')
    parser.add_argument('filter_condition', metavar='筛选条件', help='输入筛选条件，具体到学校xx幢xx层，如江海学院7幢3层')
    parser.add_argument('modem_type', metavar='光猫类型', choices=['F610GV9(1G)', 'SK-D841L/SK-D840L(10G)'], default='F610GV9(1G)', widget='Dropdown', help='选择光猫类型')

    args = parser.parse_args()
    
    process_file(args.file_path, args.filter_condition, args.modem_type, DEFAULT_PASSWORD, DEFAULT_IP)

if __name__ == '__main__':
    # 全局变量定义
    global previous_mac_address
    previous_mac_address = None
    
    # 常量定义
    DEFAULT_PASSWORD = "***"
    DEFAULT_IP = "192.168.1.1"
    
    # 执行主程序
    main()


