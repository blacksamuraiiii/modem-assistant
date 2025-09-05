import re
import time
import subprocess
import pandas as pd
import os
import sys
import logging
import tempfile
from datetime import datetime
from playwright.sync_api import Playwright, sync_playwright
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk, Canvas
import threading
from contextlib import contextmanager

# 设置标准输出编码为UTF-8
if sys.platform == 'win32' and sys.stdout is not None:
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        # 如果无法重新配置输出流，则跳过
        pass


# 状态常量定义
STATUS_PENDING = 'pending'    # 待运行
STATUS_RUNNING = 'running'    # 运行中
STATUS_SUCCESS = 'success'    # 成功
STATUS_FAILED = 'failed'      # 失败

# 状态颜色映射
STATUS_COLORS = {
    STATUS_PENDING: 'gray',
    STATUS_RUNNING: 'blue',
    STATUS_SUCCESS: 'green',
    STATUS_FAILED: 'red'
}

# 配置常量
DEFAULT_IP = "192.168.1.1"
DEFAULT_PASSWORD = "***"


class DeviceManager:
    """设备管理器：管理设备状态和MAC地址跟踪"""
    
    def __init__(self):
        self.previous_mac = None
        self.lock = threading.Lock()
    
    def get_previous_mac(self):
        with self.lock:
            return self.previous_mac
    
    def set_previous_mac(self, mac):
        with self.lock:
            self.previous_mac = mac


class ProcessExecutor:
    """进程执行器：统一处理子进程管理"""
    
    def __init__(self):
        self.processes = {}
        self.lock = threading.Lock()
    
    def add_process(self, item_id, process, stop_event):
        with self.lock:
            self.processes[item_id] = (process, stop_event)
    
    def remove_process(self, item_id):
        with self.lock:
            if item_id in self.processes:
                del self.processes[item_id]
    
    def stop_all_processes(self):
        with self.lock:
            for item_id, (process, stop_event) in list(self.processes.items()):
                try:
                    stop_event.set()
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                except Exception as e:
                    logging.error(f"终止进程时出现错误: {e}")
            self.processes.clear()
    
    def stop_process(self, item_id):
        with self.lock:
            if item_id in self.processes:
                process, stop_event = self.processes[item_id]
                try:
                    stop_event.set()
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                except Exception as e:
                    logging.error(f"终止进程时出现错误: {e}")
                finally:
                    self.remove_process(item_id)


class ScriptGenerator:
    """脚本生成器：处理临时脚本生成和清理"""
    
    @staticmethod
    def create_device_script(sn, modem_type, password, default_ip):
        """创建设备配置脚本"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        script_content = f"""import sys
import os
sys.path.insert(0, r'{current_dir}')
from app_ctk import run, sync_playwright
from datetime import datetime
with sync_playwright() as playwright:
    success = run(playwright, {repr(sn)}, {repr(modem_type)}, {repr(password)}, {repr(default_ip)})
    sys.exit(0 if success else 1)
"""
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
        temp_file.write(script_content)
        temp_file.close()
        return temp_file.name
    
    @staticmethod
    @contextmanager
    def temporary_script(sn, modem_type, password, default_ip):
        """临时脚本上下文管理器"""
        script_path = None
        try:
            script_path = ScriptGenerator.create_device_script(sn, modem_type, password, default_ip)
            yield script_path
        finally:
            if script_path and os.path.exists(script_path):
                try:
                    os.unlink(script_path)
                except Exception as e:
                    logging.error(f"删除临时文件失败: {e}")


# 全局实例
device_manager = DeviceManager()
process_executor = ProcessExecutor()


def error_handler(func):
    """错误处理装饰器"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"在 {func.__name__} 中发生错误: {str(e)}")
            # 如果是App类的方法，尝试调用log_message
            if args and hasattr(args[0], 'log_message'):
                args[0].log_message(f"错误: {str(e)}")
            return None
    return wrapper


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


def process_file(file_path, filter_condition, modem_type, default_password, default_ip, log_callback=None):

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
        if log_callback:
            log_callback(f"读取Excel文件失败: {e}")
        return

    # 验证必需的列名
    required_columns = ['装机地址', 'sn号']
    missing_columns = [col for col in required_columns if col not in df.columns]

    if missing_columns:
        logging.error(f"Excel文件缺少必需的列: {', '.join(missing_columns)}")
        logging.error(f"请确保Excel文件包含以下列: {', '.join(required_columns)}")
        if log_callback:
            log_callback(f"Excel文件缺少必需的列: {', '.join(missing_columns)}")
            log_callback(f"请确保Excel文件包含以下列: {', '.join(required_columns)}")
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

    if log_callback:
        log_callback(f"找到 {total_count} 条匹配的记录，跳过 {skipped_count} 条已成功记录，开始处理 {process_count} 条记录...")

    logging.info(f"找到 {total_count} 条匹配的记录，跳过 {skipped_count} 条已成功记录，开始处理 {process_count} 条记录...")

    if process_count == 0:
        logging.info("所有记录已处理完成！")
        if log_callback:
            log_callback("所有记录已处理完成！")
        return

    # 处理设备
    for i, device in enumerate(devices_to_process, 1):
        short_address = device['short_address']
        sn = device['sn']

        # 检查设备是否就绪（第一台设备也需要检查网络）
        if log_callback:
            log_callback(f"[{i}/{process_count}] 正在处理: {short_address} | SN: {sn}")

        logging.info(f"[{i}/{process_count}] 正在处理: {short_address} | SN: {sn}")

        # 检查设备是否就绪
        current_mac = check_device_ready(i, process_count, short_address, default_ip, is_first_device=(i == 1), log_callback=log_callback)

        if current_mac:
            # 设备就绪，启动playwright进行配置
            if log_callback:
                log_callback(f"[{i}/{process_count}] 设备就绪，开始配置...")

            logging.info(f"[{i}/{process_count}] 设备就绪，开始配置...")

            with sync_playwright() as playwright:
                success = run(playwright, sn, modem_type, default_password, default_ip)
                status = 'success' if success else 'fail'

                if log_callback:
                    log_callback(f"[{i}/{process_count}] [{'OK' if success else 'FAIL'}] {short_address} {'已写入' if success else '配置失败'} {sn}")

                logging.info(f"[{i}/{process_count}] [{'OK' if success else 'FAIL'}] {short_address} {'已写入' if success else '配置失败'} {sn}")
                write_device_status(status_log, short_address, sn, status, current_mac)
        else:
            # 设备检查失败，标记为失败
            if log_callback:
                log_callback(f"[{i}/{process_count}] 设备检查失败，跳过配置")

            logging.warning(f"[{i}/{process_count}] 设备检查失败，跳过配置")
            status = 'fail'
            write_device_status(status_log, short_address, sn, status)

        if log_callback:
            log_callback(f"[{i}/{process_count}] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        logging.info(f"[{i}/{process_count}] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # 最终统计
    if log_callback:
        log_callback(f"处理完成！总共: {total_count}, 本次处理: {process_count}")

    logging.info(f"处理完成！总共: {total_count}, 本次处理: {process_count}")


def check_device_ready(current_num, total_count, next_address, default_ip, is_first_device=False, log_callback=None, stop_flag=None):
    """检查设备是否就绪（网络连接和MAC地址验证）"""
    if not is_first_device:
        if log_callback:
            log_callback(f"[{current_num}/{total_count}] 请切换到下一台设备, 10秒后自动继续...")
        # 检查停止标志，更频繁地检查
        for _ in range(100):  # 10秒 = 100 * 0.1秒
            if stop_flag and stop_flag.is_set():
                return None
            time.sleep(0.1)

    # 清理arp缓存
    if sys.platform == "win32":
        subprocess.run(['arp', '-d', default_ip], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        subprocess.run(['arp', '-d', default_ip], capture_output=True, text=True)

    # 等待网络连接，必须 ping 通才能继续
    while not ping(default_ip):
        if log_callback:
            log_callback(f"[{current_num}/{total_count}] 等待网络连接...")
        # 检查停止标志，更频繁地检查（每0.1秒检查一次，总共10秒）
        for _ in range(100):  # 10秒 = 100 * 0.1秒
            if stop_flag and stop_flag.is_set():
                return None
            time.sleep(0.1)

    # 获取当前设备的MAC地址
    current_mac = get_mac_address(default_ip)

    if current_mac:
        if log_callback:
            log_callback(f"[{current_num}/{total_count}] 当前设备MAC地址: {current_mac}")

        logging.info(f"[{current_num}/{total_count}] 当前设备MAC地址: {current_mac}")

        # 检查是否与上一个设备相同（如果不是第一台设备）
        if not is_first_device:
            previous_mac = device_manager.get_previous_mac()
            if previous_mac and current_mac == previous_mac:
                if log_callback:
                    log_callback(f"[{current_num}/{total_count}] 设备未更换！！！请及时更换设备...")
                logging.warning(f"[{current_num}/{total_count}] 设备未更换！！！请及时更换设备...")
                # 检查停止标志
                if stop_flag and stop_flag.is_set():
                    return None
                return check_device_ready(current_num, total_count, next_address, default_ip, is_first_device=False, log_callback=log_callback, stop_flag=stop_flag)

        # 更新MAC地址
        device_manager.set_previous_mac(current_mac)
        return current_mac

    else:
        if log_callback:
            log_callback(f"[{current_num}/{total_count}] 无法获取设备MAC地址，继续执行...")
        logging.warning(f"[{current_num}/{total_count}] 无法获取设备MAC地址，继续执行...")
        return None


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 设置外观
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # 高 DPI 支持设置
        try:
            import ctypes
            if sys.platform == "win32":
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
                scaling = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100.0
            else:
                scaling = 1.0
            
            ctk.set_widget_scaling(scaling)
            self.tk.call('tk', 'scaling', scaling)
        except Exception:
            ctk.set_widget_scaling(1.0)
            self.tk.call('tk', 'scaling', 1.0)

        # 窗口配置
        self.title("光猫助手")
        self.geometry("900x700")
        self.minsize(800, 600)
        self.resizable(True, True)

        # 全局变量
        self.selected_file_path = None
        self.devices_data = []  # 设备数据列表
        self.device_buttons = {}  # 存储设备按钮引用
        self.stop_batch = False  # 批量执行停止标志

        # 创建UI组件
        self.create_widgets()

        # 配置网格布局权重
        self.grid_rowconfigure(8, weight=2)  # 日志文本框占用更多空间
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=0)  # 按钮列不伸缩

    def create_widgets(self):
        # 文件选择部分
        self.file_label = ctk.CTkLabel(self, text="Excel文件:")
        self.file_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.file_entry = ctk.CTkEntry(self, placeholder_text="选择xls或xlsx文件，必须包含'装机地址'、'sn号'列", width=300)
        self.file_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        self.file_button = ctk.CTkButton(self, text="浏览", command=self.select_file, width=60)
        self.file_button.grid(row=0, column=2, padx=10, pady=5)

        # 筛选条件部分
        self.filter_label = ctk.CTkLabel(self, text="筛选条件:")
        self.filter_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.filter_entry = ctk.CTkEntry(self, placeholder_text="输入筛选条件，具体到学校xx幢xx层，如江海学院7幢3层", width=300)
        self.filter_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        self.refresh_button = ctk.CTkButton(self, text="刷新", command=self.load_devices, width=60)
        self.refresh_button.grid(row=1, column=2, padx=10, pady=5)

        # 光猫类型和密码部分
        self.modem_label = ctk.CTkLabel(self, text="光猫类型:")
        self.modem_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.modem_combo = ctk.CTkComboBox(
            self,
            values=['F610GV9(1G)', 'SK-D841L/SK-D840L(10G)'],
            command=self.modem_changed,
            width=200
        )
        self.modem_combo.grid(row=2, column=1, sticky="w", padx=10, pady=5)
        self.modem_combo.set('F610GV9(1G)')  # 设置默认值

        self.password_label = ctk.CTkLabel(self, text="登录密码:")
        self.password_label.grid(row=2, column=1, padx=(220, 5), pady=5, sticky="w")

        self.password_entry = ctk.CTkEntry(self, placeholder_text="默认密码***", width=100)
        self.password_entry.grid(row=2, column=1, padx=(300, 10), pady=5, sticky="w")
        self.password_entry.insert(0, DEFAULT_PASSWORD)  # 设置默认密码

        # 创建设备表格
        self.create_device_table()

        # 单条执行/批量执行按钮区域
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        self.single_button = ctk.CTkButton(
            self.button_frame,
            text="单条执行",
            command=self.start_single_processing,
            height=35,
            font=ctk.CTkFont(size=12, weight="bold"),
            width=100
        )
        self.single_button.grid(row=0, column=0, padx=(10, 5), pady=10)

        self.batch_button = ctk.CTkButton(
            self.button_frame,
            text="批量执行",
            command=self.start_batch_processing,
            height=35,
            font=ctk.CTkFont(size=12, weight="bold"),
            width=100
        )
        self.batch_button.grid(row=0, column=1, padx=5, pady=10)

        self.stop_button = ctk.CTkButton(
            self.button_frame,
            text="停止",
            command=self.stop_batch_processing,
            height=35,
            fg_color="red",
            hover_color="darkred",
            state="disabled",  # 初始状态为禁用
            width=100
        )
        self.stop_button.grid(row=0, column=2, padx=(5, 10), pady=10)

        # 日志显示区域
        self.log_label = ctk.CTkLabel(self, text="处理日志:")
        self.log_label.grid(row=6, column=0, padx=10, pady=5, sticky="w")

        self.log_textbox = ctk.CTkTextbox(self, wrap="word", height=150)
        self.log_textbox.grid(row=7, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")

        # 底部信息栏
        self.info_label = ctk.CTkLabel(self, text="就绪", font=ctk.CTkFont(size=10))
        self.info_label.grid(row=8, column=0, columnspan=3, padx=10, pady=5, sticky="w")


    def create_device_table(self):
        """创建设备表格"""
        # 创建设备表格框架
        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.grid(row=3, column=0, columnspan=3, padx=20, pady=10, sticky="nsew")

        # 配置表格框架的网格权重
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        # 创建Treeview表格
        columns = ('address', 'sn', 'mac', 'status')
        self.device_tree = ttk.Treeview(
            self.table_frame,
            columns=columns,
            show='headings',
            height=10
        )

        # 设置列标题
        self.device_tree.heading('address', text='装机地址')
        self.device_tree.heading('sn', text='SN号')
        self.device_tree.heading('mac', text='MAC地址')
        self.device_tree.heading('status', text='状态')

        # 设置列宽度
        self.device_tree.column('address', width=200, minwidth=150)
        self.device_tree.column('sn', width=150, minwidth=100)
        self.device_tree.column('mac', width=150, minwidth=120)
        self.device_tree.column('status', width=80, minwidth=60)

        # 创建滚动条
        scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)

        # 布局表格和滚动条
        self.device_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # 绑定双击事件
        self.device_tree.bind('<Double-1>', self.on_tree_double_click)

    def on_tree_double_click(self, event):
        """处理表格双击事件"""
        # 获取选中的项目
        selected_items = self.device_tree.selection()
        if selected_items:
            item_id = selected_items[0]
            # 找到对应的设备数据
            for device in self.devices_data:
                if device['id'] == item_id:
                    short_address = device['short_address']
                    sn = device['sn']
                    current_status = device['status']

                    # 给单条执行特权，无论是success还是fail，只要点击单条执行或者双击，都会强制输入
                    self.run_single_device(short_address, sn, item_id)
                    break

    def load_devices(self):
        """加载设备数据到表格"""
        if not self.selected_file_path:
            # 不弹出警告，只是记录日志
            self.log_message("请先选择Excel文件！")
            return

        filter_condition = self.filter_entry.get().strip()
        
        try:
            # 读取Excel文件
            df = pd.read_excel(self.selected_file_path)

            # 验证必需的列名
            required_columns = ['装机地址', 'sn号']
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                self.log_message(f"Excel文件缺少必需的列: {', '.join(missing_columns)}")
                return

            # 根据筛选条件筛选数据
            if filter_condition:
                filtered_df = df[df['装机地址'].str.contains(filter_condition, na=False)]
            else:
                # 如果没有筛选条件，显示所有数据
                filtered_df = df

            # 清空现有表格数据
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)

            # 清空设备数据和按钮引用
            self.devices_data = []
            self.device_buttons = {}

            # 读取历史状态
            today = datetime.now().strftime('%Y%m%d')
            status_log = f"status_{today}.log"
            device_records = read_device_status(status_log)

            # 填充表格
            for idx, row in filtered_df.iterrows():
                address = row['装机地址']
                # 处理地址，如果没有筛选条件则使用完整地址
                if filter_condition:
                    short_address = filter_condition + address.split(filter_condition, 1)[1]
                else:
                    short_address = address
                sn = row['sn号']
                key = f"{short_address}|{sn}"

                # 确定设备状态和MAC地址
                mac_address = ''
                if key in device_records:
                    status = device_records[key]['status']
                    mac_address = device_records[key]['mac']
                else:
                    status = STATUS_PENDING

                # 添加到表格
                item_id = self.device_tree.insert('', 'end', values=(short_address, sn, mac_address, ''))

                # 创建设备数据
                device_data = {
                    'id': item_id,
                    'short_address': short_address,
                    'sn': sn,
                    'mac': mac_address,
                    'status': status,
                    'row_data': row
                }
                self.devices_data.append(device_data)

                # 更新状态显示
                self.update_device_status(item_id, status)

            self.log_message(f"已加载 {len(filtered_df)} 条设备记录")

            if len(filtered_df) == 0:
                self.log_message("提示：没有找到匹配的设备记录")

        except Exception as e:
            self.log_message(f"加载设备数据失败: {str(e)}")

    def update_device_status(self, item_id, status):
        """更新设备状态显示"""
        # 获取状态颜色
        color = STATUS_COLORS.get(status, 'gray')

        # 创建状态指示器（使用Unicode圆点字符）
        status_indicator = f"● {status}"

        # 更新表格数据
        current_values = list(self.device_tree.item(item_id, 'values'))
        current_values[3] = status_indicator  # 状态列（现在是第4列）
        self.device_tree.item(item_id, values=current_values)

        # 设置标签以应用颜色样式
        self.device_tree.item(item_id, tags=(status,))

        # 配置标签样式
        self.device_tree.tag_configure(STATUS_PENDING, foreground='gray')
        self.device_tree.tag_configure(STATUS_RUNNING, foreground='blue')
        self.device_tree.tag_configure(STATUS_SUCCESS, foreground='green')
        self.device_tree.tag_configure(STATUS_FAILED, foreground='red')

        # 更新设备数据中的状态
        for device in self.devices_data:
            if device['id'] == item_id:
                device['status'] = status
                break
    def create_action_buttons(self, item_id, short_address, sn):
        """为设备创建操作按钮"""
        # 在表格中嵌入按钮比较复杂，这里我们采用另一种方式
        # 可以通过右键菜单或者在单独的框架中放置按钮
        pass

    def run_device(self, short_address, sn, item_id):
        """运行设备"""
        # 检查设备状态，只有待运行状态才能运行
        for device in self.devices_data:
            if device['id'] == item_id and device['status'] == STATUS_PENDING:
                self.run_single_device(short_address, sn, item_id)
                return
        self.log_message(f"设备 {short_address} 状态不是待运行，无法执行运行操作")

    def stop_device(self, short_address, sn, item_id):
        """终止设备"""
        # 检查设备状态，只有运行中状态才能终止
        for device in self.devices_data:
            if device['id'] == item_id and device['status'] == STATUS_RUNNING:
                # 设置停止标志
                if hasattr(self, 'running_threads'):
                    for thread, stop_event in self.running_threads:
                        # 这里需要更精确地找到对应的线程
                        stop_event.set()
                self.update_device_status(item_id, STATUS_FAILED)
                self.log_message(f"设备 {short_address} 已终止")
                return
        self.log_message(f"设备 {short_address} 状态不是运行中，无法执行终止操作")

    def retry_device(self, short_address, sn, item_id):
        """重试设备"""
        # 检查设备状态，只有失败状态才能重试
        for device in self.devices_data:
            if device['id'] == item_id and device['status'] == STATUS_FAILED:
                self.run_single_device(short_address, sn, item_id)
                return
        self.log_message(f"设备 {short_address} 状态不是失败，无法执行重试操作")


    def _execute_device(self, short_address, sn, item_id, current_num, total_count, is_first_device=True, stop_event=None):
        """执行设备配置的核心逻辑"""
        try:
            # 检查设备是否就绪
            current_mac = check_device_ready(current_num, total_count, short_address, DEFAULT_IP, 
                                          is_first_device=is_first_device, log_callback=self.log_message, stop_flag=stop_event)
            
            # 检查是否需要停止
            if stop_event and stop_event.is_set():
                self.log_message(f"设备 {short_address} 处理被用户停止")
                return STATUS_FAILED
            
            # 如果设备未就绪，直接返回失败
            if not current_mac:
                self.log_message(f"设备 {short_address} 检查失败，无法进行配置")
                return STATUS_FAILED
            
            modem_type = self.modem_combo.get()
            password = self.password_entry.get().strip()
            if not password:
                password = "***"  # 使用默认密码

            # 使用ScriptGenerator创建临时脚本
            with ScriptGenerator.temporary_script(sn, modem_type, password, DEFAULT_IP) as script_path:
                # 构造命令参数
                cmd = [sys.executable, script_path]
                
                # 启动子进程
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # 存储子进程引用和停止事件
                process_executor.add_process(item_id, process, stop_event)
                
                # 实时读取子进程输出
                while process.poll() is None and (not stop_event or not stop_event.is_set()):
                    # 非阻塞方式读取输出
                    output = process.stdout.readline()
                    if output:
                        prefix = f"[{current_num}/{total_count}] " if total_count > 1 else ""
                        self.log_message(f"{prefix}设备 {short_address}: {output.strip()}")
                    else:
                        # 短暂休眠以避免CPU占用过高
                        time.sleep(0.1)
                
                # 如果进程还在运行，尝试终止它
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                
                # 获取剩余输出
                remaining_stdout, remaining_stderr = process.communicate()
                
                # 检查是否需要停止
                if stop_event and stop_event.is_set():
                    self.log_message(f"设备 {short_address} 处理被用户停止")
                    return STATUS_FAILED
                
                # 获取子进程返回码
                return_code = process.returncode
                
                # 记录日志
                prefix = f"[{current_num}/{total_count}] " if total_count > 1 else ""
                if remaining_stdout:
                    for line in remaining_stdout.strip().split('\n'):
                        if line.strip():
                            self.log_message(f"{prefix}设备 {short_address}: {line.strip()}")
                if remaining_stderr:
                    for line in remaining_stderr.strip().split('\n'):
                        if line.strip():
                            self.log_message(f"{prefix}设备 {short_address} 错误: {line.strip()}")
                
                # 根据返回码确定状态
                status = STATUS_SUCCESS if return_code == 0 else STATUS_FAILED
                
                if status == STATUS_SUCCESS:
                    self.log_message(f"{prefix}设备 {short_address} 配置成功")
                else:
                    self.log_message(f"{prefix}设备 {short_address} 配置失败")
                
                # 写入状态日志
                today = datetime.now().strftime('%Y%m%d')
                status_log = f"status_{today}.log"
                write_device_status(status_log, short_address, sn, status, current_mac)
                
                return status
                
        except Exception as e:
            self.log_message(f"处理设备 {short_address} 时出现错误: {str(e)}")
            return STATUS_FAILED
        finally:
            # 清理进程引用
            process_executor.remove_process(item_id)

    def run_single_device(self, short_address, sn, item_id):
        """运行单个设备"""
        # 更新状态为运行中
        self.update_device_status(item_id, STATUS_RUNNING)
        
        # 记录开始处理日志
        self.log_message(f"正在处理: {short_address} | SN: {sn}")
        
        # 禁用单条执行按钮，启用停止按钮
        self.single_button.configure(state="disabled")
        self.batch_button.configure(state="disabled")
        self.stop_button.configure(state="normal", text="停止")
        
        # 创建停止事件
        stop_event = threading.Event()
        
        # 在后台线程中执行设备配置
        def run_device_thread():
            try:
                # 使用统一的设备执行方法
                status = self._execute_device(short_address, sn, item_id, 1, 1, True, stop_event)
                
                # 更新状态显示
                self.update_device_status(item_id, status)
                
                # 记录处理完成日志
                self.log_message(f"设备 {short_address} 处理完成")
                
            except Exception as e:
                self.log_message(f"启动设备 {short_address} 时出现错误: {str(e)}")
                self.update_device_status(item_id, STATUS_FAILED)
            finally:
                # 恢复按钮状态
                self.single_button.configure(state="normal")
                self.batch_button.configure(state="normal")
                self.stop_button.configure(state="disabled", text="停止")
        
        # 启动设备处理线程
        device_thread = threading.Thread(target=run_device_thread, daemon=True)
        device_thread.start()

    def start_single_processing(self):
        """开始单条处理"""
        # 获取选中的设备
        selected_items = self.device_tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个设备！")
            return
            
        item_id = selected_items[0]
        
        # 找到对应的设备数据
        selected_device = None
        for device in self.devices_data:
            if device['id'] == item_id:
                selected_device = device
                break
                
        if not selected_device:
            messagebox.showwarning("警告", "未找到选中的设备数据！")
            return
            
        # 给单条执行特权，无论是success还是fail，只要点击单条执行或者双击，都会强制输入
        # 执行单个设备
        self.run_single_device(selected_device['short_address'], selected_device['sn'], item_id)

    def start_batch_processing(self):
        """开始批量处理"""
        if not self.devices_data:
            messagebox.showwarning("警告", "请先加载设备数据！")
            return

        # 重置停止标志
        self.stop_batch = False

        # 禁用批量执行按钮，启用停止按钮
        self.single_button.configure(state="disabled")
        self.batch_button.configure(state="disabled", text="批量执行中...")
        self.stop_button.configure(state="normal", text="停止")

        # 创建线程停止事件
        stop_event = threading.Event()

        # 在后台线程中运行批量处理
        def batch_process_thread():
            try:
                self.log_message("开始批量处理...")

                # 筛选待运行的设备
                pending_devices = [d for d in self.devices_data if d['status'] == STATUS_PENDING]

                if not pending_devices:
                    self.log_message("没有待处理的设备")
                    return

                self.log_message(f"找到 {len(pending_devices)} 条待处理记录")

                for i, device in enumerate(pending_devices, 1):
                    # 检查是否需要停止
                    if self.stop_batch or stop_event.is_set():
                        self.log_message("批量处理已被用户停止")
                        break

                    item_id = device['id']
                    short_address = device['short_address']
                    sn = device['sn']

                    # 更新状态为运行中
                    self.update_device_status(item_id, STATUS_RUNNING)

                    self.log_message(f"[{i}/{len(pending_devices)}] 正在处理: {short_address} | SN: {sn}")

                    try:
                        # 使用统一的设备执行方法
                        status = self._execute_device(short_address, sn, item_id, i, len(pending_devices), 
                                                   is_first_device=(i == 1), stop_event=stop_event)
                        
                        # 更新状态显示
                        self.update_device_status(item_id, status)

                    except Exception as e:
                        self.log_message(f"处理设备 {short_address} 时出现错误: {str(e)}")
                        self.update_device_status(item_id, STATUS_FAILED)

                if not self.stop_batch and not stop_event.is_set():
                    self.log_message("批量处理完成！")
                else:
                    self.log_message("批量处理已停止")

            except Exception as e:
                self.log_message(f"批量处理过程中出现错误: {str(e)}")
                messagebox.showerror("错误", f"批量处理失败: {str(e)}")

            finally:
                # 恢复按钮状态
                self.single_button.configure(state="normal")
                self.batch_button.configure(state="normal", text="批量执行")
                self.stop_button.configure(state="disabled", text="停止")

        # 启动后台线程
        thread = threading.Thread(target=batch_process_thread, daemon=True)
        thread.start()

        # 保存线程引用和停止事件，用于停止功能
        if not hasattr(self, 'running_threads'):
            self.running_threads = []
        self.running_threads.append((thread, stop_event))

    def stop_batch_processing(self):
        """停止批量处理和单条执行"""
        self.stop_batch = True
        self.log_message("正在停止处理...")
        self.stop_button.configure(state="disabled", text="停止中...")
        
        # 停止所有运行中的线程
        if hasattr(self, 'running_threads'):
            for thread, stop_event in self.running_threads:
                stop_event.set()
            self.running_threads.clear()
            
        # 使用ProcessExecutor终止所有进程
        process_executor.stop_all_processes()
        
        # 更新所有运行中设备的状态为失败
        for device in self.devices_data:
            if device['status'] == STATUS_RUNNING:
                self.update_device_status(device['id'], STATUS_FAILED)
                        
        self.log_message("所有进程已停止")
        
        # 恢复按钮状态
        self.single_button.configure(state="normal")
        self.batch_button.configure(state="normal", text="批量执行")
        self.stop_button.configure(state="disabled", text="停止")

    def select_file(self):
        """选择Excel文件"""
        filetypes = [
            ('Excel files', '*.xlsx *.xls'),
            ('All files', '*.*')
        ]

        filename = filedialog.askopenfilename(
            title='选择Excel文件',
            filetypes=filetypes
        )

        if filename:
            self.selected_file_path = filename
            self.file_entry.delete(0, 'end')
            self.file_entry.insert(0, filename)
            self.log_message(f"已选择文件: {filename}")

            # 自动加载设备数据
            self.load_devices()

    def modem_changed(self, choice):
        """光猫类型选择回调"""
        self.log_message(f"已选择光猫类型: {choice}")

        # 如果已有文件和筛选条件，重新加载数据
        if self.selected_file_path and self.filter_entry.get().strip():
            self.load_devices()

    def log_message(self, message):
        """添加日志消息"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"

        self.log_textbox.insert("end", log_entry)
        self.log_textbox.see("end")  # 自动滚动到底部

        # 同时输出到控制台
        print(log_entry.strip())

    def start_processing(self):
        """开始处理按钮回调"""
        # 验证输入
        if not self.selected_file_path:
            messagebox.showerror("错误", "请先选择Excel文件！")
            return

        filter_condition = self.filter_entry.get().strip()
        if not filter_condition:
            messagebox.showerror("错误", "请输入筛选条件！")
            return

        modem_type = self.modem_combo.get()

        # 禁用按钮，防止重复点击
        self.start_button.configure(state="disabled", text="处理中...")
        self.status_label.configure(text="正在处理...")

        # 清空日志
        self.log_textbox.delete("0.0", "end")

        # 在后台线程中运行处理逻辑
        def process_thread():
            try:
                # 获取密码
                password = self.password_entry.get().strip()
                if not password:
                    password = DEFAULT_PASSWORD  # 使用默认密码

                self.log_message("开始处理...")
                self.log_message(f"文件: {self.selected_file_path}")
                self.log_message(f"筛选条件: {filter_condition}")
                self.log_message(f"光猫类型: {modem_type}")
                self.log_message(f"登录密码: {'***' if password == '***' else '自定义密码'}")

                # 调用处理函数
                process_file(
                    self.selected_file_path,
                    filter_condition,
                    modem_type,
                    password,
                    DEFAULT_IP,
                    log_callback=self.log_message
                )

                self.log_message("处理完成！")

            except Exception as e:
                self.log_message(f"处理过程中出现错误: {str(e)}")
                messagebox.showerror("错误", f"处理失败: {str(e)}")

            finally:
                # 恢复按钮状态
                self.start_button.configure(state="normal", text="开始处理")
                self.info_label.configure(text="就绪")

        # 启动后台线程
        thread = threading.Thread(target=process_thread, daemon=True)
        thread.start()


if __name__ == '__main__':
    # 创建并运行应用
    app = App()
    app.mainloop()