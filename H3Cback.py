import paramiko
import pandas as pd
import re
from datetime import datetime
import time
import logging
import os

# 获取当前日期用于日志文件命名
CURRENT_DATE = datetime.now().strftime("%Y%m%d")

# 配置日志，按日期命名
LOG_FILE = f"switch_config_{CURRENT_DATE}.log"
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# 指定保存配置文件的文件夹
CONFIG_DIR = "configs"

def ssh_connect(ip, username, password, port=22):
    """建立SSH连接，强制使用密码认证"""
    logging.info(f"尝试连接到 {ip}，用户名: {username}，密码: {password[:2]}****")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            ip,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False
        )
        logging.info(f"成功连接到 {ip}")
        return ssh
    except paramiko.AuthenticationException as e:
        logging.error(f"连接 {ip} 失败: 认证失败 - {str(e)}")
        return None
    except Exception as e:
        logging.error(f"连接 {ip} 失败: {str(e)}")
        return None

def read_output(shell, command, timeout=120, expected_endings=('#', '>', 'return'), max_buffer_size=131072):
    """封装读取输出函数，多次确认无新内容后结束"""
    logging.debug(f"发送命令: {command.strip()}")
    shell.send(command + "\n")
    output = ""
    start_time = time.time()
    pager_patterns = ["---- More ----", "<More>"]
    last_output_time = start_time
    confirm_count = 0
    CONFIRM_THRESHOLD = 3  # 连续3次无新内容
    CONFIRM_INTERVAL = 2  # 每次确认间隔2秒
    
    while time.time() - start_time < timeout:
        if shell.recv_ready():
            chunk = shell.recv(max_buffer_size).decode('utf-8', errors='ignore')
            for pager in pager_patterns:
                if pager in chunk:
                    output += chunk.replace(pager, "")
                    shell.send(" ")
                    logging.debug(f"检测到分页提示 '{pager}'，发送空格继续读取")
                    time.sleep(0.5)
                    last_output_time = time.time()
                    confirm_count = 0
                    break
            else:
                output += chunk
                last_output_time = time.time()
                confirm_count = 0
            logging.debug(f"收到部分输出: {chunk[-100:]}")
            last_line = output.strip().splitlines()[-1] if output.strip() else ""
            if any(end in last_line for end in expected_endings):
                logging.debug("检测到预期结尾，开始确认无新内容")
        
        if time.time() - last_output_time > 5 and confirm_count < CONFIRM_THRESHOLD:
            confirm_count += 1
            logging.debug(f"第 {confirm_count} 次确认无新输出，等待 {CONFIRM_INTERVAL} 秒")
            time.sleep(CONFIRM_INTERVAL)
            if shell.recv_ready():
                logging.debug("确认期间Delta收到新输出，重置计数")
                confirm_count = 0
                continue
            elif confirm_count == CONFIRM_THRESHOLD:
                logging.debug(f"连续 {CONFIRM_THRESHOLD} 次确认无新输出，结束读取")
                break
        
        time.sleep(0.1)
    
    if not output.strip():
        logging.warning(f"{command} 输出为空")
        return output, False  # 返回输出和是否成功的标志
    last_line = output.strip().splitlines()[-1]
    if not any(end in last_line for end in expected_endings):
        logging.warning(f"{command} 输出未以预期结尾，可能不完整")
        return output, False
    logging.debug(f"{command} 输出以预期结尾: {last_line}")
    return output, True

def check_config_content(content):
    """检查配置文件内容是否有效"""
    if not content.strip():
        logging.error("配置文件内容为空")
        return False
    if not any(keyword in content for keyword in ['sysname', 'interface']):
        logging.warning("配置文件内容可能不完整，未找到关键配置项（如 sysname 或 interface）")
        return False
    logging.debug("配置文件内容有效")
    return True

def get_switch_config(ssh, sn_list, ip):
    """获取交换机配置并保存，SN或配置获取失败时重试"""
    try:
        shell = ssh.invoke_shell()
        logging.debug(f"{ip}: 创建交互式 shell")
        
        shell.send("\n")
        time.sleep(1)
        if shell.recv_ready():
            shell.recv(65535)
            logging.debug(f"{ip}: 清空缓冲区完成")
        
        # 获取设备序列号，尝试3次
        MAX_RETRIES = 3
        for attempt in range(MAX_RETRIES):
            output, success = read_output(shell, "display device manuinfo")
            serial_numbers = re.findall(r'DEVICE_SERIAL_NUMBER\s*:\s*(\S+)', output)
            logging.debug(f"{ip}: 完整序列号输出: {output}")
            logging.info(f"{ip}: 从设备提取的序列号: {serial_numbers}")
            if serial_numbers:
                break
            logging.warning(f"{ip}: 第 {attempt + 1} 次尝试执行 display device manuinfo 未获取序列号")
            if attempt < MAX_RETRIES - 1:
                time.sleep(2)  # 重试前等待2秒
        else:
            logging.error(f"{ip}: {MAX_RETRIES} 次尝试后仍未获取序列号，放弃")
            return False
        
        logging.info(f"{ip}: Excel中的序列号列表: {sn_list}")
        matched_sns = [sn for sn in serial_numbers if sn in sn_list]
        logging.info(f"{ip}: 匹配到的序列号: {matched_sns}")
        
        current_date = datetime.now().strftime("%Y%m%d")
        logging.debug(f"{ip}: 当前日期: {current_date}")
        
        # 确定文件名：SN匹配成功用SN，否则用IP
        if matched_sns:
            if len(matched_sns) == 1:
                filename = f"{matched_sns[0]}_{current_date}.txt"
            else:
                filename = f"{'_'.join(matched_sns)}_{current_date}.txt"
            logging.info(f"{ip}: SN匹配成功，生成文件名: {filename}")
        else:
            filename = f"{ip}_{current_date}.txt"
            logging.warning(f"{ip}: 未找到匹配的序列号，使用IP生成文件名: {filename}")
        
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR)
            logging.info(f"创建文件夹: {CONFIG_DIR}")
        
        filepath = os.path.join(CONFIG_DIR, filename)
        
        # 获取配置，尝试3次
        for attempt in range(MAX_RETRIES):
            config_output, success = read_output(shell, "display current-configuration")
            if success and check_config_content(config_output):
                break
            logging.warning(f"{ip}: 第 {attempt + 1} 次尝试执行 display current-configuration 未正确结束或内容无效")
            if attempt < MAX_RETRIES - 1:
                time.sleep(2)
        else:
            logging.error(f"{ip}: {MAX_RETRIES} 次尝试后仍未获取完整配置，放弃")
            return False
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(config_output)
        logging.info(f"{ip}: 配置已保存到: {filepath}")
        return True
            
    except Exception as e:
        logging.error(f"{ip}: 获取配置失败: {str(e)}")
        return False
    finally:
        ssh.close()
        logging.debug(f"{ip}: SSH连接已关闭")

def main():
    try:
        switch_df = pd.read_excel('switches.xlsx')
        logging.info("成功读取 switches.xlsx")
    except Exception as e:
        logging.error(f"读取交换机信息Excel文件失败: {str(e)}")
        return

    try:
        sn_df = pd.read_excel('sn_list.xlsx')
        sn_list = sn_df['sn'].tolist()
        logging.info(f"成功读取 sn_list.xlsx，SN列表: {sn_list}")
    except Exception as e:
        logging.error(f"读取SN码Excel文件失败: {str(e)}")
        return

    success_devices = []
    failed_devices = []

    for index, row in switch_df.iterrows():
        ip = row['ip']
        username = row['username']
        password = row['password']
        
        logging.info(f"开始处理设备: {ip}")
        
        ssh = ssh_connect(ip, username, password)
        if ssh:
            if get_switch_config(ssh, sn_list, ip):
                success_devices.append(ip)
            else:
                failed_devices.append(ip)
        else:
            failed_devices.append(ip)

    summary = (
        f"\n=== 处理结果汇总 ===\n"
        f"总设备数: {len(switch_df)}\n"
        f"成功设备数: {len(success_devices)}\n"
        f"失败设备数: {len(failed_devices)}\n"
        f"成功设备: {success_devices}\n"
        f"失败设备: {failed_devices}\n"
    )
    logging.info(summary)

if __name__ == "__main__":
    main()