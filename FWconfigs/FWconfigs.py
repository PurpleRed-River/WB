import csv
import datetime
import re
import argparse
import os

def log_message(message, verbose, is_verbose_message=False):
    """打印带时间戳的调试信息，verbose 控制是否显示详细日志"""
    if verbose or not is_verbose_message:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")

def convert_to_utf8(file_path, verbose, forced_encoding='gb2312'):
    """直接使用 GB2312 或指定编码转换为 UTF-8，生成临时文件"""
    log_message(f"处理文件编码: {file_path}", verbose, is_verbose_message=True)
    
    # 保存备份文件
    backup_path = file_path + '.backup'
    with open(file_path, 'rb') as f:
        with open(backup_path, 'wb') as bf:
            bf.write(f.read())
    log_message(f"创建备份文件: {backup_path}", verbose, is_verbose_message=True)

    # 使用指定编码或默认 GB2312
    encoding = forced_encoding if forced_encoding else 'gb2312'
    log_message(f"使用编码: {encoding}", verbose, is_verbose_message=True)
    try:
        with open(file_path, 'rb') as file:
            raw_content = file.read()
        content = raw_content.decode(encoding)
        log_message(f"成功以 {encoding} 解码文件", verbose, is_verbose_message=True)
    except UnicodeDecodeError as e:
        log_message(f"错误: 以 {encoding} 解码失败: {e}，使用 UTF-8 替换乱码", verbose)
        content = raw_content.decode('utf-8', errors='replace')
    
    # 转换为 UTF-8
    content = content.encode('utf-8').decode('utf-8')
    
    # 保存 UTF-8 文件
    utf8_path = file_path + '.utf8'
    with open(utf8_path, 'w', encoding='utf-8') as file:
        file.write(content)
    log_message(f"保存 UTF-8 文件: {utf8_path}", verbose, is_verbose_message=True)
    
    return content, backup_path, utf8_path

def parse_policy_groups(file_content, verbose):
    """解析配置文件中的 policy-group 块，返回 policy-group 与 rule ID 的映射"""
    log_message("解析策略组", verbose, is_verbose_message=True)
    policy_groups = {}
    current_group = None
    group_pattern = re.compile(r'policy-group\s+"([^"]+)"', re.IGNORECASE)
    rule_pattern = re.compile(r'rule\s+(?:id\s+)?(\d+)', re.IGNORECASE)
    exit_pattern = re.compile(r'^\s*exit\s*$', re.IGNORECASE)
    
    for line in file_content.splitlines():
        line = line.strip()
        if not line:
            continue
        group_match = group_pattern.match(line)
        if group_match:
            current_group = group_match.group(1)
            policy_groups[current_group] = []
            log_message(f"找到策略组: {current_group}", verbose, is_verbose_message=True)
            continue
        rule_match = rule_pattern.match(line)
        if rule_match and current_group:
            rule_id = rule_match.group(1)
            policy_groups[current_group].append(rule_id)
            log_message(f"策略组 {current_group} 添加 rule ID: {rule_id}", verbose, is_verbose_message=True)
            continue
        if exit_pattern.match(line) and current_group:
            current_group = None
            log_message("退出当前策略组", verbose, is_verbose_message=True)
            continue
    
    if not policy_groups:
        log_message("未找到 policy-group，使用默认值: default", verbose, is_verbose_message=True)
        policy_groups['default'] = []
    
    return policy_groups

def parse_config(file_path, verbose, forced_encoding=None):
    """解析配置文件，提取策略信息并组织为字典列表"""
    log_message(f"开始解析配置文件: {file_path}", verbose)
    
    if not os.path.exists(file_path):
        log_message(f"错误: 文件 {file_path} 不存在", verbose)
        return [], None, None
    
    try:
        content, backup_path, utf8_path = convert_to_utf8(file_path, verbose, forced_encoding)
        lines = content.splitlines()
        log_message(f"文件内容行数: {len(lines)}", verbose)
        
        # 解析 policy-group 和 rule ID 映射
        policy_groups = parse_policy_groups(content, verbose)
        
        blocks = []
        current_block = []
        block_start_pattern = re.compile(r'^(firewall\s+policy\s+\d+|rule\s+(?:id\s+)?\d+)', re.IGNORECASE)
        
        for line in lines:
            line = line.rstrip()
            if not line.strip():
                if current_block:
                    blocks.append('\n'.join(current_block))
                    current_block = []
                continue
            if block_start_pattern.match(line):
                if current_block:
                    blocks.append('\n'.join(current_block))
                    current_block = []
                current_block.append(line)
            else:
                if current_block:
                    current_block.append(line)
        if current_block:
            blocks.append('\n'.join(current_block))
        
        log_message(f"找到 {len(blocks)} 个配置块", verbose)
        
        policies = []
        
        for i, block in enumerate(blocks, 1):
            block = block.strip()
            if not block:
                log_message(f"块 {i}: 跳过空块", verbose, is_verbose_message=True)
                continue
                
            policy = {
                '记录时间': datetime.datetime.now().strftime('%Y/%m/%d'),
                '策略组': 'default',
                '策略ID': '',
                '策略名称': '',
                '策略状态': '启用',
                '策略情况': '',
                '工单编号': '',
                '具体内容': '',
                '备注': ''
            }
            log_message(f"块 {i}: 初始化策略字典", verbose, is_verbose_message=True)
            log_message(f"块 {i} 内容:\n{block[:200]}...", verbose, is_verbose_message=True)
            
            fw_match = re.match(r'firewall\s+policy\s+(\d+)', block, re.IGNORECASE)
            if fw_match:
                policy['策略ID'] = fw_match.group(1)
                log_message(f"块 {i}: 解析 firewall policy 块，ID={policy['策略ID']}", verbose, is_verbose_message=True)
                has_enable = False
                description_parts = []
                for line in block.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    log_message(f"块 {i}: 处理行: {line}", verbose, is_verbose_message=True)
                    name_match = re.match(r'name\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if name_match:
                        policy['策略名称'] = name_match.group(2)
                        log_message(f"块 {i}: 提取策略名称: {policy['策略名称']}", verbose, is_verbose_message=True)
                        continue
                    desc_match = re.match(r'description\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if desc_match:
                        description_parts.append(desc_match.group(2))
                        log_message(f"块 {i}: 提取描述: {description_parts[-1]}", verbose, is_verbose_message=True)
                        continue
                    group_match = re.match(r'(?:firewall-)?policy-group\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if group_match:
                        policy['策略组'] = group_match.group(2)
                        log_message(f"块 {i}: 提取策略组: {policy['策略组']}", verbose, is_verbose_message=True)
                        continue
                    if re.search(r'^\s*enable\s*$', line, re.IGNORECASE):
                        has_enable = True
                        log_message(f"块 {i}: 检测到 enable", verbose, is_verbose_message=True)
                        continue
                    action_match = re.match(r'action\s+(permit|deny)', line, re.IGNORECASE)
                    if action_match:
                        action = '放通' if action_match.group(1).lower() == 'permit' else '阻断'
                        description_parts.append(f"动作: {action}")
                        log_message(f"块 {i}: 提取动作: {action}", verbose, is_verbose_message=True)
                        continue
                policy['策略状态'] = '启用' if has_enable else '禁用'
                log_message(f"块 {i}: 策略状态设为: {policy['策略状态']}", verbose, is_verbose_message=True)
                policy['具体内容'] = ' - '.join(description_parts) if description_parts else ''
                log_message(f"块 {i}: 拼接具体内容: {policy['具体内容']}", verbose, is_verbose_message=True)
                policies.append(policy)
                log_message(f"块 {i}: 添加策略: {policy}", verbose, is_verbose_message=True)
                continue
            
            rule_match = re.match(r'rule\s+(?:id\s+)?(\d+)', block, re.IGNORECASE)
            if rule_match:
                policy['策略ID'] = rule_match.group(1)
                log_message(f"块 {i}: 解析 rule 块，ID={policy['策略ID']}", verbose, is_verbose_message=True)
                has_disable = False
                description_parts = []
                # 查找 rule ID 所属的 policy-group
                for group_name, rule_ids in policy_groups.items():
                    if policy['策略ID'] in rule_ids:
                        policy['策略组'] = group_name
                        log_message(f"块 {i}: 分配策略组: {policy['策略组']} for rule ID {policy['策略ID']}", verbose, is_verbose_message=True)
                        break
                for line in block.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    log_message(f"块 {i}: 处理行: {line}", verbose, is_verbose_message=True)
                    name_match = re.match(r'name\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if name_match:
                        policy['策略名称'] = name_match.group(2)
                        log_message(f"块 {i}: 提取策略名称: {policy['策略名称']}", verbose, is_verbose_message=True)
                        continue
                    desc_match = re.match(r'description\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if desc_match:
                        description_parts.append(desc_match.group(2))
                        log_message(f"块 {i}: 提取描述: {description_parts[-1]}", verbose, is_verbose_message=True)
                        continue
                    group_match = re.match(r'(?:firewall-)?policy-group\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if group_match:
                        policy['策略组'] = group_match.group(2)
                        log_message(f"块 {i}: 提取策略组: {policy['策略组']}", verbose, is_verbose_message=True)
                        continue
                    if re.search(r'^\s*disable\s*$', line, re.IGNORECASE):
                        has_disable = True
                        log_message(f"块 {i}: 检测到 disable", verbose, is_verbose_message=True)
                        continue
                    action_match = re.match(r'action\s+(permit|deny)', line, re.IGNORECASE)
                    if action_match:
                        action = '放通' if action_match.group(1).lower() == 'permit' else '阻断'
                        description_parts.append(f"动作: {action}")
                        log_message(f"块 {i}: 提取动作: {action}", verbose, is_verbose_message=True)
                        continue
                policy['策略状态'] = '禁用' if has_disable else '启用'
                log_message(f"块 {i}: 策略状态设为: {policy['策略状态']}", verbose, is_verbose_message=True)
                policy['具体内容'] = ' - '.join(description_parts) if description_parts else ''
                log_message(f"块 {i}: 拼接具体内容: {policy['具体内容']}", verbose, is_verbose_message=True)
                policies.append(policy)
                log_message(f"块 {i}: 添加策略: {policy}", verbose, is_verbose_message=True)
                continue
            
            log_message(f"块 {i}: 未匹配任何策略格式", verbose, is_verbose_message=True)
        
        log_message(f"解析完成，共提取 {len(policies)} 条策略", verbose)
        return policies, backup_path, utf8_path
    
    except Exception as e:
        log_message(f"处理文件时出错: {e}", verbose)
        return [], None, None

def export_to_csv(policies, output_file, verbose):
    """将解析的策略信息导出为 CSV 文件"""
    log_message(f"导出 CSV 文件: {output_file}", verbose)
    headers = ['记录时间', '策略组', '策略ID', '策略名称', '策略状态', '策略情况', '工单编号', '具体内容', '备注']
    try:
        with open(output_file, 'w', encoding='utf-8-sig', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            log_message("写入 CSV 表头", verbose, is_verbose_message=True)
            for i, policy in enumerate(policies, 1):
                writer.writerow(policy)
                log_message(f"写入策略 {i}: {policy}", verbose, is_verbose_message=True)
        log_message(f"CSV 文件生成成功: {output_file}", verbose)
    except Exception as e:
        log_message(f"生成 CSV 文件时出错: {e}", verbose)

def main():
    """主函数，处理命令行参数并执行解析和导出"""
    parser = argparse.ArgumentParser(
        description="将服务器配置文本转换为 CSV 表格",
        epilog="示例: python FWconfigs.py -i config.txt --verbose --encoding gb2312"
    )
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='输入的配置文件路径'
    )
    parser.add_argument(
        '-o', '--output',
        help='输出的 CSV 文件路径（默认: 输入文件名.csv）'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='启用详细日志输出'
    )
    parser.add_argument(
        '--encoding',
        default=None,
        help='指定输入文件编码（如 gb2312, gbk, utf-8），默认使用 gb2312'
    )
    args = parser.parse_args()
    
    # 设置默认输出文件名为输入文件名（替换扩展名为 .csv）
    output_file = args.output if args.output else os.path.splitext(args.input)[0] + '.csv'
    
    log_message("脚本启动", verbose=args.verbose)
    log_message(f"输入文件: {args.input}, 输出文件: {output_file}, 编码: {args.encoding or 'gb2312'}", verbose=args.verbose)
    
    policies, backup_path, utf8_path = parse_config(args.input, args.verbose, args.encoding)
    if policies:
        export_to_csv(policies, output_file, args.verbose)
        # 删除临时文件
        try:
            if backup_path and os.path.exists(backup_path):
                os.remove(backup_path)
                log_message(f"删除备份文件: {backup_path}", verbose=args.verbose, is_verbose_message=True)
            if utf8_path and os.path.exists(utf8_path):
                os.remove(utf8_path)
                log_message(f"删除 UTF-8 文件: {utf8_path}", verbose=args.verbose, is_verbose_message=True)
        except Exception as e:
            log_message(f"删除临时文件时出错: {e}", verbose=args.verbose)
    else:
        log_message("未找到策略或处理过程中发生错误", verbose=args.verbose)
    
    log_message("脚本执行完成", verbose=args.verbose)

if __name__ == "__main__":
    main()