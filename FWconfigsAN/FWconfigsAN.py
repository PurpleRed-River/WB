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
    
    backup_path = file_path + '.backup'
    with open(file_path, 'rb') as f:
        with open(backup_path, 'wb') as bf:
            bf.write(f.read())
    log_message(f"创建备份文件: {backup_path}", verbose, is_verbose_message=True)

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
    
    content = content.encode('utf-8').decode('utf-8')
    
    utf8_path = file_path + '.utf8'
    with open(utf8_path, 'w', encoding='utf-8') as file:
        file.write(content)
    log_message(f"保存 UTF-8 文件: {utf8_path}", verbose, is_verbose_message=True)
    
    return content, backup_path, utf8_path

def parse_address_groups(file_content, verbose):
    """解析配置文件中的 address 块，返回地址组名称与 IP 段的映射"""
    log_message("解析地址组", verbose, is_verbose_message=True)
    address_groups = {}
    current_group = None
    address_pattern = re.compile(r'address\s+"([^"]+)"', re.IGNORECASE)
    ip_pattern = re.compile(r'ip\s+([\d./]+)', re.IGNORECASE)
    range_pattern = re.compile(r'range\s+([\d.]+)\s+([\d.]+)', re.IGNORECASE)
    exit_pattern = re.compile(r'^\s*exit\s*$', re.IGNORECASE)
    
    for line in file_content.splitlines():
        line = line.strip()
        if not line:
            continue
        address_match = address_pattern.match(line)
        if address_match:
            current_group = address_match.group(1)
            address_groups[current_group] = []
            log_message(f"找到地址组: {current_group}", verbose, is_verbose_message=True)
            continue
        ip_match = ip_pattern.match(line)
        if ip_match and current_group:
            ip = ip_match.group(1)
            address_groups[current_group].append(ip)
            log_message(f"地址组 {current_group} 添加 IP: {ip}", verbose, is_verbose_message=True)
            continue
        range_match = range_pattern.match(line)
        if range_match and current_group:
            start_ip, end_ip = range_match.groups()
            ip_range = f"{start_ip}-{end_ip}"
            address_groups[current_group].append(ip_range)
            log_message(f"地址组 {current_group} 添加 IP 范围: {ip_range}", verbose, is_verbose_message=True)
            continue
        if exit_pattern.match(line) and current_group:
            current_group = None
            log_message("退出当前地址组", verbose, is_verbose_message=True)
            continue
    
    return address_groups

def parse_policy_groups(file_content, verbose):
    """解析配置文件中的 policy-group 块，返回 policy-group 与 rule ID 的映射"""
    log_message("解析策略组", verbose, is_verbose_message=True)
    policy_groups = {}
    current_group = None
    group_pattern = re.compile(r'(?:firewall-)?policy-group\s+"([^"]+)"', re.IGNORECASE)
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

def parse_config(file_path, verbose, forced_encoding=None, resolve_addresses=False):
    """解析配置文件，提取策略信息并组织为字典列表"""
    log_message(f"开始解析配置文件: {file_path}", verbose)
    
    if not os.path.exists(file_path):
        log_message(f"错误: 文件 {file_path} 不存在", verbose)
        return [], None, None
    
    try:
        content, backup_path, utf8_path = convert_to_utf8(file_path, verbose, forced_encoding)
        lines = content.splitlines()
        log_message(f"文件内容行数: {len(lines)}", verbose)
        
        address_groups = parse_address_groups(content, verbose) if resolve_addresses else {}
        policy_groups = parse_policy_groups(content, verbose)
        
        blocks = []
        current_block = []
        block_start_pattern = re.compile(r'^(firewall\s+policy\s+\d+|rule\s+(?:id\s+)?\d+|firewall\s+policy\s+add\s+name\s+)', re.IGNORECASE)
        
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
                '策略组': 'default',
                '策略ID': '',
                '策略名称': '',
                '策略状态': '启用',
                '源地址': '',
                '目的地址': '',
                '源端口': '',
                '目的端口': '',
                '协议': '',
                '具体内容': '',
                '备注': ''
            }
            log_message(f"块 {i}: 初始化策略字典", verbose, is_verbose_message=True)
            log_message(f"块 {i} 内容:\n{block[:200]}...", verbose, is_verbose_message=True)
            
            # 第一种配置：firewall policy <id>
            fw_match = re.match(r'firewall\s+policy\s+(\d+)', block, re.IGNORECASE)
            if fw_match:
                policy['策略ID'] = fw_match.group(1)
                log_message(f"块 {i}: 解析 firewall policy 块，ID={policy['策略ID']}", verbose, is_verbose_message=True)
                has_enable = False
                description_parts = []
                src_addresses = []
                dst_addresses = []
                services = []
                protocols = []
                dst_ports = []
                for line in block.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    log_message(f"块 {i}: 处理行: {line}", verbose, is_verbose_message=True)
                    name_match = re.match(r'name\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if name_match:
                        policy['策略名称'] = name_match.group(2).strip()
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
                    src_addr_match = re.match(r'src-addr\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_addr_match:
                        addr = src_addr_match.group(2).strip()
                        if addr.lower() == 'any':
                            src_addresses.append('Any')
                            log_message(f"块 {i}: 提取源地址: Any", verbose, is_verbose_message=True)
                        elif resolve_addresses and addr in address_groups:
                            src_addresses.extend(address_groups[addr])
                            log_message(f"块 {i}: 解析地址组 {addr} 为: {','.join(address_groups[addr])}", verbose, is_verbose_message=True)
                        else:
                            src_addresses.append(addr)
                            log_message(f"块 {i}: 提取源地址: {addr}", verbose, is_verbose_message=True)
                        continue
                    dst_addr_match = re.match(r'dst-addr\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_addr_match:
                        addr = dst_addr_match.group(2).strip()
                        if addr.lower() == 'any':
                            dst_addresses.append('Any')
                            log_message(f"块 {i}: 提取目的地址: Any", verbose, is_verbose_message=True)
                        elif resolve_addresses and addr in address_groups:
                            dst_addresses.extend(address_groups[addr])
                            log_message(f"块 {i}: 解析地址组 {addr} 为: {','.join(address_groups[addr])}", verbose, is_verbose_message=True)
                        else:
                            dst_addresses.append(addr)
                            log_message(f"块 {i}: 提取目的地址: {addr}", verbose, is_verbose_message=True)
                        continue
                    src_ip_match = re.match(r'src-ip\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_ip_match:
                        ip = src_ip_match.group(2).strip()
                        src_addresses.append(ip)
                        log_message(f"块 {i}: 提取源IP: {ip}", verbose, is_verbose_message=True)
                        continue
                    dst_ip_match = re.match(r'dst-ip\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_ip_match:
                        ip = dst_ip_match.group(2).strip()
                        dst_addresses.append(ip)
                        log_message(f"块 {i}: 提取目的IP: {ip}", verbose, is_verbose_message=True)
                        continue
                    src_range_match = re.match(r'src-range\s+([\d.]+)\s+([\d.]+)', line, re.IGNORECASE)
                    if src_range_match:
                        start_ip, end_ip = src_range_match.groups()
                        ip_range = f"{start_ip}-{end_ip}"
                        src_addresses.append(ip_range)
                        log_message(f"块 {i}: 提取源地址范围: {ip_range}", verbose, is_verbose_message=True)
                        continue
                    dst_range_match = re.match(r'dst-range\s+([\d.]+)\s+([\d.]+)', line, re.IGNORECASE)
                    if dst_range_match:
                        start_ip, end_ip = dst_range_match.groups()
                        ip_range = f"{start_ip}-{end_ip}"
                        dst_addresses.append(ip_range)
                        log_message(f"块 {i}: 提取目的地址范围: {ip_range}", verbose, is_verbose_message=True)
                        continue
                    src_zone_match = re.match(r'src-zone\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_zone_match:
                        log_message(f"块 {i}: 检测到 src-zone: {src_zone_match.group(2)}", verbose, is_verbose_message=True)
                        continue
                    dst_zone_match = re.match(r'dst-zone\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_zone_match:
                        log_message(f"块 {i}: 检测到 dst-zone: {dst_zone_match.group(2)}", verbose, is_verbose_message=True)
                        continue
                    src_port_match = re.match(r'src-port\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_port_match:
                        port = src_port_match.group(2).strip()
                        policy['源端口'] = f"{policy['源端口']},{port}" if policy['源端口'] else port
                        log_message(f"块 {i}: 提取源端口: {port}", verbose, is_verbose_message=True)
                        continue
                    dst_port_match = re.match(r'dst-port\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_port_match:
                        port = dst_port_match.group(2).strip()
                        dst_ports.append(port)
                        log_message(f"块 {i}: 提取目的端口: {port}", verbose, is_verbose_message=True)
                        continue
                    service_match = re.match(r'service\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if service_match:
                        service = service_match.group(2).strip()
                        services.append(service)
                        if re.match(r'^(TCP|UDP)(\d+)', service, re.IGNORECASE):
                            protocol = service[:3].upper()
                            port = service[3:]
                            protocols.append(protocol)
                            dst_ports.append(port)
                        else:
                            dst_ports.append(service)
                        log_message(f"块 {i}: 提取服务: {service}", verbose, is_verbose_message=True)
                        continue
                policy['策略状态'] = '启用' if has_enable else '禁用'
                policy['源地址'] = ','.join(src_addresses) if src_addresses else ''
                policy['目的地址'] = ','.join(dst_addresses) if dst_addresses else ''
                policy['协议'] = ','.join(protocols) if protocols else ''
                policy['目的端口'] = ','.join(dst_ports) if dst_ports else ''
                policy['具体内容'] = ' - '.join(description_parts + [f"服务: {','.join(services)}"] if services else description_parts)
                policies.append(policy)
                log_message(f"块 {i}: 添加策略: {policy}", verbose, is_verbose_message=True)
                continue
            
            # 第二种配置：rule id <id>
            rule_match = re.match(r'rule\s+(?:id\s+)?(\d+)', block, re.IGNORECASE)
            if rule_match:
                policy['策略ID'] = rule_match.group(1)
                log_message(f"块 {i}: 解析 rule 块，ID={policy['策略ID']}", verbose, is_verbose_message=True)
                has_disable = False
                description_parts = []
                src_addresses = []
                dst_addresses = []
                services = []
                protocols = []
                dst_ports = []
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
                        policy['策略名称'] = name_match.group(2).strip()
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
                    src_ip_match = re.match(r'src-ip\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_ip_match:
                        ip = src_ip_match.group(2).strip()
                        src_addresses.append(ip)
                        log_message(f"块 {i}: 提取源IP: {ip}", verbose, is_verbose_message=True)
                        continue
                    dst_ip_match = re.match(r'dst-ip\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_ip_match:
                        ip = dst_ip_match.group(2).strip()
                        dst_addresses.append(ip)
                        log_message(f"块 {i}: 提取目的IP: {ip}", verbose, is_verbose_message=True)
                        continue
                    src_addr_match = re.match(r'src-addr\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_addr_match:
                        addr = src_addr_match.group(2).strip()
                        if addr.lower() == 'any':
                            src_addresses.append('Any')
                            log_message(f"块 {i}: 提取源地址: Any", verbose, is_verbose_message=True)
                        elif resolve_addresses and addr in address_groups:
                            src_addresses.extend(address_groups[addr])
                            log_message(f"块 {i}: 解析地址组 {addr} 为: {','.join(address_groups[addr])}", verbose, is_verbose_message=True)
                        else:
                            src_addresses.append(addr)
                            log_message(f"块 {i}: 提取源地址: {addr}", verbose, is_verbose_message=True)
                        continue
                    dst_addr_match = re.match(r'dst-addr\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_addr_match:
                        addr = dst_addr_match.group(2).strip()
                        if addr.lower() == 'any':
                            dst_addresses.append('Any')
                            log_message(f"块 {i}: 提取目的地址: Any", verbose, is_verbose_message=True)
                        elif resolve_addresses and addr in address_groups:
                            dst_addresses.extend(address_groups[addr])
                            log_message(f"块 {i}: 解析地址组 {addr} 为: {','.join(address_groups[addr])}", verbose, is_verbose_message=True)
                        else:
                            dst_addresses.append(addr)
                            log_message(f"块 {i}: 提取目的地址: {addr}", verbose, is_verbose_message=True)
                        continue
                    src_range_match = re.match(r'src-range\s+([\d.]+)\s+([\d.]+)', line, re.IGNORECASE)
                    if src_range_match:
                        start_ip, end_ip = src_range_match.groups()
                        ip_range = f"{start_ip}-{end_ip}"
                        src_addresses.append(ip_range)
                        log_message(f"块 {i}: 提取源地址范围: {ip_range}", verbose, is_verbose_message=True)
                        continue
                    dst_range_match = re.match(r'dst-range\s+([\d.]+)\s+([\d.]+)', line, re.IGNORECASE)
                    if dst_range_match:
                        start_ip, end_ip = dst_range_match.groups()
                        ip_range = f"{start_ip}-{end_ip}"
                        dst_addresses.append(ip_range)
                        log_message(f"块 {i}: 提取目的地址范围: {ip_range}", verbose, is_verbose_message=True)
                        continue
                    src_zone_match = re.match(r'src-zone\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_zone_match:
                        log_message(f"块 {i}: 检测到 src-zone: {src_zone_match.group(2)}", verbose, is_verbose_message=True)
                        continue
                    dst_zone_match = re.match(r'dst-zone\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_zone_match:
                        log_message(f"块 {i}: 检测到 dst-zone: {dst_zone_match.group(2)}", verbose, is_verbose_message=True)
                        continue
                    src_port_match = re.match(r'src-port\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if src_port_match:
                        port = src_port_match.group(2).strip()
                        policy['源端口'] = f"{policy['源端口']},{port}" if policy['源端口'] else port
                        log_message(f"块 {i}: 提取源端口: {port}", verbose, is_verbose_message=True)
                        continue
                    dst_port_match = re.match(r'dst-port\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if dst_port_match:
                        port = dst_port_match.group(2).strip()
                        dst_ports.append(port)
                        log_message(f"块 {i}: 提取目的端口: {port}", verbose, is_verbose_message=True)
                        continue
                    service_match = re.match(r'service\s+("?)(.*?)\1\s*$', line, re.IGNORECASE)
                    if service_match:
                        service = service_match.group(2).strip()
                        services.append(service)
                        if re.match(r'^(TCP|UDP)(\d+)', service, re.IGNORECASE):
                            protocol = service[:3].upper()
                            port = service[3:]
                            protocols.append(protocol)
                            dst_ports.append(port)
                        else:
                            dst_ports.append(service)
                        log_message(f"块 {i}: 提取服务: {service}", verbose, is_verbose_message=True)
                        continue
                policy['策略状态'] = '禁用' if has_disable else '启用'
                policy['源地址'] = ','.join(src_addresses) if src_addresses else ''
                policy['目的地址'] = ','.join(dst_addresses) if dst_addresses else ''
                policy['协议'] = ','.join(protocols) if protocols else ''
                policy['目的端口'] = ','.join(dst_ports) if dst_ports else ''
                policy['具体内容'] = ' - '.join(description_parts + [f"服务: {','.join(services)}"] if services else description_parts)
                policies.append(policy)
                log_message(f"块 {i}: 添加策略: {policy}", verbose, is_verbose_message=True)
                continue
            
            # 第三种配置：firewall policy add
            add_match = re.match(r'firewall\s+policy\s+add\s+name\s+([^"]+?)\s+action\s+(accept|deny)\s+srcarea\s+[\'"](.*?)[\'"]\s+dstarea\s+[\'"](.*?)[\'"]\s+src\s+[\'"](.*?)[\'"]\s+dst\s+[\'"](.*?)[\'"]\s+service\s+[\'"](.*?)[\'"](?:\s+group_name\s+[\'"](.*?)[\'"])?(?:\s+comment\s+[\'"](.*?)[\'"])?$', block, re.IGNORECASE)
            if add_match:
                log_message(f"块 {i}: 解析 firewall policy add 块", verbose, is_verbose_message=True)
                policy['策略名称'] = add_match.group(1).strip()
                action = '放通' if add_match.group(2).lower() == 'accept' else '阻断'
                src_area = add_match.group(3)
                dst_area = add_match.group(4)
                src_addresses = add_match.group(5).strip().split()
                dst_addresses = add_match.group(6).strip().split()
                service = add_match.group(7).strip()
                policy['策略组'] = add_match.group(8) if add_match.group(8) else 'default'
                policy['备注'] = add_match.group(9) if add_match.group(9) else ''
                
                description_parts = [f"动作: {action}"]
                services = [service]
                protocols = []
                dst_ports = []
                
                log_message(f"块 {i}: 提取策略名称: {policy['策略名称']}", verbose, is_verbose_message=True)
                log_message(f"块 {i}: 提取动作: {action}", verbose, is_verbose_message=True)
                log_message(f"块 {i}: 检测到 srcarea: {src_area}", verbose, is_verbose_message=True)
                log_message(f"块 {i}: 检测到 dstarea: {dst_area}", verbose, is_verbose_message=True)
                log_message(f"块 {i}: 提取源地址: {','.join(src_addresses)}", verbose, is_verbose_message=True)
                log_message(f"块 {i}: 提取目的地址: {','.join(dst_addresses)}", verbose, is_verbose_message=True)
                log_message(f"块 {i}: 提取服务: {service}", verbose, is_verbose_message=True)
                log_message(f"块 {i}: 提取策略组: {policy['策略组']}", verbose, is_verbose_message=True)
                if policy['备注']:
                    log_message(f"块 {i}: 提取备注: {policy['备注']}", verbose, is_verbose_message=True)
                    description_parts.append(f"备注: {policy['备注']}")
                
                if re.match(r'^(TCP|UDP)(\d+)', service, re.IGNORECASE):
                    protocol = service[:3].upper()
                    port = service[3:]
                    protocols.append(protocol)
                    dst_ports.append(port)
                else:
                    dst_ports.append(service)
                
                policy['源地址'] = ','.join(src_addresses) if src_addresses else ''
                policy['目的地址'] = ','.join(dst_addresses) if dst_addresses else ''
                policy['协议'] = ','.join(protocols) if protocols else ''
                policy['目的端口'] = ','.join(dst_ports) if dst_ports else ''
                policy['具体内容'] = ' - '.join(description_parts + [f"服务: {','.join(services)}"] if services else description_parts)
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
    headers = ['策略组', '策略ID', '策略名称', '策略状态', '源地址', '目的地址', '源端口', '目的端口', '协议', '具体内容', '备注']
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
        epilog="示例: python FWconfigs.py -i config.txt --verbose --encoding gb2312 --resolve-addresses"
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
    parser.add_argument(
        '--resolve-addresses',
        action='store_true',
        help='解析地址组为实际 IP 段（仅适用于第一种和第二种配置）'
    )
    args = parser.parse_args()
    
    output_file = args.output if args.output else os.path.splitext(args.input)[0] + '.csv'
    
    log_message("脚本启动", verbose=args.verbose)
    log_message(f"输入文件: {args.input}, 输出文件: {output_file}, 编码: {args.encoding or 'gb2312'}, 解析地址组: {args.resolve_addresses}", verbose=args.verbose)
    
    policies, backup_path, utf8_path = parse_config(args.input, args.verbose, args.encoding, args.resolve_addresses)
    if policies:
        export_to_csv(policies, output_file, args.verbose)
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