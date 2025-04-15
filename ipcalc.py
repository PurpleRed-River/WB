import pandas as pd
import ipaddress
import math
import re

def is_valid_ip(ip):
    """验证是否为有效IPv4地址"""
    if not isinstance(ip, str):
        return False
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ip_pattern, ip.strip()))

def read_ip_from_excel(file_path):
    """读取Excel文件中单列IP地址，自动跳过表头"""
    try:
        df_preview = pd.read_excel(file_path, nrows=1, header=None)
        first_entry = str(df_preview.iloc[0, 0])
        
        if not is_valid_ip(first_entry):
            # print(f"检测到表头: {first_entry}，自动跳过")
            df = pd.read_excel(file_path, header=0)
        else:
            df = pd.read_excel(file_path, header=None)
        
        ip_column = df.iloc[:, 0].dropna().astype(str).str.strip()
        ips = ip_column.tolist()
        
        valid_ips = []
        invalid_count = 0
        for ip in ips:
            if is_valid_ip(ip):
                valid_ips.append(ip)
            else:
                invalid_count += 1
                print(f"跳过无效IP地址: {ip}")
        
        if invalid_count > 0:
            print(f"共发现 {invalid_count} 个无效IP地址（不含表头），已跳过")
        return valid_ips
    except FileNotFoundError:
        print(f"错误: 文件 '{file_path}' 未找到，请检查文件路径")
        return []
    except Exception as e:
        print(f"读取Excel文件错误: {e}")
        return []

def ip_to_network(ip, prefix_len):
    """将IP转换为指定前缀长度的网段"""
    try:
        return ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
    except ValueError:
        return None

def find_common_network(ips):
    """寻找包含所有IP的最小单一网段"""
    if not ips:
        return None
    try:
        ip_objects = [ipaddress.ip_address(ip.strip()) for ip in ips]
        if not ip_objects:
            return None
        
        min_ip = min(ip_objects)
        
        for prefix_len in range(32, -1, -1):
            network = ipaddress.ip_network(f"{min_ip}/{prefix_len}", strict=False)
            if all(ip in network for ip in ip_objects):
                return network
        return None
    except Exception as e:
        print(f"计算单一网段错误: {e}")
        return None

def calculate_utilization(ips, network):
    """计算网段利用率"""
    if not network:
        return 0
    total_ips = network.num_addresses - 2
    used_ips = len(set(ips))
    return (used_ips / total_ips) * 100 if total_ips > 0 else 0

def estimate_prefix_for_network(network_ips):
    """为特定网段的IP估算最佳掩码"""
    if not network_ips:
        return 30
    try:
        ip_objects = [ipaddress.ip_address(ip.strip()) for ip in network_ips]
        ip_count = len(set(network_ips))
        
        log_ips = math.log2(ip_count * 2) if ip_count > 0 else 1
        prefix_len = max(16, min(30, 32 - math.ceil(log_ips)))
        
        min_ip = min(ip_objects)
        max_ip = max(ip_objects)
        ip_range = int(max_ip) - int(min_ip)
        if ip_range > 0:
            range_log = math.log2(ip_range + 1)
            prefix_len = min(prefix_len, 32 - math.ceil(range_log))
        
        for p in range(prefix_len, 33):
            network = ipaddress.ip_network(f"{min_ip}/{p}", strict=False)
            if all(ip in network for ip in ip_objects):
                return p
        return prefix_len
    except Exception:
        return 30

def estimate_optimal_prefix(ips):
    """为所有IP估算初始掩码"""
    if not ips:
        return 24
    try:
        ip_objects = [ipaddress.ip_address(ip.strip()) for ip in ips]
        if not ip_objects:
            return 24
        
        min_ip = min(ip_objects)
        max_ip = max(ip_objects)
        ip_range = int(max_ip) - int(min_ip)
        
        ip_count = len(set(ips))
        log_ips = math.log2(ip_count * 4) if ip_count > 0 else 1
        prefix_len = max(16, min(30, 32 - math.ceil(log_ips)))
        
        if ip_range > 0:
            range_log = math.log2(ip_range + 1)
            prefix_len = min(prefix_len, 32 - math.ceil(range_log))
        
        return max(16, min(30, prefix_len))
    except Exception:
        return 24

def get_network_details(network, network_ips):
    """获取网段的详细信息"""
    if not network:
        return None
    details = {
        "available_ips": network.num_addresses - 2,
        "subnet_mask": str(network.netmask),
        "network_address": str(network.network_address),
        "usable_range": f"{str(network.network_address + 1)} - {str(network.broadcast_address - 1)}" if network.num_addresses > 2 else "N/A",
        "broadcast_address": str(network.broadcast_address),
        "utilization": calculate_utilization(network_ips, network)
    }
    return details

def analyze_ip_segments(file_path):
    """智能分析IP地址并生成报告"""
    # 读取IP地址
    ips = read_ip_from_excel(file_path)
    if not ips:
        print("无有效IP地址")
        return

    # 估算初始掩码
    initial_prefix = estimate_optimal_prefix(ips)
    # print(f"初始智能估算的分析掩码: /{initial_prefix}")

    # 初步分组
    network_groups = {}
    for ip in ips:
        network = ip_to_network(ip, initial_prefix)
        if network:
            network_groups.setdefault(str(network), []).append(ip)

    # 为每个网段自适应掩码
    adaptive_networks = {}
    for network_str, network_ips in network_groups.items():
        prefix_len = estimate_prefix_for_network(network_ips)
        network = ip_to_network(network_ips[0], prefix_len)
        if network:
            adaptive_networks[str(network)] = (network, network_ips)

    # 生成报告
    print("\n============ IP网段分析报告 ============")
    print(f"总IP数: {len(ips)}")
    
    print("\n1. 网段分布统计（基于自适应掩码）:")
    if adaptive_networks:
        for network_str, (network, network_ips) in sorted(adaptive_networks.items()):
            count = len(network_ips)
            network_util = calculate_utilization(network_ips, network)
            print(f"网段 {network}: {count} 个IP (利用率: {network_util:.2f}%)")
    else:
        print("无有效网段")
    
    print("\n----------------------------------------")
    print("\n2. 单一网段建议:")
    common_network = find_common_network(ips)
    if common_network:
        utilization = calculate_utilization(ips, common_network)
        print(f"推荐单一网段: {common_network}")
        print(f"网段包含IP数量: {common_network.num_addresses}")
        print(f"利用率: {utilization:.2f}%")
    else:
        print("无法找到合适的单一网段")
    
    print("\n----------------------------------------")
    print("\n3. 网段分布详细信息:")
    if adaptive_networks:
        for network_str, (network, network_ips) in sorted(adaptive_networks.items()):
            details = get_network_details(network, network_ips)
            print(f"\n网段 {network}:")
            print(f"  可用IP数量: {details['available_ips']}")
            print(f"  掩码: {details['subnet_mask']}")
            print(f"  网络地址: {details['network_address']}")
            print(f"  可用IP范围: {details['usable_range']}")
            print(f"  广播地址: {details['broadcast_address']}")
            print(f"  当前利用率: {details['utilization']:.2f}%")
    else:
        print("无网段可显示")
    
    print("\n----------------------------------------")
    print("\n4. 优化建议:")
    if common_network:
        utilization = calculate_utilization(ips, common_network)
        if utilization < 30:
            print(f"- 单一网段利用率低，建议尝试更小的网段（如/{min(common_network.prefixlen + 2, 32)}）")
        elif utilization > 80:
            print(f"- 单一网段利用率高，建议扩展网段（如/{max(common_network.prefixlen - 2, 16)}）")
    
    if len(adaptive_networks) > 1:
        print("- IP分布在多个网段，考虑整合到单一网段或分配多个子网")
    if len(ips) != len(set(ips)):
        print("- 检测到重复IP，建议清理")
    print("- 建议记录IP分配情况，避免冲突")
    if len(ips) > 50 and any(network.prefixlen >= 28 for network, _ in adaptive_networks.values()):
        print("- IP数量较多，建议使用更大的网段（例如/26或/25）以简化管理")
    print("\n========================================")
if __name__ == "__main__":
    file_path = "ip.xlsx"  # 替换为实际Excel文件路径
    analyze_ip_segments(file_path)