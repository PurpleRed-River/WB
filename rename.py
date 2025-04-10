import os
import logging
import argparse
from datetime import datetime

# 配置日志
CURRENT_DATE = datetime.now().strftime("%Y%m%d")
LOG_FILE = f"rename_files_{CURRENT_DATE}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def rename_files(directory, old_string, new_string, extensions=None, preview=False):
    """
    批量替换文件名中的部分字符串
    :param directory: 文件夹路径
    :param old_string: 要替换的字符串
    :param new_string: 替换后的字符串
    :param extensions: 文件扩展名列表（如 ['.txt', '.log']），None表示处理所有文件
    :param preview: 是否仅预览（不实际重命名）
    """
    if not os.path.isdir(directory):
        logging.error(f"目录 {directory} 不存在")
        return
    
    # 规范化扩展名
    if extensions:
        extensions = [ext.lower() for ext in extensions]
    
    # 记录预览或实际操作的文件列表
    rename_list = []
    
    # 遍历目录中的文件
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if not os.path.isfile(file_path):
            continue
        
        # 检查文件扩展名（如果指定了扩展名）
        if extensions:
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in extensions:
                continue
        
        # 检查是否包含要替换的字符串
        if old_string in filename:
            new_filename = filename.replace(old_string, new_string)
            rename_list.append((filename, new_filename))
    
    if not rename_list:
        logging.info("没有找到需要替换的文件")
        return
    
    # 预览模式
    if preview:
        logging.info("预览模式：以下文件将要重命名")
        for old_name, new_name in rename_list:
            logging.info(f"{old_name} -> {new_name}")
        return
    
    # 实际重命名
    success_count = 0
    fail_count = 0
    for old_name, new_name in rename_list:
        old_path = os.path.join(directory, old_name)
        new_path = os.path.join(directory, new_name)
        try:
            os.rename(old_path, new_path)
            logging.info(f"成功重命名: {old_name} -> {new_name}")
            success_count += 1
        except Exception as e:
            logging.error(f"重命名失败: {old_name} -> {new_name}, 错误: {str(e)}")
            fail_count += 1
    
    logging.info(f"重命名完成: 成功 {success_count} 个，失败 {fail_count} 个")

def main():
    # 设置命令行参数
    parser = argparse.ArgumentParser(
        description="批量替换文件名中的部分字符串，支持指定文件夹路径和文件类型。"
    )
    parser.add_argument(
        "-d", "--directory",
        type=str,
        help="指定文件夹路径，例如: configs 或 /path/to/folder"
    )
    parser.add_argument(
        "-o", "--old",
        type=str,
        default="20250410",
        help="要替换的字符串（默认: 20250410）"
    )
    parser.add_argument(
        "-n", "--new",
        type=str,
        default="20250411",
        help="替换后的字符串（默认: 20250411）"
    )
    parser.add_argument(
        "-e", "--extensions",
        nargs="*",
        default=None,  # 默认支持所有扩展名
        help="文件扩展名列表，例如: .txt .log（默认: 处理所有文件）"
    )
    parser.add_argument(
        "-p", "--preview",
        action="store_true",
        help="仅预览，不实际重命名"
    )
    
    args = parser.parse_args()
    
    # 如果未通过命令行指定目录，则交互式输入
    if args.directory:
        directory = args.directory
    else:
        directory = input("请输入文件夹路径（默认: configs）: ").strip() or "configs"
    
    old_string = args.old
    new_string = args.new
    extensions = args.extensions if args.extensions else None  # None 表示处理所有文件
    preview = args.preview
    
    logging.info("开始批量重命名文件")
    logging.info(f"参数: 目录={directory}, 替换='{old_string}' 为='{new_string}', 扩展名={extensions or '所有文件'}, 预览={preview}")
    
    rename_files(directory, old_string, new_string, extensions, preview)
    
    # 如果预览模式，询问是否继续执行
    if preview:
        response = input("是否确认执行重命名？(yes/no): ").strip().lower()
        if response == 'yes':
            logging.info("用户确认执行重命名")
            rename_files(directory, old_string, new_string, extensions, preview=False)
        else:
            logging.info("用户取消实际重命名")

if __name__ == "__main__":
    main()