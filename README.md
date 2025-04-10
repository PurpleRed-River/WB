# :)

## H3Cback.py

用于批量备份 H3C 交换机配置的脚本。它通过 SSH 连接到指定的交换机，执行 display device manuinfo 获取序列号（SN），并执行 display current-configuration 获取当前配置，最终将配置保存为本地文件。

### 主要功能

- **批量连接**：从 Excel 文件读取交换机 IP、用户名和密码，批量处理。
- **序列号匹配**：从设备获取 SN，与预设列表匹配，匹配成功使用 SN 命名文件，失败使用 IP 命名。
- **分页处理**：自动处理 ---- More ---- 分页，确保配置完整。
- **重试机制**：如果获取 SN 或配置失败，最多重试 3 次。
- **日志记录**：记录每台设备的操作详情到日志文件。

#### 交换机信息表格（switches.xlsx）

```
| ip           | username | password |
|--------------|----------|----------|
| 192.168.1.1  | admin    | pass123  |
| 192.168.1.2  | admin    | pass456  |
```

#### SN 码表格（sn_list.xlsx）

```
| sn            |
|---------------|
| ABC123456789  |
| XYZ987654321  |
```

#### 文件命名规则

```
SN 匹配成功：{SN}_{YYYYMMDD}.txt（如 ABC123_20250410.txt）。
SN 匹配失败：{IP}_{YYYYMMDD}.txt（如 1.1.1.1_20250410.txt）。
```

## rename.py

用于批量重命名文件的脚本。它可以替换文件名中的指定字符串，支持指定文件夹路径和文件类型，适用于整理备份文件或其他批量命名需求。

```shell
❯ : uv run rename.py -h
usage: rename.py [-h] [-d DIRECTORY] [-o OLD] [-n NEW] [-e [EXTENSIONS ...]] [-p]

批量替换文件名中的部分字符串，支持指定文件夹路径和文件类型。

options:
  -h, --help            show this help message and exit
  -d, --directory DIRECTORY
                        指定文件夹路径，例如: configs 或 /path/to/folder
  -o, --old OLD         要替换的字符串（默认: 20250410）
  -n, --new NEW         替换后的字符串（默认: 20250411）
  -e, --extensions [EXTENSIONS ...]
                        文件扩展名列表，例如: .txt .log（默认: 处理所有文件）
  -p, --preview         仅预览，不实际重命名
```

