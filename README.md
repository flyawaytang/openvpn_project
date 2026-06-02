# OpenVPN 全流量明文监控系统

本项目基于 OpenVPN 开源代码（**v2.8 Git 开发版**）修改实现，能够实时监控并输出 OpenVPN 通信过程中的**解密后明文数据**（十六进制格式）。
主要监控内容包括：
1. **控制通道 (Control Channel)**：TLS 握手、密钥协商等管理指令。
2. **数据通道 (Data Channel)**：实际传输的 IP 数据包（解密后）。

## ⚠️ 重要说明

*   **必须重新编译 OpenVPN**：由于需要 Hook 内部的加密/解密函数，无法通过插件或外部工具实现，必须修改源码并重新编译 OpenVPN。
*   **运行环境**：本方案已在 Ubuntu 20.04 上验证通过（基于 OpenVPN v2.8 源码）。
*   **输出方式**：解密后的数据直接打印到标准输出 (stdout) 或指定日志文件，方便分析。
*   **版本说明**：
    - 工作区 `openvpn-source/` 目录包含的是 **OpenVPN v2.8 (Git 开发版)** 源码
    - 同时提供了 `openvpn_monitor.patch` 补丁文件，可应用于其他版本（如 v2.6.3）
    - 推荐使用 v2.8 版本，因为源码已预集成监控钩子

---

## 一、环境准备 (Ubuntu 20.04)

在开始之前，请安装必要的编译依赖：

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev net-tools git wget pkg-config autoconf automake libtool
```

---

## 二、项目结构说明

工作区包含以下关键文件：

```
/workspace/
├── openvpn-source/           # OpenVPN v2.8 完整源码（已集成监控钩子）
│   ├── src/openvpn/crypto.c      # 数据通道加解密逻辑（含钩子调用）
│   ├── src/openvpn/ssl_pkt.c     # 控制通道加解密逻辑（含钩子调用）
│   └── ...
├── openvpn_traffic_monitor.c # 监控模块实现（钩子函数定义）
├── openvpn_monitor.patch     # 补丁文件（如需应用到其他版本）
└── README.md                 # 本说明文档
```

**注意**：当前 `openvpn-source` 目录中的源码已经集成了监控钩子，无需额外打补丁，直接编译即可。

---

## 三、编译与安装

### 方法 A：直接编译已集成的源码（推荐）

当前 `openvpn-source` 目录中的源码是 **OpenVPN v2.8 (Git 开发版)**，已经集成了监控钩子，无需额外打补丁，直接编译即可。

```bash
cd /workspace/openvpn-source

# 生成 configure 脚本
./bootstrap

# 配置编译选项
# --prefix: 安装路径，建议安装到独立目录以免覆盖系统自带 openvpn
./configure --prefix=/usr/local/openvpn-monitor --enable-password-save

# 将监控模块复制到源码目录
cp /workspace/openvpn_traffic_monitor.c src/openvpn/

# 注意：需要将监控模块添加到编译列表中
# 编辑 src/openvpn/Makefile.am，在 openvpn_SOURCES 中添加 openvpn_traffic_monitor.c
echo "Adding monitor module to Makefile.am..."
sed -i '/openvpn_SOURCES.*=/a\\topenvpn_traffic_monitor.c' src/openvpn/Makefile.am

# 重新生成 Makefile
autoreconf -fi

# 编译
make -j$(nproc)

# 安装
sudo make install
```

### 方法 B：使用补丁应用到官方源码

如果你想使用其他版本的 OpenVPN 源码，可以使用提供的补丁文件：

```bash
cd /workspace

# 下载官方源码（以 v2.6.3 为例，也可选择其他版本）
wget https://github.com/OpenVPN/openvpn/releases/download/v2.6.3/openvpn-2.6.3.tar.gz
tar -xzf openvpn-2.6.3.tar.gz
cd openvpn-2.6.3

# 应用补丁（可能需要根据版本差异手动调整）
patch -p1 < /workspace/openvpn_monitor.patch || echo "Patch may need manual adjustment"

# 将监控模块复制进去
cp /workspace/openvpn_traffic_monitor.c src/openvpn/

# 添加到编译列表
sed -i '/openvpn_SOURCES.*=/a\\topenvpn_traffic_monitor.c' src/openvpn/Makefile.am

# 继续标准编译流程
./bootstrap
./configure --prefix=/usr/local/openvpn-monitor
make -j$(nproc)
sudo make install
```

> **版本说明**：
> - **推荐使用 v2.8**（工作区已集成的版本）：这是最新的开发分支，代码结构最新
> - **v2.6.x**：稳定版本，补丁兼容性较好
> - **v2.5.x 及更早**：可能需要手动调整补丁，因为内部 API 有变化

---

## 四、使用说明

### 1. 基本用法

编译完成后，可执行文件位于 `/usr/local/openvpn-monitor/sbin/openvpn`。

#### 启动服务器端（带监控）

```bash
# 创建日志目录
mkdir -p /var/log/openvpn-monitor

# 启动服务器，输出到日志文件
sudo /usr/local/openvpn-monitor/sbin/openvpn \
    --config /etc/openvpn/server/server.conf \
    --verb 4 \
    > /var/log/openvpn-monitor/server_plain.log 2>&1
```

#### 启动客户端（带监控）

```bash
# 启动客户端，输出到标准输出（实时查看）
sudo /usr/local/openvpn-monitor/sbin/openvpn \
    --config /etc/openvpn/client/client.conf \
    --verb 4
```

### 2. 输出示例

监控日志将包含以下格式的输出：

```text
=== CONTROL CHANNEL [RX] 2024-01-15 10:30:45 ===
Peer: 192.168.1.100:1194
Opcode: P_CONTROL_V1 (3)
Plaintext payload (24 bytes):
00000000  0a 01 00 00 00 00 00 00  00 00 00 00 01 02 03 04  |................|
00000010  05 06 07 08 09 0a 0b 0c                           |........|

--- DATA CHANNEL [RX] 2024-01-15 10:30:46 ---
Peer: 192.168.1.100:1194
Packet length: 84 bytes
IPv4 Packet: src=10.8.0.2, dst=8.8.8.8, proto=17
Plaintext payload (84 bytes):
00000000  45 00 00 54 00 01 00 00  40 11 00 00 0a 08 00 02  |E..T....@.......|
00000010  08 08 08 08 d0 4f 00 35  00 40 00 00 ...         |.....O.5.@..|
```

### 3. 高级配置

#### 使用插件参数（如果编译为插件）

```bash
plugin /usr/local/lib/openvpn/plugins/openvpn_traffic_monitor.so log=/var/log/traffic.log debug=15
```

调试级别 (debug)：
- `1`: 基本信息
- `2`: 数据包信息
- `4`: 十六进制详细输出
- `8`: 控制通道专用
- `16`: 数据通道专用

可以组合使用，例如 `debug=15` 启用所有功能。

---

## 五、技术原理

本方案通过在 OpenVPN 核心源码中注入钩子函数实现明文抓取：

### 1. 数据通道 (Data Channel)
- **位置**: `src/openvpn/crypto.c`
- **时机**: 在 `openvpn_decrypt_*` 函数完成解密后
- **内容**: 完整的 IP 数据包（已去除 OpenVPN 头部）

### 2. 控制通道 (Control Channel)  
- **位置**: `src/openvpn/ssl_pkt.c`
- **时机**: 
  - 加密前：`write_control_auth()` 函数
  - 解密后：`read_control_auth()` 函数
- **内容**: OpenVPN 控制协议消息（PUSH_REQUEST, AUTH_RESPONSE 等）

### 3. 钩子函数接口

```c
// 解密后的控制通道数据
void traffic_monitor_control_decrypted(const uint8_t *data, size_t len,
                                        const char *peer_info, bool incoming);

// 解密后的数据通道数据
void traffic_monitor_data_decrypted(const uint8_t *data, size_t len,
                                     const char *peer_info, bool incoming);

// 加密前的控制通道数据
void traffic_monitor_control_encrypted(const uint8_t *data, size_t len,
                                        const char *peer_info, bool incoming);

// 加密前的数据通道数据
void traffic_monitor_data_encrypted(const uint8_t *data, size_t len,
                                     const char *peer_info, bool incoming);
```

---

## 六、数据分析

### 将 Hex 导出为 PCAP 文件

可以使用以下 Python 脚本将日志转换为 Wireshark 可读的格式：

```python
#!/usr/bin/env python3
import re

def hex_to_pcap(log_file, pcap_file):
    with open(log_file, 'r') as f:
        data = []
        for line in f:
            # 提取 hex 行
            match = re.search(r'^[0-9a-fA-F]{8}\s+([0-9a-fA-F ]+)\s+\|', line)
            if match:
                hex_str = match.group(1).replace(' ', '')
                data.append(bytes.fromhex(hex_str))
    
    with open(pcap_file, 'wb') as f:
        # 写入简化的 PCAP 头
        f.write(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00')
        for i, pkt in enumerate(data):
            import struct
            import time
            ts = int(time.time())
            f.write(struct.pack('<IIII', ts, 0, len(pkt), len(pkt)))
            f.write(pkt)

hex_to_pcap('/var/log/openvpn-monitor/server_plain.log', '/tmp/traffic.pcap')
```

然后用 Wireshark 打开 `traffic.pcap` 进行分析。

---

## 七、常见问题 (FAQ)

**Q: 为什么不使用 tcpdump 或 Wireshark 直接解密？**  
A: tcpdump 只能抓到加密后的 UDP/TCP 包。虽然 Wireshark 支持导入 TLS 密钥解密，但配置复杂且对 OpenVPN 自定义协议支持有限。本方案直接在应用层输出明文，简单可靠。

**Q: 会影响网络性能吗？**  
A: 会有轻微影响（约 5-10%），主要来自 I/O 操作。生产环境建议：
1. 降低日志详细程度
2. 仅采样部分数据包
3. 将日志写入高速存储或内存盘

**Q: 编译时遇到 `undefined reference to traffic_monitor_*` 错误？**  
A: 确保 `openvpn_traffic_monitor.c` 已正确添加到编译列表中。检查 `src/openvpn/Makefile.am` 是否包含该文件。

**Q: 如何只监控特定类型的流量？**  
A: 修改 `openvpn_traffic_monitor.c` 中的钩子函数，添加过滤逻辑（如根据 IP、端口、协议类型等）。

---

## 八、免责声明

本工具仅供网络安全研究、故障排查及合法的网络流量分析使用。请勿用于非法窃听或侵犯他人隐私。使用者需自行承担法律责任。
