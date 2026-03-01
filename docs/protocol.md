# SSH Jump Server 通信协议

## 概述

SSH Jump Server 使用自定义的 Agent 通信协议，基于 TCP 连接，采用二进制消息格式。

## 协议规范

### 消息格式

所有消息采用统一的头部格式：

```
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
|  Magic (4 bytes)  |  Type  |    Length (4 bytes)   |          Payload (Length bytes)         |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
```

- **Magic** (4 bytes): 固定值 `0x4A534853` ("JSHS" 的 ASCII)
- **Type** (1 byte): 消息类型
- **Length** (4 bytes): Payload 长度（大端序）
- **Payload** (Length bytes): JSON 格式的消息内容

### 消息类型

| 类型值 | 名称 | 说明 |
|--------|------|------|
| 0x01 | REGISTER | Agent 注册请求 |
| 0x02 | HEARTBEAT | 心跳消息 |
| 0x03 | UNREGISTER | 注销请求 |
| 0x04 | COMMAND | 服务器发送的命令 |
| 0x05 | RESPONSE | 响应消息 |
| 0x06 | FORWARD_REQUEST | 转发请求 |
| 0x07 | FORWARD_DATA | 转发数据 |

### 注册流程

```
Agent                              Server
  |                                   |
  |-------- REGISTER Request -------->| Auth Token
  |                                   | Verification
  |<------- REGISTER Response --------| Success/Fail
  |                                   |
  |                                   |
  |-------- HEARTBEAT (30s) --------->| Keep Alive
  |<------- HEARTBEAT ACK ------------| Confirm
  |                                   |
```

### 注册请求 (REGISTER)

**Payload 格式：**

```json
{
  "agent_id": "web-server-01",
  "hostname": "Web Server 01",
  "ip_address": "10.0.1.5",
  "version": "2.0.0",
  "auth_token": "secret-token"
}
```

说明：
- `jump-agent` 只负责资产注册与心跳，不需要通过命令行声明可暴露服务。
- 服务端按跳板场景默认连接目标 SSH 端口 `22`。

### 注册响应

**成功响应：**

```json
{
  "success": true,
  "message": "Registered successfully",
  "heartbeat_interval": 30
}
```

**失败响应：**

```json
{
  "success": false,
  "message": "Invalid token"
}
```

### 心跳消息 (HEARTBEAT)

**请求：**

```json
{
  "agent_id": "web-server-01",
  "timestamp": 1704067200,
  "status": "healthy"
}
```

**响应：**

```json
{
  "success": true,
  "timestamp": 1704067200
}
```

### 注销消息 (UNREGISTER)

**请求：**

```json
{
  "agent_id": "web-server-01",
  "reason": "shutdown"
}
```

## NAT 穿透转发流程（FORWARD_REQUEST）

当目标主机位于 NAT 后无法被跳板机直接访问时，服务端会通过 Agent 的控制连接发送 `FORWARD_REQUEST`，由 Agent 主动回拨建立数据通道。

```
User -> Jump Server -> Agent(control)
                       |
                       | (FORWARD_REQUEST)
                       v
                    Agent 连接本地服务 (127.0.0.1:targetPort)
                       |
                       | 主动回拨 Jump Server:connectBackPort
                       v
User <- Jump Server <- Reverse Tunnel <- Agent <- Target Service
```

**FORWARD_REQUEST Payload（服务端 -> Agent）：**

```json
{
  "requestId": "uuid",
  "targetHost": "127.0.0.1",
  "targetPort": 22,
  "connectBackPort": 38001,
  "connectBackHost": "198.51.100.10"
}
```

说明：
- `targetHost/targetPort`：Agent 本地要连接的目标服务
- `connectBackPort`：服务端在配置端口池内选择的回拨监听端口
- `connectBackHost`：可选，服务端回拨地址（支持 IPv4/IPv6）；缺省时 Agent 使用控制连接的服务端地址
- 服务端会按 `reverse_tunnel_retries` 次数重试不同端口，超时后回退直连模式

## 服务器与 Agent 通信示例

### 连接建立

```python
import socket
import struct
import json

# 连接到服务器
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('jump.example.com', 8888))

# 构建注册消息
payload = json.dumps({
    'agent_id': 'web-server-01',
    'hostname': 'Web Server 01',
    'auth_token': 'secret-token'
}).encode()

# 构建消息头部
magic = 0x4A534853
msg_type = 0x01  # REGISTER
length = len(payload)

header = struct.pack('>IBI', magic, msg_type, length)
message = header + payload

# 发送
sock.sendall(message)

# 接收响应
resp_header = sock.recv(9)
magic, resp_type, resp_len = struct.unpack('>IBI', resp_header)
resp_payload = sock.recv(resp_len)
response = json.loads(resp_payload.decode())

print(response)  # {'success': True, ...}
```

### 心跳循环

```python
import time

while True:
    time.sleep(30)  # heartbeat_interval
    
    heartbeat = json.dumps({
        'agent_id': 'web-server-01',
        'timestamp': int(time.time()),
        'status': 'healthy'
    }).encode()
    
    header = struct.pack('>IBI', magic, 0x02, len(heartbeat))
    sock.sendall(header + heartbeat)
    
    # 接收确认
    ack = sock.recv(9)
```

## SSH 协议支持

服务器实现了一个 SSH 服务器，支持标准 SSH 协议：

### 支持的算法

**密钥交换：**
- curve25519-sha256
- ecdh-sha2-nistp256/384/521
- diffie-hellman-group14-sha256

**主机密钥：**
- ssh-rsa
- rsa-sha2-256/512
- ecdsa-sha2-nistp256/384/521
- ssh-ed25519

**加密算法：**
- aes256-gcm@openssh.com
- aes128-gcm@openssh.com
- aes256-ctr
- aes192-ctr
- aes128-ctr

**MAC 算法：**
- hmac-sha2-256/512
- hmac-sha2-256-etm@openssh.com

### 认证方式

1. **公钥认证**
   - 支持 RSA、ECDSA、Ed25519 密钥
   - 公钥存储在服务器配置中

2. **密码认证**
   - 支持 PAM 集成
   - 可配置密码复杂度要求

## 数据转发协议

当用户选择资产后，建立透明数据通道：

```
User <-----> SSH Jump Server <-----> Agent <-----> Target Service
```

数据转发采用双工通道：
- **上行**：用户 -> Agent -> 目标服务
- **下行**：目标服务 -> Agent -> 用户

数据格式为原始字节流，不做任何修改。

## 端口配置

### 服务器端口

| 端口 | 用途 | 协议 |
|------|------|------|
| 2222 | SSH 用户连接 | SSH |
| 8888 | Agent 注册/心跳 | 自定义 TCP |

### 防火墙建议

```bash
# 允许 SSH 用户连接
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# 允许 Agent 连接（限制来源 IP）
iptables -A INPUT -p tcp --dport 8888 -s 10.0.0.0/8 -j ACCEPT

# 拒绝其他来源的 Agent 连接
iptables -A INPUT -p tcp --dport 8888 -j DROP
```

## 安全考虑

### 传输加密

- Agent 与服务器之间的通信可使用 TLS 加密（可选配置）
- SSH 连接使用标准 SSH 加密

### 认证机制

1. **Agent 认证**：基于预共享 Token
2. **用户认证**：SSH 公钥或密码
3. **会话管理**：每个连接独立的会话 ID

### 防重放攻击

- 心跳消息包含时间戳
- 服务器检查消息顺序
- 连接异常时立即断开
