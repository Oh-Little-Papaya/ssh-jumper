# SSH Jump Server 文档

欢迎来到 SSH Jump Server 文档中心。

## 文档索引

### 用户指南
- [主README](../README.md) - 项目概述和快速开始
- [快速开始](quickstart.md) - 5分钟快速上手指南
- [配置指南](configuration.md) - 详细配置说明
- [部署指南](deployment.md) - 生产环境部署

### 开发文档
- [协议文档](protocol.md) - Agent通信协议详解
- [性能优化](performance.md) - 性能调优指南

### Docker环境
- [Docker测试环境](../docker/README.md) - Docker完整测试环境说明

## 快速链接

- 项目版本: **v2.0.0**
- 最后更新: 2026年2月
- 主要特性: NAT 回拨穿透、子节点 CRUD、Folly 可选性能优化

## 版本亮点

### v2.0.0 (当前版本)
- ✨ **简洁界面**: 全新JumpServer风格设计，40%更多内容空间
- 🐛 **EOF修复**: 修复exit后卡住的问题
- ✨ **优雅退出**: 自动返回菜单，无需重连
- ✨ **最近访问**: 记录最近连接，快速重连
- 🎨 **视觉优化**: 彩色状态指示，清晰的层次
- 🌐 **NAT 穿透**: 支持 Agent 回拨建立转发通道
- 🧩 **管理增强**: 公网管理节点支持子节点 CRUD
- ⚡ **性能优化**: 支持 Folly ON/OFF 对比与压测脚本

## 支持

如有问题，请查看 [故障排查](../README.md#故障排查) 或提交 Issue。
