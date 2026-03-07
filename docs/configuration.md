# SSH Jump Server 配置指南

`ssh_jump_server` 和 `ssh_jump_agent` 以命令行参数启动。

关键补充：
- `ssh_jump_server` 支持 `--users-file`、`--agent-token-file`、`--pid-file`
- 启动引导用户和运行时用户/节点 CRUD 会持久化到对应文件
- 最近访问记录会保存，供 `@1`、`@2` 快捷重连使用

最准确的参数说明以 `./ssh_jump_server --help` 和 `./ssh_jump_agent --help` 为准。
