# SSH Mesh Orchestrator

An automated tool to establish **full-mesh passwordless SSH trust**
among multiple servers.

一个用于自动化建立多台服务器之间 **全互信 SSH 免密登录** 的工具。

> **Note / 说明**  
> This script was developed with the assistance of AI and has been reviewed,
> tested, and verified in real environments.  
> 本脚本在 AI 辅助下完成，并已经过人工审查与实际环境验证。

## File Structure / 目录结构

- `ssh_mesh.sh` — Main script / 主脚本  
- `nodes` — List of server IPs or hostnames (one per line)  
  节点列表（每行一个 IP 或主机名）

## Quick Start / 使用方法

1. **Configure Nodes / 配置节点列表**  
   Add server IPs or hostnames to the `nodes` file.  
   在 `nodes` 文件中填写服务器 IP 或主机名。

2. **Install Dependency / 安装依赖**  
   Ensure `sshpass` is installed.  
   确保系统已安装 `sshpass`。

3. **Run / 运行**

   ```bash
   chmod +x ssh_mesh.sh
   ./ssh_mesh.sh
