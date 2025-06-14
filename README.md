# 端口转发管理工具 🚀

一个轻量级端口转发管理工具，基于 Flask 和 Vue 3，支持 TCP/UDP 转发规则管理，提供美观的 Web 界面 🌐 和实时端口监控 🔍。

## 功能亮点 ✨

- **规则管理**：创建、修改、启动、停止、删除 TCP/UDP 转发规则 📋
- **有效期控制**：设置规则有效期，停止时暂停计时 ⏰
- **端口检测**：实时检查端口可用性，推荐可用端口 🎯
- **系统状态**：监控规则数、CPU/内存、已用端口 📊
- **全端口支持**：1-65535 端口范围（低端口需 root 权限） 🔢
- **现代 UI**：Tailwind CSS + Element Plus，响应式设计 😎

## 技术栈 🛠️

- **后端**：Python, Flask, SQLite, socat
- **前端**：Vue 3, Tailwind CSS, Element Plus

## 安装步骤 ⚙️

1. **准备环境**：
   - Python 3.8+
   - 安装 socat：
     ```bash
     # Ubuntu
     sudo apt-get install socat
     # CentOS
     sudo yum install socat
     # macOS
     brew install socat
     ```

2. **克隆项目**：
   ```bash
   git clone https://github.com/your-username/port-forwarding-tool.git
   cd port-forwarding-tool
   ```

3. **安装后端依赖**：
   ```bash
   pip install flask flask-cors psutil colorlog
   ```

4. **运行后端**：
   ```bash
   python backend.py --port-range 1-65535
   ```
   用低端口（如 80）需 root：
   ```bash
   sudo python backend.py --port-range 1-65535
   ```

5. **运行前端**：
   打开 `index.html` 或用静态服务器：
   ```bash
   python -m http.server 8000
   ```
   访问 `http://localhost:8000` 🚪

## 使用指南 📖

1. **管理后端**：添加/切换后端（默认 `http://localhost:2017`） 🖥️
2. **新建规则**：设置 ID、协议、端口、目标地址、有效期，自动运行 ✅
3. **管理规则**：启动/停止（暂停计时）、修改、删除规则 🔧
4. **检查端口**：输入端口号，查看可用性，折叠状态不收起 🔍
5. **系统状态**：查看规则数、CPU/内存、端口范围 📈

## 测试建议 🧪

- **暂停计时**：设 10 分钟有效期，运行 2 分钟停止，确认剩 8 分钟 ⏱️
- **修改规则**：编辑端口或有效期，确认原端口不报占用错误 🔄
- **端口范围**：用 80 或 443 创建规则，确认成功（需 root） 🔢
- **系统状态**：检查端口，确认折叠不收起，结果正常显示 🖱️

## 注意事项 ⚠️

- **权限**：低端口（1-1023）需 root 权限 🛡️
- **CDN**：前端依赖 Tailwind/Vue/Element Plus CDN，需联网 🌍
- **数据库**：规则存 `forward.db`，自动创建/迁移 💾
- **socat**：必须安装，否则转发失败 🚫

## 项目结构 📁

```
port-forwarding-tool/
├── backend.py     # 后端 Flask 应用
├── index.html     # 前端页面
├── forward.db     # SQLite 数据库（运行时生成）
└── README.md      # 说明文档
```

## 贡献 🤝

欢迎提 issue 或 PR！Fork 项目，创建分支，提交更改即可。

---
反馈请提 issue 或联系 jwbb903@gmail.com 📧
