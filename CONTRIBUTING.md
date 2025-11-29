# 贡献指南

感谢您对JWT Tool GUI项目的关注！我们欢迎各种形式的贡献，包括但不限于：

- 报告错误
- 提出新功能建议
- 提交代码改进
- 改进文档
- 添加测试用例

## 如何贡献

### 报告错误

如果您发现了错误，请在GitHub上创建一个新的issue，并尽可能提供以下信息：

- 错误描述
- 复现步骤
- 预期行为
- 实际行为
- 环境信息（操作系统、Python版本等）
- 相关截图（如果有）

### 提出新功能建议

如果您有新功能的想法，请在GitHub上创建一个新的issue，并详细描述：

- 功能描述
- 使用场景
- 预期效果
- 可能的实现方式

### 提交代码

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建一个 Pull Request

### 代码规范

- 请确保您的代码符合PEP 8规范
- 添加必要的注释和文档字符串
- 确保您的代码不会破坏现有功能
- 为新功能添加适当的测试用例
- 更新相关文档（如README.md、CHANGELOG.md等）

### 测试

在提交代码前，请确保：

1. 所有现有测试通过
2. 新功能有对应的测试用例
3. GUI界面正常工作
4. 代码没有明显的性能问题

## 开发环境设置

1. 克隆仓库：
   ```bash
   git clone https://github.com/Apzx7/jwt-gui.git
   cd jwt-gui
   ```

2. 创建虚拟环境：
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # 或
   venv\Scripts\activate  # Windows
   ```

3. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

4. 运行测试：
   ```bash
   python test_jwt_gui.py
   ```

## 许可证

通过贡献您的代码，您同意您的贡献将在MIT许可证下授权。