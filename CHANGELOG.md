# 更新日志

所有重要的项目变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增
- 错误注入测试功能
- 密钥格式转换功能
- 高级时间戳操作功能
- 日志记录系统
- GitHub Actions自动化测试
- 详细的发布指南

### 改进
- 优化用户界面
- 提高代码可读性和可维护性
- 添加更全面的文档

### 修复
- 修复GUI启动问题
- 优化依赖版本兼容性

## [1.0.0] - 2023-11-15

### 新增
- JWT解析功能
- JWT篡改功能
- 签名验证功能
- 密钥破解功能
- 漏洞利用功能
- 设置配置功能

### 技术实现
- 基于tkinter的图形用户界面
- 集成jwt_tool.py的核心功能
- 支持多种JWT签名算法
- 支持HTTP代理配置

### 系统要求
- Python 3.6+
- tkinter库
- PyJWT>=2.0.0
- requests>=2.25.0
- pycryptodomex>=3.10.0
- cryptography>=3.4.0