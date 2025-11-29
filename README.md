# JWT Tool GUI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

这是一个基于 `jwt_tool.py` 的图形化界面工具，提供了直观的操作方式来处理JWT令牌。

## 功能特点

- **JWT解析**: 解码并显示JWT的Header、Payload和Signature部分
- **JWT篡改**: 修改Header和Payload内容，并使用不同算法重新签名
- **签名验证**: 使用公钥或JWKS文件验证JWT签名
- **密钥破解**: 支持字典攻击、密码尝试和密钥文件破解
- **漏洞利用**: 实现各种JWT漏洞利用技术
- **错误注入测试**: 测试JWT处理器的错误处理能力
- **密钥格式转换**: 在不同密钥格式之间进行转换
- **高级时间戳操作**: 批量修改JWT时间戳声明
- **日志记录系统**: 记录和查看操作日志
- **设置**: 配置代理和其他选项

## 安装

### 克隆仓库

```bash
git clone https://github.com/yourusername/jwt-gui.git
cd jwt-gui
```

### 安装依赖

```bash
pip install -r requirements.txt
```

### 或者手动安装依赖

```bash
pip install PyJWT requests pycryptodomex cryptography
```

## 使用方法

### 启动方式

1. **推荐方式**: 双击运行 `start_gui.bat` 文件（批处理脚本）
2. 或者在命令行中执行：
   - `python jwt_gui_integrated.py`（集成版，推荐）

### 基本流程

1. 在"JWT解析"选项卡中输入JWT令牌
2. 点击"解析JWT"按钮查看令牌内容
3. 根据需要切换到其他选项卡进行相应操作

### 各选项卡功能

#### JWT解析
- 输入JWT令牌并解析其内容
- 显示Header、Payload和Signature部分
- 发送HTTP请求测试JWT令牌

#### JWT篡改
- 修改Header和Payload内容
- 选择签名算法和密钥
- 添加或删除声明
- 生成新的JWT令牌

#### 签名验证
- 使用公钥文件验证JWT签名
- 使用JWKS文件验证JWT签名
- 查看验证结果

#### 密钥破解
- 使用字典文件进行字典攻击
- 尝试特定密码
- 使用密钥文件进行破解
- 内置多种密码字典：
  - `top500.txt`: 包含500个最常用密码
  - `top1000.txt`: 包含1000个最常用密码
  - `top3000.txt`: 包含3000个最常用密码
  - `top6000.txt`: 包含6000个最常用密码
  - `top19576.txt`: 包含19576个常用密码

#### 漏洞利用
- 实现alg:none漏洞利用
- 实现空签名漏洞利用
- 实现空白密码漏洞利用
- 实现Psychic签名漏洞利用
- 实现JWKS欺骗攻击
- 实现密钥混淆攻击
- 实现内联JWKS注入

#### 设置
- 配置HTTP/HTTPS代理
- 设置其他选项（忽略SSL证书验证、不使用代理等）

## 注意事项

1. 本工具需要Python 3.6+环境
2. 需要安装tkinter库（通常Python自带）
3. 某些功能可能需要额外的依赖库（如requests、pycryptodomex等）

## 系统要求

- Python 3.6+
- tkinter库
- Windows操作系统（推荐）

## 文件说明

- `jwt_gui_integrated.py`: 集成版GUI（推荐），将jwt_tool.py的所有功能直接集成到GUI中
- `start_gui.bat`: 启动脚本（批处理）
- `jwt_tool.py`: 原始JWT工具命令行版本
- `README.md`: 说明文档
- `requirements.txt`: 项目依赖列表
- `test_jwt_gui.py`: 单元测试文件
- `top500.txt`: 包含500个最常用密码的字典文件
- `top1000.txt`: 包含1000个最常用密码的字典文件
- `top3000.txt`: 包含3000个最常用密码的字典文件
- `top6000.txt`: 包含6000个最常用密码的字典文件
- `top19576.txt`: 包含19576个常用密码的字典文件

## 故障排除

如果GUI无法启动，请检查：

1. Python是否正确安装
2. tkinter库是否可用
3. 所有依赖库是否已安装

如果集成版GUI无法满足需求，可以尝试使用原始命令行版本jwt_tool.py。

## 贡献

欢迎贡献代码！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何参与项目开发。

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 致谢

- 基于 [jwt_tool](https://github.com/ticarpi/jwt_tool) 项目开发
- 感谢所有贡献者的支持