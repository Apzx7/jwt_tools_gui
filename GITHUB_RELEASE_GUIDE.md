# GitHub发布指南

## 准备工作

1. 确保您已在GitHub上创建了一个新仓库（例如：jwt-gui）
2. 确保您已安装Git并配置了用户信息

## 发布步骤

### 1. 添加远程仓库

```bash
git remote add origin https://github.com/apzx7/jwt-gui.git
```


### 2. 推送到GitHub

```bash
git push -u origin master
```

### 3. 创建发布版本

1. 在GitHub仓库页面，点击"Releases"选项卡
2. 点击"Create a new release"
3. 选择"Choose a tag"，输入版本号（例如：v1.0.0）
4. 标题输入"Release v1.0.0"
5. 在描述框中添加发布说明
6. 点击"Publish release"

### 4. 设置仓库信息

1. 在仓库主页，点击"Settings"选项卡
2. 在"Options"部分，设置仓库描述和网站URL（如果有）
3. 在"Features"部分，根据需要启用Issues、Projects、Wiki等功能
4. 在"Merge button"部分，选择合适的合并策略

## 后续维护

### 添加新功能

1. 创建新分支：`git checkout -b feature/new-feature`
2. 开发并测试新功能
3. 提交更改：`git commit -m "Add new feature"`
4. 推送分支：`git push origin feature/new-feature`
5. 在GitHub上创建Pull Request
6. 合并到主分支后，删除功能分支

### 发布新版本

1. 更新CHANGELOG.md
2. 创建发布标签：`git tag -a v1.1.0 -m "Release version 1.1.0"`
3. 推送标签：`git push origin v1.1.0`
4. 在GitHub上创建新的Release

## 注意事项

1. 在发布前确保所有测试通过
2. 检查代码质量和安全性
3. 更新README.md中的信息（如果有变化）
4. 定期检查和更新依赖项

## 自动化

项目已配置GitHub Actions，会在以下情况自动运行测试：

- 推送到main或develop分支
- 创建Pull Request

这有助于确保代码质量和稳定性。