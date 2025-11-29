@echo off
echo 准备发布到GitHub...
echo.

echo 1. 清理Python缓存文件...
if exist __pycache__ rmdir /s /q __pycache__
if exist *.pyc del /q *.pyc

echo 2. 运行测试...
python test_jwt_gui.py
if %errorlevel% neq 0 (
    echo 测试失败，请修复错误后再发布
    pause
    exit /b 1
)

echo.
echo 3. 准备完成！
echo.
echo 接下来请执行以下步骤：
echo 1. 在GitHub上创建新仓库
echo 2. 添加远程仓库: git remote add origin https://github.com/apzx7/jwt-gui.git
echo 3. 提交代码: git add .
echo 4. 提交更改: git commit -m "Initial release"
echo 5. 推送到GitHub: git push -u origin main
echo.
echo 注意：请将yourusername替换为您的GitHub用户名
echo.
pause