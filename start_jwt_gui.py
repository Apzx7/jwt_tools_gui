#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import tkinter as tk
from tkinter import messagebox

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import jwt_gui_integrated
    print("正在启动JWT GUI工具...")
    
    # 创建主窗口
    root = tk.Tk()
    
    # 创建应用实例
    app = jwt_gui_integrated.JWTToolGUI(root)
    
    # 启动主循环
    root.mainloop()
    
except ImportError as e:
    print(f"导入错误: {e}")
    print("请确保所有依赖项已正确安装")
    input("按任意键退出...")
except Exception as e:
    print(f"启动错误: {e}")
    input("按任意键退出...")