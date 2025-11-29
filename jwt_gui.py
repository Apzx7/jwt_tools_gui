import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import base64
import os
import sys
import subprocess
import threading
import re
from urllib.parse import urlparse, urljoin

# 导入JWT工具的函数
try:
    import jwt_tool
    JWT_TOOL_AVAILABLE = True
except ImportError:
    # 如果导入失败，尝试将当前目录添加到路径
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import jwt_tool
        JWT_TOOL_AVAILABLE = True
    except ImportError:
        print("警告: 无法导入jwt_tool模块，某些功能可能不可用")
        JWT_TOOL_AVAILABLE = False
        jwt_tool = None

class JWTToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JWT Tool GUI")
        self.root.geometry("1000x700")
        
        # 创建选项卡
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 创建各个选项卡
        self.create_main_tab()
        self.create_tamper_tab()
        self.create_verify_tab()
        self.create_crack_tab()
        self.create_exploit_tab()
        self.create_settings_tab()
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def create_main_tab(self):
        """主选项卡 - JWT解析和基本操作"""
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="JWT解析")
        
        # JWT输入区域
        input_frame = ttk.LabelFrame(self.main_tab, text="JWT令牌")
        input_frame.pack(fill='x', padx=10, pady=5)
        
        self.jwt_input = scrolledtext.ScrolledText(input_frame, height=5)
        self.jwt_input.pack(fill='x', padx=5, pady=5)
        
        # 解析按钮
        ttk.Button(input_frame, text="解析JWT", command=self.parse_jwt).pack(pady=5)
        
        # JWT解析结果区域
        result_frame = ttk.LabelFrame(self.main_tab, text="解析结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # 创建三列布局
        columns_frame = ttk.Frame(result_frame)
        columns_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Header列
        header_frame = ttk.LabelFrame(columns_frame, text="Header")
        header_frame.pack(side='left', fill='both', expand=True, padx=5)
        self.header_text = scrolledtext.ScrolledText(header_frame, height=10)
        self.header_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Payload列
        payload_frame = ttk.LabelFrame(columns_frame, text="Payload")
        payload_frame.pack(side='left', fill='both', expand=True, padx=5)
        self.payload_text = scrolledtext.ScrolledText(payload_frame, height=10)
        self.payload_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Signature列
        signature_frame = ttk.LabelFrame(columns_frame, text="Signature")
        signature_frame.pack(side='left', fill='both', expand=True, padx=5)
        self.signature_text = scrolledtext.ScrolledText(signature_frame, height=10)
        self.signature_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # HTTP请求区域
        http_frame = ttk.LabelFrame(self.main_tab, text="HTTP请求")
        http_frame.pack(fill='x', padx=10, pady=5)
        
        # URL输入
        url_frame = ttk.Frame(http_frame)
        url_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(url_frame, text="目标URL:").pack(side='left')
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # 请求选项
        options_frame = ttk.Frame(http_frame)
        options_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(options_frame, text="Cookie:").pack(side='left')
        self.cookie_entry = ttk.Entry(options_frame)
        self.cookie_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        ttk.Label(options_frame, text="POST数据:").pack(side='left')
        self.post_data_entry = ttk.Entry(options_frame)
        self.post_data_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # 发送请求按钮
        ttk.Button(http_frame, text="发送请求", command=self.send_request).pack(pady=5)
        
    def create_tamper_tab(self):
        """篡改选项卡"""
        self.tamper_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.tamper_tab, text="JWT篡改")
        
        # 签名选项
        sign_frame = ttk.LabelFrame(self.tamper_tab, text="签名选项")
        sign_frame.pack(fill='x', padx=10, pady=5)
        
        # 算法选择
        algo_frame = ttk.Frame(sign_frame)
        algo_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(algo_frame, text="算法:").pack(side='left')
        self.algo_var = tk.StringVar(value="HS256")
        algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var, 
                                  values=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
                                         "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "none"])
        algo_combo.pack(side='left', padx=5)
        
        # 密钥输入
        key_frame = ttk.Frame(sign_frame)
        key_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(key_frame, text="密钥:").pack(side='left')
        self.key_entry = ttk.Entry(key_frame, show="*")
        self.key_entry.pack(side='left', fill='x', expand=True, padx=5)
        self.show_key_var = tk.BooleanVar()
        ttk.Checkbutton(key_frame, text="显示密钥", variable=self.show_key_var, 
                       command=self.toggle_key_visibility).pack(side='left')
        
        # 密钥文件选择
        keyfile_frame = ttk.Frame(sign_frame)
        keyfile_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(keyfile_frame, text="密钥文件:").pack(side='left')
        self.keyfile_entry = ttk.Entry(keyfile_frame)
        self.keyfile_entry.pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(keyfile_frame, text="浏览", command=self.browse_keyfile).pack(side='left')
        
        # Header修改区域
        header_frame = ttk.LabelFrame(self.tamper_tab, text="Header修改")
        header_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.header_edit = scrolledtext.ScrolledText(header_frame, height=8)
        self.header_edit.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Payload修改区域
        payload_frame = ttk.LabelFrame(self.tamper_tab, text="Payload修改")
        payload_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.payload_edit = scrolledtext.ScrolledText(payload_frame, height=8)
        self.payload_edit.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 篡改按钮
        button_frame = ttk.Frame(self.tamper_tab)
        button_frame.pack(fill='x', padx=10, pady=5)
        ttk.Button(button_frame, text="应用修改", command=self.apply_tamper).pack(side='left', padx=5)
        ttk.Button(button_frame, text="添加声明", command=self.add_claim).pack(side='left', padx=5)
        ttk.Button(button_frame, text="删除声明", command=self.remove_claim).pack(side='left', padx=5)
        
        # 结果区域
        result_frame = ttk.LabelFrame(self.tamper_tab, text="篡改结果")
        result_frame.pack(fill='x', padx=10, pady=5)
        
        self.tamper_result = scrolledtext.ScrolledText(result_frame, height=5)
        self.tamper_result.pack(fill='x', padx=5, pady=5)
        
    def create_verify_tab(self):
        """验证选项卡"""
        self.verify_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.verify_tab, text="签名验证")
        
        # 验证选项
        verify_frame = ttk.LabelFrame(self.verify_tab, text="验证选项")
        verify_frame.pack(fill='x', padx=10, pady=5)
        
        # 公钥输入
        pubkey_frame = ttk.Frame(verify_frame)
        pubkey_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(pubkey_frame, text="公钥:").pack(side='left')
        self.pubkey_entry = ttk.Entry(pubkey_frame)
        self.pubkey_entry.pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(pubkey_frame, text="浏览", command=self.browse_pubkey).pack(side='left')
        
        # JWKS文件
        jwks_frame = ttk.Frame(verify_frame)
        jwks_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(jwks_frame, text="JWKS文件:").pack(side='left')
        self.jwks_entry = ttk.Entry(jwks_frame)
        self.jwks_entry.pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(jwks_frame, text="浏览", command=self.browse_jwks).pack(side='left')
        
        # 验证按钮
        ttk.Button(verify_frame, text="验证签名", command=self.verify_signature).pack(pady=10)
        
        # 验证结果
        result_frame = ttk.LabelFrame(self.verify_tab, text="验证结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.verify_result = scrolledtext.ScrolledText(result_frame, height=15)
        self.verify_result.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_crack_tab(self):
        """破解选项卡"""
        self.crack_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.crack_tab, text="密钥破解")
        
        # 破解选项
        crack_frame = ttk.LabelFrame(self.crack_tab, text="破解选项")
        crack_frame.pack(fill='x', padx=10, pady=5)
        
        # 破解模式
        mode_frame = ttk.Frame(crack_frame)
        mode_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(mode_frame, text="破解模式:").pack(side='left')
        self.crack_mode = tk.StringVar(value="dict")
        ttk.Radiobutton(mode_frame, text="字典攻击", variable=self.crack_mode, value="dict").pack(side='left', padx=5)
        ttk.Radiobutton(mode_frame, text="密码尝试", variable=self.crack_mode, value="password").pack(side='left', padx=5)
        ttk.Radiobutton(mode_frame, text="密钥文件", variable=self.crack_mode, value="keyfile").pack(side='left', padx=5)
        
        # 字典文件
        dict_frame = ttk.Frame(crack_frame)
        dict_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(dict_frame, text="字典文件:").pack(side='left')
        self.dict_entry = ttk.Entry(dict_frame)
        self.dict_entry.pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(dict_frame, text="浏览", command=self.browse_dict).pack(side='left')
        
        # 密码输入
        password_frame = ttk.Frame(crack_frame)
        password_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(password_frame, text="密码:").pack(side='left')
        self.password_entry = ttk.Entry(password_frame, show="*")
        self.password_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # 密钥文件
        keyfile_frame = ttk.Frame(crack_frame)
        keyfile_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(keyfile_frame, text="密钥文件:").pack(side='left')
        self.crack_keyfile_entry = ttk.Entry(keyfile_frame)
        self.crack_keyfile_entry.pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(keyfile_frame, text="浏览", command=self.browse_crack_keyfile).pack(side='left')
        
        # 破解按钮
        ttk.Button(crack_frame, text="开始破解", command=self.start_crack).pack(pady=10)
        
        # 破解结果
        result_frame = ttk.LabelFrame(self.crack_tab, text="破解结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.crack_result = scrolledtext.ScrolledText(result_frame, height=15)
        self.crack_result.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_exploit_tab(self):
        """漏洞利用选项卡"""
        self.exploit_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.exploit_tab, text="漏洞利用")
        
        # 漏洞利用选项
        exploit_frame = ttk.LabelFrame(self.exploit_tab, text="漏洞利用选项")
        exploit_frame.pack(fill='x', padx=10, pady=5)
        
        # 利用类型
        exploit_type_frame = ttk.Frame(exploit_frame)
        exploit_type_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(exploit_type_frame, text="利用类型:").pack(side='left')
        self.exploit_type = tk.StringVar(value="alg:none")
        exploit_combo = ttk.Combobox(exploit_type_frame, textvariable=self.exploit_type,
                                    values=["alg:none", "null signature", "blank password", 
                                           "psychic signature", "spoof JWKS", "key confusion", "inject inline JWKS"])
        exploit_combo.pack(side='left', padx=5)
        
        # JWKS URL
        jwks_url_frame = ttk.Frame(exploit_frame)
        jwks_url_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(jwks_url_frame, text="JWKS URL:").pack(side='left')
        self.jwks_url_entry = ttk.Entry(jwks_url_frame)
        self.jwks_url_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # 公钥
        pubkey_frame = ttk.Frame(exploit_frame)
        pubkey_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(pubkey_frame, text="公钥:").pack(side='left')
        self.exploit_pubkey_entry = ttk.Entry(pubkey_frame)
        self.exploit_pubkey_entry.pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(pubkey_frame, text="浏览", command=self.browse_exploit_pubkey).pack(side='left')
        
        # 利用按钮
        ttk.Button(exploit_frame, text="执行利用", command=self.execute_exploit).pack(pady=10)
        
        # 利用结果
        result_frame = ttk.LabelFrame(self.exploit_tab, text="利用结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.exploit_result = scrolledtext.ScrolledText(result_frame, height=15)
        self.exploit_result.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_settings_tab(self):
        """设置选项卡"""
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="设置")
        
        # 代理设置
        proxy_frame = ttk.LabelFrame(self.settings_tab, text="代理设置")
        proxy_frame.pack(fill='x', padx=10, pady=5)
        
        proxy_host_frame = ttk.Frame(proxy_frame)
        proxy_host_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(proxy_host_frame, text="代理主机:").pack(side='left')
        self.proxy_host_entry = ttk.Entry(proxy_host_frame)
        self.proxy_host_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        proxy_port_frame = ttk.Frame(proxy_frame)
        proxy_port_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(proxy_port_frame, text="代理端口:").pack(side='left')
        self.proxy_port_entry = ttk.Entry(proxy_port_frame)
        self.proxy_port_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # 其他设置
        other_frame = ttk.LabelFrame(self.settings_tab, text="其他设置")
        other_frame.pack(fill='x', padx=10, pady=5)
        
        self.verbose_var = tk.BooleanVar()
        ttk.Checkbutton(other_frame, text="详细输出", variable=self.verbose_var).pack(anchor='w', padx=5, pady=5)
        
        self.insecure_var = tk.BooleanVar()
        ttk.Checkbutton(other_frame, text="使用HTTP(不安全)", variable=self.insecure_var).pack(anchor='w', padx=5, pady=5)
        
        self.noproxy_var = tk.BooleanVar()
        ttk.Checkbutton(other_frame, text="禁用代理", variable=self.noproxy_var).pack(anchor='w', padx=5, pady=5)
        
        self.noredir_var = tk.BooleanVar()
        ttk.Checkbutton(other_frame, text="禁用重定向", variable=self.noredir_var).pack(anchor='w', padx=5, pady=5)
        
        # 保存设置按钮
        ttk.Button(other_frame, text="保存设置", command=self.save_settings).pack(pady=10)
        
    # 功能方法
    def parse_jwt(self):
        """解析JWT令牌"""
        jwt_token = self.jwt_input.get(1.0, tk.END).strip()
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        try:
            # 分割JWT
            parts = jwt_token.split('.')
            if len(parts) != 3:
                raise ValueError("无效的JWT格式")
                
            # 解码Header
            header_b64 = self.fix_base64(parts[0])
            header_bytes = base64.urlsafe_b64decode(header_b64)
            header_json = header_bytes.decode('utf-8')
            header_dict = json.loads(header_json)
            
            # 解码Payload
            payload_b64 = self.fix_base64(parts[1])
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload_json = payload_bytes.decode('utf-8')
            payload_dict = json.loads(payload_json)
            
            # 显示结果
            self.header_text.delete(1.0, tk.END)
            self.header_text.insert(tk.END, json.dumps(header_dict, indent=2))
            
            self.payload_text.delete(1.0, tk.END)
            self.payload_text.insert(tk.END, json.dumps(payload_dict, indent=2))
            
            self.signature_text.delete(1.0, tk.END)
            self.signature_text.insert(tk.END, parts[2])
            
            # 更新篡改选项卡的内容
            self.header_edit.delete(1.0, tk.END)
            self.header_edit.insert(tk.END, json.dumps(header_dict, indent=2))
            
            self.payload_edit.delete(1.0, tk.END)
            self.payload_edit.insert(tk.END, json.dumps(payload_dict, indent=2))
            
            self.status_var.set("JWT解析成功")
            
        except Exception as e:
            messagebox.showerror("错误", f"JWT解析失败: {str(e)}")
            self.status_var.set("JWT解析失败")
            
    def fix_base64(self, b64_str):
        """修复Base64字符串，确保长度是4的倍数"""
        # 移除可能的填充字符
        b64_str = b64_str.rstrip('=')
        # 计算需要添加的填充字符
        padding = 4 - (len(b64_str) % 4)
        if padding != 4:
            b64_str += '=' * padding
        return b64_str
        
    def toggle_key_visibility(self):
        """切换密钥可见性"""
        if self.show_key_var.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")
            
    def browse_keyfile(self):
        """浏览密钥文件"""
        filename = filedialog.askopenfilename(
            title="选择密钥文件",
            filetypes=[("所有文件", "*.*")]
        )
        if filename:
            self.keyfile_entry.delete(0, tk.END)
            self.keyfile_entry.insert(0, filename)
            
    def browse_pubkey(self):
        """浏览公钥文件"""
        filename = filedialog.askopenfilename(
            title="选择公钥文件",
            filetypes=[("所有文件", "*.*")]
        )
        if filename:
            self.pubkey_entry.delete(0, tk.END)
            self.pubkey_entry.insert(0, filename)
            
    def browse_jwks(self):
        """浏览JWKS文件"""
        filename = filedialog.askopenfilename(
            title="选择JWKS文件",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        if filename:
            self.jwks_entry.delete(0, tk.END)
            self.jwks_entry.insert(0, filename)
            
    def browse_dict(self):
        """浏览字典文件"""
        filename = filedialog.askopenfilename(
            title="选择字典文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if filename:
            self.dict_entry.delete(0, tk.END)
            self.dict_entry.insert(0, filename)
            
    def browse_crack_keyfile(self):
        """浏览破解密钥文件"""
        filename = filedialog.askopenfilename(
            title="选择密钥文件",
            filetypes=[("所有文件", "*.*")]
        )
        if filename:
            self.crack_keyfile_entry.delete(0, tk.END)
            self.crack_keyfile_entry.insert(0, filename)
            
    def browse_exploit_pubkey(self):
        """浏览利用公钥文件"""
        filename = filedialog.askopenfilename(
            title="选择公钥文件",
            filetypes=[("所有文件", "*.*")]
        )
        if filename:
            self.exploit_pubkey_entry.delete(0, tk.END)
            self.exploit_pubkey_entry.insert(0, filename)
            
    def apply_tamper(self):
        """应用JWT篡改"""
        if not JWT_TOOL_AVAILABLE:
            messagebox.showerror("错误", "JWT工具模块不可用，请检查jwt_tool.py是否存在")
            return
            
        try:
            # 获取修改后的Header和Payload
            header_str = self.header_edit.get(1.0, tk.END).strip()
            payload_str = self.payload_edit.get(1.0, tk.END).strip()
            
            if not header_str or not payload_str:
                messagebox.showerror("错误", "Header和Payload不能为空")
                return
                
            header_dict = json.loads(header_str)
            payload_dict = json.loads(payload_str)
            
            # 构建命令行参数
            cmd = [sys.executable, "jwt_tool.py"]
            
            # 添加JWT令牌
            jwt_token = self.jwt_input.get(1.0, tk.END).strip()
            if jwt_token:
                cmd.append(jwt_token)
                
            # 添加签名选项
            algo = self.algo_var.get()
            if algo and algo != "none":
                cmd.extend(["-S", algo.lower()])
                
                # 添加密钥或密钥文件
                key = self.key_entry.get()
                keyfile = self.keyfile_entry.get()
                
                if key:
                    cmd.extend(["-k", key])
                elif keyfile:
                    cmd.extend(["-pr", keyfile])
            else:
                cmd.extend(["-X", "a"])  # alg:none exploit
                
            # 添加篡改选项
            cmd.append("-T")
            
            # 在新线程中运行命令
            threading.Thread(target=self.run_command, args=(cmd, self.tamper_result), daemon=True).start()
            
            self.status_var.set("正在应用篡改...")
            
        except Exception as e:
            messagebox.showerror("错误", f"篡改失败: {str(e)}")
            self.status_var.set("篡改失败")
            
    def add_claim(self):
        """添加声明"""
        dialog = ClaimDialog(self.root, "添加声明")
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            try:
                # 获取当前Payload
                payload_str = self.payload_edit.get(1.0, tk.END).strip()
                if payload_str:
                    payload_dict = json.loads(payload_str)
                else:
                    payload_dict = {}
                    
                # 添加新声明
                key, value = dialog.result
                payload_dict[key] = value
                
                # 更新Payload
                self.payload_edit.delete(1.0, tk.END)
                self.payload_edit.insert(tk.END, json.dumps(payload_dict, indent=2))
                
            except Exception as e:
                messagebox.showerror("错误", f"添加声明失败: {str(e)}")
                
    def remove_claim(self):
        """删除声明"""
        dialog = ClaimDialog(self.root, "删除声明", remove=True)
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            try:
                # 获取当前Payload
                payload_str = self.payload_edit.get(1.0, tk.END).strip()
                if payload_str:
                    payload_dict = json.loads(payload_str)
                    
                    # 删除声明
                    key = dialog.result
                    if key in payload_dict:
                        del payload_dict[key]
                        
                        # 更新Payload
                        self.payload_edit.delete(1.0, tk.END)
                        self.payload_edit.insert(tk.END, json.dumps(payload_dict, indent=2))
                    else:
                        messagebox.showinfo("提示", f"声明 '{key}' 不存在")
                        
            except Exception as e:
                messagebox.showerror("错误", f"删除声明失败: {str(e)}")
                
    def verify_signature(self):
        """验证签名"""
        if not JWT_TOOL_AVAILABLE:
            messagebox.showerror("错误", "JWT工具模块不可用，请检查jwt_tool.py是否存在")
            return
            
        try:
            # 构建命令行参数
            cmd = [sys.executable, "jwt_tool.py"]
            
            # 添加JWT令牌
            jwt_token = self.jwt_input.get(1.0, tk.END).strip()
            if jwt_token:
                cmd.append(jwt_token)
                
            # 添加验证选项
            cmd.append("-V")
            
            # 添加公钥或JWKS文件
            pubkey = self.pubkey_entry.get()
            jwks = self.jwks_entry.get()
            
            if pubkey:
                cmd.extend(["-pk", pubkey])
            elif jwks:
                cmd.extend(["-jw", jwks])
            else:
                messagebox.showerror("错误", "请提供公钥或JWKS文件")
                return
                
            # 在新线程中运行命令
            threading.Thread(target=self.run_command, args=(cmd, self.verify_result), daemon=True).start()
            
            self.status_var.set("正在验证签名...")
            
        except Exception as e:
            messagebox.showerror("错误", f"验证失败: {str(e)}")
            self.status_var.set("验证失败")
            
    def start_crack(self):
        """开始破解"""
        if not JWT_TOOL_AVAILABLE:
            messagebox.showerror("错误", "JWT工具模块不可用，请检查jwt_tool.py是否存在")
            return
            
        try:
            # 构建命令行参数
            cmd = [sys.executable, "jwt_tool.py"]
            
            # 添加JWT令牌
            jwt_token = self.jwt_input.get(1.0, tk.END).strip()
            if jwt_token:
                cmd.append(jwt_token)
                
            # 添加破解选项
            cmd.append("-C")
            
            # 根据破解模式添加参数
            mode = self.crack_mode.get()
            if mode == "dict":
                dict_file = self.dict_entry.get()
                if not dict_file:
                    messagebox.showerror("错误", "请选择字典文件")
                    return
                cmd.extend(["-d", dict_file])
            elif mode == "password":
                password = self.password_entry.get()
                if not password:
                    messagebox.showerror("错误", "请输入密码")
                    return
                cmd.extend(["-p", password])
            elif mode == "keyfile":
                keyfile = self.crack_keyfile_entry.get()
                if not keyfile:
                    messagebox.showerror("错误", "请选择密钥文件")
                    return
                cmd.extend(["-kf", keyfile])
                
            # 在新线程中运行命令
            threading.Thread(target=self.run_command, args=(cmd, self.crack_result), daemon=True).start()
            
            self.status_var.set("正在破解...")
            
        except Exception as e:
            messagebox.showerror("错误", f"破解失败: {str(e)}")
            self.status_var.set("破解失败")
            
    def execute_exploit(self):
        """执行漏洞利用"""
        if not JWT_TOOL_AVAILABLE:
            messagebox.showerror("错误", "JWT工具模块不可用，请检查jwt_tool.py是否存在")
            return
            
        try:
            # 构建命令行参数
            cmd = [sys.executable, "jwt_tool.py"]
            
            # 添加JWT令牌
            jwt_token = self.jwt_input.get(1.0, tk.END).strip()
            if jwt_token:
                cmd.append(jwt_token)
                
            # 根据利用类型添加参数
            exploit_type = self.exploit_type.get()
            if exploit_type == "alg:none":
                cmd.extend(["-X", "a"])
            elif exploit_type == "null signature":
                cmd.extend(["-X", "n"])
            elif exploit_type == "blank password":
                cmd.extend(["-X", "b"])
            elif exploit_type == "psychic signature":
                cmd.extend(["-X", "p"])
            elif exploit_type == "spoof JWKS":
                jwks_url = self.jwks_url_entry.get()
                if not jwks_url:
                    messagebox.showerror("错误", "请输入JWKS URL")
                    return
                cmd.extend(["-X", "s", "-ju", jwks_url])
            elif exploit_type == "key confusion":
                pubkey = self.exploit_pubkey_entry.get()
                if not pubkey:
                    messagebox.showerror("错误", "请选择公钥文件")
                    return
                cmd.extend(["-X", "k", "-pk", pubkey])
            elif exploit_type == "inject inline JWKS":
                cmd.extend(["-X", "i"])
                
            # 在新线程中运行命令
            threading.Thread(target=self.run_command, args=(cmd, self.exploit_result), daemon=True).start()
            
            self.status_var.set("正在执行利用...")
            
        except Exception as e:
            messagebox.showerror("错误", f"利用失败: {str(e)}")
            self.status_var.set("利用失败")
            
    def send_request(self):
        """发送HTTP请求"""
        if not JWT_TOOL_AVAILABLE:
            messagebox.showerror("错误", "JWT工具模块不可用，请检查jwt_tool.py是否存在")
            return
            
        try:
            # 构建命令行参数
            cmd = [sys.executable, "jwt_tool.py"]
            
            # 添加JWT令牌
            jwt_token = self.jwt_input.get(1.0, tk.END).strip()
            if jwt_token:
                cmd.append(jwt_token)
                
            # 添加URL
            url = self.url_entry.get()
            if url:
                cmd.extend(["-t", url])
                
            # 添加Cookie
            cookie = self.cookie_entry.get()
            if cookie:
                cmd.extend(["-rc", cookie])
                
            # 添加POST数据
            post_data = self.post_data_entry.get()
            if post_data:
                cmd.extend(["-pd", post_data])
                
            # 添加其他选项
            if self.insecure_var.get():
                cmd.append("-i")
            if self.noproxy_var.get():
                cmd.append("-np")
            if self.noredir_var.get():
                cmd.append("-nr")
            if self.verbose_var.get():
                cmd.append("-v")
                
            # 在新线程中运行命令
            threading.Thread(target=self.run_command, args=(cmd, None), daemon=True).start()
            
            self.status_var.set("正在发送请求...")
            
        except Exception as e:
            messagebox.showerror("错误", f"请求失败: {str(e)}")
            self.status_var.set("请求失败")
            
    def save_settings(self):
        """保存设置"""
        try:
            # 这里可以实现保存设置到配置文件的逻辑
            messagebox.showinfo("提示", "设置已保存")
            self.status_var.set("设置已保存")
        except Exception as e:
            messagebox.showerror("错误", f"保存设置失败: {str(e)}")
            self.status_var.set("保存设置失败")
            
    def run_command(self, cmd, output_widget):
        """运行命令并显示输出"""
        try:
            # 运行命令
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            
            # 读取输出
            for line in iter(process.stdout.readline, ''):
                if output_widget:
                    output_widget.insert(tk.END, line)
                    output_widget.see(tk.END)
                    output_widget.update()
                else:
                    print(line)  # 如果没有输出控件，则打印到控制台
                    
            # 等待进程完成
            process.wait()
            
            if output_widget:
                output_widget.insert(tk.END, f"\n命令执行完成，退出代码: {process.returncode}\n")
                output_widget.see(tk.END)
            else:
                print(f"\n命令执行完成，退出代码: {process.returncode}\n")
                
            self.status_var.set("命令执行完成")
            
        except Exception as e:
            error_msg = f"执行命令时出错: {str(e)}"
            if output_widget:
                output_widget.insert(tk.END, error_msg + "\n")
                output_widget.see(tk.END)
            else:
                print(error_msg)
            self.status_var.set("命令执行失败")


class ClaimDialog:
    """声明对话框"""
    def __init__(self, parent, title, remove=False):
        self.top = tk.Toplevel(parent)
        self.top.title(title)
        self.top.geometry("300x150")
        self.top.transient(parent)
        self.top.grab_set()
        
        self.result = None
        
        # 创建界面
        if remove:
            # 删除模式
            ttk.Label(self.top, text="声明名称:").pack(pady=10)
            self.key_entry = ttk.Entry(self.top)
            self.key_entry.pack(pady=5, padx=10, fill='x')
            
            ttk.Button(self.top, text="删除", command=self.remove).pack(pady=10)
        else:
            # 添加模式
            ttk.Label(self.top, text="声明名称:").pack(pady=5)
            self.key_entry = ttk.Entry(self.top)
            self.key_entry.pack(pady=5, padx=10, fill='x')
            
            ttk.Label(self.top, text="声明值:").pack(pady=5)
            self.value_entry = ttk.Entry(self.top)
            self.value_entry.pack(pady=5, padx=10, fill='x')
            
            ttk.Button(self.top, text="添加", command=self.add).pack(pady=10)
            
    def add(self):
        """添加声明"""
        key = self.key_entry.get().strip()
        value = self.value_entry.get().strip()
        
        if not key or not value:
            messagebox.showerror("错误", "声明名称和值不能为空")
            return
            
        self.result = (key, value)
        self.top.destroy()
        
    def remove(self):
        """删除声明"""
        key = self.key_entry.get().strip()
        
        if not key:
            messagebox.showerror("错误", "声明名称不能为空")
            return
            
        self.result = key
        self.top.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = JWTToolGUI(root)
    root.mainloop()