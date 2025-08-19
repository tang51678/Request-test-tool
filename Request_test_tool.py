import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from requests.exceptions import RequestException
import re
import urllib.parse
import threading
import time
import json
import difflib
from datetime import datetime
import uuid
import os
import pickle
from collections import deque
import logging

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class HTTPRequestTester:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP/S 请求测试工具")
        self.root.geometry("1000x750")
        self.root.configure(bg='#f5f5f5')
        
        # 状态变量
        self.is_running = False
        self.request_queue = deque(maxlen=20)  # 存储最近20次请求
        self.request_history = []
        self.change_points = []
        
        # 创建标签页
        self.tab_control = ttk.Notebook(root)
        
        # 导入请求标签页
        self.tab1 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab1, text='导入请求')
        
        # 配置请求标签页
        self.tab2 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab2, text='请求配置')
        
        # 结果监控标签页
        self.tab3 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab3, text='结果监控')
        
        self.tab_control.pack(expand=1, fill="both", padx=15, pady=15)
        
        # 构建UI
        self.setup_import_tab()
        self.setup_config_tab()
        self.setup_monitor_tab()
        
        # 保存历史记录的目录
        if not os.path.exists("history"):
            os.makedirs("history")
        
    def setup_import_tab(self):
        """设置导入标签页UI"""
        frame = ttk.LabelFrame(self.tab1, text="导入HTTP请求数据包")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10, ipadx=10, ipady=10)
        
        tk.Label(frame, text="粘贴原始请求数据:", font=('Arial', 10)).pack(pady=(5, 0), anchor='nw')
        
        # 原始请求输入框
        self.raw_request_text = scrolledtext.ScrolledText(
            frame, height=18, width=110, font=('Consolas', 10), wrap=tk.WORD
        )
        self.raw_request_text.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        
        # 示例按钮
        tk.Button(frame, text="加载示例请求", command=self.load_example, 
                  bg='#4CAF50', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # 解析按钮
        tk.Button(frame, text="解析请求", command=self.parse_request, 
                  bg='#2196F3', fg='white', font=('Arial', 10)).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # 状态信息
        self.parse_status = ttk.Label(frame, text="准备解析...", foreground="gray")
        self.parse_status.pack(pady=(0, 5), anchor='e')
    
    def setup_config_tab(self):
        """设置配置标签页UI"""
        main_frame = ttk.Frame(self.tab2)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # URL 框架
        url_frame = ttk.LabelFrame(main_frame, text="URL")
        url_frame.pack(fill=tk.X, padx=5, pady=5, ipadx=5, ipady=5)
        
        self.protocol_var = tk.StringVar(value="https")
        ttk.Label(url_frame, text="协议:").pack(side=tk.LEFT, padx=(10, 0), pady=5)
        ttk.Combobox(url_frame, textvariable=self.protocol_var, width=6, 
                    values=["http", "https"], state="readonly").pack(side=tk.LEFT, padx=5)
        
        ttk.Label(url_frame, text="URL路径和查询参数:").pack(side=tk.LEFT, padx=(10, 0), pady=5)
        self.url_entry = ttk.Entry(url_frame, width=80)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        # 请求头表格
        headers_frame = ttk.LabelFrame(main_frame, text="请求头")
        headers_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        # 表头
        columns = ("name", "value")
        self.headers_tree = ttk.Treeview(headers_frame, columns=columns, show="headings", height=8)
        
        self.headers_tree.heading("name", text="头部名称")
        self.headers_tree.heading("value", text="头部值")
        self.headers_tree.column("name", width=200, anchor="w")
        self.headers_tree.column("value", width=650, anchor="w")
        
        self.headers_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 头部操作按钮
        btn_frame = ttk.Frame(headers_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(btn_frame, text="添加头部", command=self.add_header, 
                  bg='#2196F3', fg='white', font=('Arial', 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(btn_frame, text="编辑头部", command=self.edit_header, 
                  bg='#4CAF50', fg='white', font=('Arial', 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(btn_frame, text="删除头部", command=self.remove_header, 
                  bg='#f44336', fg='white', font=('Arial', 9)).pack(side=tk.LEFT, padx=2)
        
        # 主体内容
        body_frame = ttk.LabelFrame(main_frame, text="请求体")
        body_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        self.body_text = scrolledtext.ScrolledText(
            body_frame, height=8, font=('Consolas', 10), wrap=tk.WORD)
        self.body_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 状态指示
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="就绪", foreground="green")
        self.status_label.pack(side=tk.LEFT)
        
        # 测试控制按钮
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=10)
        
        tk.Button(control_frame, text="单次测试", command=self.run_single_test, 
                  bg='#2196F3', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="开始定时测试", command=self.start_interval_test, 
                  bg='#4CAF50', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="停止测试", command=self.stop_interval_test, 
                  bg='#f44336', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        # 间隔时间设置
        interval_frame = ttk.Frame(control_frame)
        interval_frame.pack(side=tk.RIGHT, padx=10)
        
        ttk.Label(interval_frame, text="间隔秒数:").pack(side=tk.LEFT)
        self.interval_var = tk.StringVar(value="10")
        interval_spin = ttk.Spinbox(interval_frame, from_=1, to=600, textvariable=self.interval_var, width=5)
        interval_spin.pack(side=tk.LEFT, padx=5)
    
    def setup_monitor_tab(self):
        """设置结果监控标签页UI"""
        main_frame = ttk.Frame(self.tab3)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 请求历史表格
        history_frame = ttk.LabelFrame(main_frame, text="请求历史")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        columns = ("timestamp", "status", "length", "time", "difference")
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show="headings", height=15)
        
        self.history_tree.heading("timestamp", text="时间戳")
        self.history_tree.heading("status", text="状态")
        self.history_tree.heading("length", text="内容长度")
        self.history_tree.heading("time", text="响应时间(ms)")
        self.history_tree.heading("difference", text="内容差异")
        
        self.history_tree.column("timestamp", width=150)
        self.history_tree.column("status", width=80, anchor="center")
        self.history_tree.column("length", width=100, anchor="center")
        self.history_tree.column("time", width=120, anchor="center")
        self.history_tree.column("difference", width=120, anchor="center")
        
        vsb = ttk.Scrollbar(history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=vsb.set)
        
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定双击事件查看详情
        self.history_tree.bind("<Double-1>", self.show_response_detail)
        
        # 响应详情
        detail_frame = ttk.LabelFrame(main_frame, text="响应详情")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, height=10, font=('Consolas', 9), wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.detail_text.config(state=tk.DISABLED)  # 初始状态不可编辑
        
        # 特殊标记区域
        marker_frame = ttk.LabelFrame(main_frame, text="变化点记录")
        marker_frame.pack(fill=tk.BOTH, padx=5, pady=5, ipadx=5, ipady=5)
        
        self.marker_text = tk.Text(marker_frame, height=4, font=('Arial', 9))
        self.marker_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.marker_text.config(state=tk.DISABLED)  # 初始状态不可编辑
        
        # 操作按钮
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="保存结果历史", command=self.save_history, 
                 bg='#2196F3', fg='white').pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame, text="清除历史", command=self.clear_history,
                 bg='#f44336', fg='white').pack(side=tk.RIGHT, padx=10)
    
    def load_example(self):
        """加载示例HTTP请求"""
        example = """POST /bomc_workorder/api/portal/home/getCommonUrlList?type=3&uat=d89c11257b1545ec9455e76c50bde2ed&appcode=h5&rnd=25020948.55370449&ts=1755571682463&sig=13d6c8fdc94af99676fb5bdfc5b878e861089006 HTTP/1.1
Host: app.cqmc.com:441
Content-Length: 2
Pragma: no-cache
Cache-Control: no-cache
Accept-Language: zh-CN,zh;q=0.9
Accept: application/json, text/plain, */*
Content-Type: application/json
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1
Origin: https://app.cqmc.com:441
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://app.cqmc.com:441/bomc_workorder/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

{}"""
        self.raw_request_text.delete(1.0, tk.END)
        self.raw_request_text.insert(tk.END, example)
        self.parse_status.config(text="示例加载完成!", foreground="green")
    
    def parse_request(self):
        """解析原始HTTP请求字符串"""
        raw_text = self.raw_request_text.get(1.0, tk.END).strip()
        if not raw_text:
            self.parse_status.config(text="请输入HTTP请求数据!", foreground="red")
            return
        
        try:
            # 将文本分割为行
            lines = [line.strip() for line in raw_text.split('\n') if line.strip()]
            
            # 解析请求行
            if not lines:
                raise ValueError("请求数据为空")
                
            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 3:
                raise ValueError("请求行格式错误")
                
            method, full_path, http_version = parts[0], parts[1], ' '.join(parts[2:])
            
            # 尝试从请求行中提取主机信息
            host_from_url = None
            if '://' in full_path:
                try:
                    parsed_url = urllib.parse.urlparse(full_path)
                    host_from_url = parsed_url.netloc
                    full_path = parsed_url.path
                    if parsed_url.query:
                        full_path += '?' + parsed_url.query
                except Exception as e:
                    logging.warning(f"解析URL失败: {str(e)}")
            
            # 提取主机和端口信息
            host_value = None
            port = None
            
            # 从头部查找Host
            for i in range(1, len(lines)):
                line = lines[i]
                if ':' in line:
                    key, value = [part.strip() for part in line.split(':', 1)]
                    if key.lower() == 'host':
                        host_value = value
                        break
            
            # 优先使用Host头，其次使用URL中的主机信息
            if host_value:
                host_value = host_value.split(']')[0]  # 处理IPv6地址
                if ':' in host_value:
                    host, port_str = host_value.split(':', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = None
                else:
                    host = host_value
            elif host_from_url:
                host = host_from_url
                if ':' in host:
                    host, port_str = host.split(':', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = None
            else:
                raise ValueError("未找到Host信息")
            
            # 设置协议
            if port == 443:
                self.protocol_var.set("https")
            elif port == 80:
                self.protocol_var.set("http")
            elif not port:
                # 根据上下文推断协议
                self.protocol_var.set("https" if ":443" in raw_text else "http")
            
            # 填充UI字段
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, full_path)
            
            # 解析头部
            self.headers_tree.delete(*self.headers_tree.get_children())
            headers = {}
            body_lines = []
            in_body = False
            
            for i in range(1, len(lines)):
                line = lines[i]
                if not line:  # 空行标识头部结束
                    in_body = True
                    continue
                    
                if in_body:
                    body_lines.append(line)
                    continue
                    
                if ':' in line:
                    key, value = [part.strip() for part in line.split(':', 1)]
                    # 忽略自动计算的头部
                    if key.lower() not in ["content-length", "host"]:
                        headers[key] = value
                        self.headers_tree.insert("", tk.END, values=(key, value))
            
            # 解析主体
            body = '\n'.join(body_lines).strip()
            self.body_text.delete(1.0, tk.END)
            self.body_text.insert(tk.END, body)
            
            # 添加/更新Host头
            if host_value:
                self.update_or_add_header('Host', host_value)
            elif host:
                host_display = f"{host}:{port}" if port else host
                self.update_or_add_header('Host', host_display)
            
            self.parse_status.config(text="解析成功!", foreground="green")
            
        except Exception as e:
            self.parse_status.config(text=f"解析错误: {str(e)}", foreground="red")
            logging.error(f"解析请求失败: {str(e)}")
    
    def update_or_add_header(self, key, value):
        """更新或添加请求头"""
        # 查找是否已存在该头部
        for item in self.headers_tree.get_children():
            k, _ = self.headers_tree.item(item, 'values')
            if k.lower() == key.lower():
                self.headers_tree.item(item, values=(key, value))
                return
        # 不存在则添加
        self.headers_tree.insert("", tk.END, values=(key, value))
    
    def add_header(self):
        """添加新的请求头"""
        result = self.show_header_dialog("添加头部", "", "")
        if result:
            key, value = result
            self.headers_tree.insert("", tk.END, values=(key, value))
    
    def edit_header(self):
        """编辑选中的请求头"""
        selected = self.headers_tree.selection()
        if not selected:
            return
            
        item = self.headers_tree.item(selected[0])
        key, value = item['values']
        
        result = self.show_header_dialog("编辑头部", key, value)
        if result:
            new_key, new_value = result
            self.headers_tree.item(selected[0], values=(new_key, new_value))
    
    def remove_header(self):
        """移除选中的请求头"""
        selected = self.headers_tree.selection()
        if selected:
            self.headers_tree.delete(selected[0])
    
    def show_header_dialog(self, title, key, value):
        """显示添加/编辑头部的对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="头部名称:", font=('Arial', 10)).place(x=20, y=30)
        key_entry = ttk.Entry(dialog, width=40)
        key_entry.place(x=120, y=30)
        key_entry.insert(0, key)
        
        tk.Label(dialog, text="头部值:", font=('Arial', 10)).place(x=20, y=80)
        value_entry = ttk.Entry(dialog, width=40)
        value_entry.place(x=120, y=80)
        value_entry.insert(0, value)
        
        result = None
        
        def save():
            nonlocal result
            k = key_entry.get().strip()
            v = value_entry.get().strip()
            if k:
                result = (k, v)
                dialog.destroy()
            else:
                messagebox.showerror("错误", "头部名称不能为空")
        
        tk.Button(dialog, text="确定", command=save, width=10).place(x=120, y=130)
        tk.Button(dialog, text="取消", command=dialog.destroy, width=10).place(x=220, y=130)
        
        dialog.wait_window()
        return result
    
    def get_headers(self):
        """从树形控件中获取所有头部"""
        headers = {}
        for item in self.headers_tree.get_children():
            k, v = self.headers_tree.item(item, 'values')
            headers[k] = v
        return headers
    
    def build_full_url(self):
        """构建完整的请求URL"""
        protocol = self.protocol_var.get()
        path_query = self.url_entry.get().strip()
        if not path_query:
            messagebox.showerror("错误", "URL路径不能为空")
            return None
        
        # 从树形控件中找到Host头
        host_value = None
        for item in self.headers_tree.get_children():
            k, v = self.headers_tree.item(item, 'values')
            if k.lower() == 'host':
                host_value = v
                break
        
        if host_value is None:
            messagebox.showerror("错误", "缺少Host头部信息")
            return None
        
        # 处理IPv6地址
        if host_value.startswith('[') and ']' in host_value:
            # IPv6地址格式 [::1]:8080
            host, port_part = host_value.split(']', 1)
            host = host[1:]  # 移除开头的[
            if port_part.startswith(':'):
                port = port_part[1:]
            else:
                port = None
        elif ':' in host_value:
            host, port = host_value.split(':', 1)
        else:
            host = host_value
            port = None
        
        # 验证端口
        if port:
            try:
                port = int(port)
            except ValueError:
                messagebox.showerror("错误", f"无效的端口号: {port}")
                return None
            
            # 检查端口是否与协议匹配
            if (protocol == 'https' and port == 80) or (protocol == 'http' and port == 443):
                if not messagebox.askyesno("端口警告", 
                                          f"协议{protocol}通常使用端口{443 if protocol=='https' else 80}, "
                                          f"但当前端口为{port}。是否继续？"):
                    return None
        
        # 构建URL
        if port:
            url = f"{protocol}://{host}:{port}{path_query}"
        else:
            url = f"{protocol}://{host}{path_query}"
            
        return url
    
    def run_request(self):
        """执行HTTP请求并返回结果"""
        url = self.build_full_url()
        if not url:
            return None
            
        method = "POST" if self.body_text.get("1.0", tk.END).strip() else "GET"
        headers = self.get_headers()
        body = self.body_text.get("1.0", tk.END).strip()
        
        # 自动设置Content-Length
        content_length = str(len(body))
        if body:
            headers['Content-Length'] = content_length
        else:
            if 'Content-Length' in headers:
                del headers['Content-Length']
        
        try:
            start_time = time.perf_counter()
            
            # 禁用SSL警告
            requests.packages.urllib3.disable_warnings()
            
            if method == "POST":
                # 根据Content-Type决定如何发送数据
                content_type = headers.get('Content-Type', '').lower()
                if 'json' in content_type:
                    try:
                        json_data = json.loads(body) if body else None
                        response = requests.post(url, json=json_data, headers=headers, verify=False)
                    except json.JSONDecodeError:
                        response = requests.post(url, data=body, headers=headers, verify=False)
                else:
                    response = requests.post(url, data=body, headers=headers, verify=False)
            else:
                response = requests.get(url, headers=headers, verify=False)
            
            response_time = int((time.perf_counter() - start_time) * 1000)  # ms
            
            # 尝试解码JSON响应
            content = response.text
            try:
                response_data = response.json()
                formatted_content = json.dumps(response_data, indent=2, ensure_ascii=False)
            except:
                formatted_content = content[:500] + "..." if len(content) > 500 else content
            
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(content),
                'content': content,
                'formatted_content': formatted_content,
                'response_time': response_time,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            return result
            
        except RequestException as e:
            messagebox.showerror("请求错误", f"请求失败: {str(e)}")
            logging.error(f"请求失败: {str(e)}")
            return None
    
    def run_single_test(self):
        """执行单次测试"""
        result = self.run_request()
        if result:
            self.process_result(result)
            # 显示响应详情
            self.clear_detail_text()
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(tk.END, f"状态码: {result['status']}\n")
            self.detail_text.insert(tk.END, f"响应时间: {result['response_time']} ms\n")
            self.detail_text.insert(tk.END, f"内容长度: {result['content_length']} 字节\n")
            self.detail_text.insert(tk.END, f"时间戳: {result['timestamp']}\n\n")
            if result['status'] != 200:
                self.detail_text.insert(tk.END, f"错误: {result['content']}")
            else:
                self.detail_text.insert(tk.END, result['formatted_content'])
            self.detail_text.config(state=tk.DISABLED)
    
    def process_result(self, result):
        """处理请求结果，检测内容变化"""
        # 添加到历史记录
        self.request_queue.append(result)
        self.request_history.append(result)
        
        # 检测内容变化
        diff_percentage = 0.0
        changes = "未变化"
        
        if len(self.request_queue) > 1:
            prev_content = self.request_queue[-2]['content']
            curr_content = result['content']
            
            # 计算变化率
            diff = difflib.SequenceMatcher(None, prev_content, curr_content).ratio()
            diff_percentage = int((1 - diff) * 100)
            
            # 检测鉴权值失效
            if diff_percentage > 10:  # 假设内容变化超过10%说明有重大变化
                changes = f"变化 {diff_percentage}%"
                # 记录变化点
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.change_points.append({
                    'timestamp': timestamp,
                    'status': result['status'],
                    'diff': diff_percentage,
                    'old_length': self.request_queue[-2]['content_length'],
                    'new_length': result['content_length']
                })
                self.update_marker_text()
            else:
                changes = f"变化 {diff_percentage}%"
        
        # 更新历史记录
        row = (
            result['timestamp'],
            result['status'],
            result['content_length'],
            result['response_time'],
            changes
        )
        tag = "red" if result['status'] != 200 else "green" if diff_percentage > 0 else ""
        
        self.history_tree.insert("", tk.END, values=row, tags=(tag,))
        
        # 自动滚动到最新记录
        self.history_tree.yview_moveto(1.0)
    
    def update_marker_text(self):
        """更新变化点文本框"""
        self.marker_text.config(state=tk.NORMAL)
        self.marker_text.delete(1.0, tk.END)
        
        if not self.change_points:
            self.marker_text.insert(tk.END, "尚无变化记录")
        else:
            self.marker_text.insert(tk.END, "检测到响应内容重大变化的时间点:\n\n")
            for point in self.change_points:
                self.marker_text.insert(
                    tk.END, 
                    f"{point['timestamp']} - 状态: {point['status']}, "
                    f"变化率: {point['diff']}%, "
                    f"前长度: {point['old_length']}, 现长度: {point['new_length']}\n"
                )
        
        self.marker_text.config(state=tk.DISABLED)
    
    def start_interval_test(self):
        """启动定时测试"""
        if self.is_running:
            return
            
        try:
            interval = int(self.interval_var.get())
            if interval < 1:
                raise ValueError("间隔时间太短")
        except:
            messagebox.showerror("错误", "请输入1-600之间的整数")
            return
        
        self.is_running = True
        self.status_label.config(text=f"定时测试中 ({interval}秒/次)", foreground="blue")
        
        # 在新线程中运行定时测试
        self.interval_thread = threading.Thread(
            target=self.run_interval_test, 
            args=(interval,),
            daemon=True
        )
        self.interval_thread.start()
    
    def run_interval_test(self, interval):
        """定时测试主循环"""
        while self.is_running:
            result = self.run_request()
            if result:
                self.root.after(0, self.process_result, result)
            
            # 等待指定时间，但允许随时中断
            for _ in range(interval * 10):
                if not self.is_running:
                    return
                time.sleep(0.1)
    
    def stop_interval_test(self):
        """停止定时测试"""
        self.is_running = False
        self.status_label.config(text="测试已停止", foreground="green")
    
    def show_response_detail(self, event):
        """双击显示响应详情"""
        item = self.history_tree.selection()
        if not item:
            return
            
        item = item[0]
        index = int(self.history_tree.index(item))
        
        if index < 0 or index >= len(self.request_history):
            return
        
        result = self.request_history[index]
        
        self.clear_detail_text()
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.insert(tk.END, f"时间: {result['timestamp']}\n")
        self.detail_text.insert(tk.END, f"状态码: {result['status']}\n")
        self.detail_text.insert(tk.END, f"响应时间: {result['response_time']} ms\n")
        self.detail_text.insert(tk.END, f"内容长度: {result['content_length']} 字节\n\n")
        
        self.detail_text.insert(tk.END, "==== 响应头 ====\n")
        for key, value in result['headers'].items():
            self.detail_text.insert(tk.END, f"{key}: {value}\n")
        
        self.detail_text.insert(tk.END, "\n==== 响应体 ====\n")
        self.detail_text.insert(tk.END, result['formatted_content'])
        self.detail_text.config(state=tk.DISABLED)
    
    def clear_detail_text(self):
        """清空详情文本框"""
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.config(state=tk.DISABLED)
    
    def save_history(self):
        """保存历史记录到文件"""
        if not self.request_history:
            messagebox.showinfo("保存", "历史记录为空!")
            return
            
        filename = f"history/request_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
        try:
            with open(filename, 'wb') as f:
                pickle.dump(self.request_history, f)
            messagebox.showinfo("成功", f"已保存历史记录到 {filename}")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")
            logging.error(f"保存历史记录失败: {str(e)}")
    
    def clear_history(self):
        """清除历史记录"""
        if messagebox.askyesno("确认", "确定要清除所有历史记录吗?"):
            self.history_tree.delete(*self.history_tree.get_children())
            self.request_history = []
            self.request_queue.clear()
            self.change_points = []
            self.clear_detail_text()
            self.marker_text.config(state=tk.NORMAL)
            self.marker_text.delete(1.0, tk.END)
            self.marker_text.config(state=tk.DISABLED)
            self.status_label.config(text="历史记录已清除", foreground="green")

if __name__ == "__main__":
    root = tk.Tk()
    app = HTTPRequestTester(root)
    root.mainloop()