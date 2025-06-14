import sqlite3
import time
import subprocess
import threading
import logging
import re
import shutil
import socket
import psutil
import argparse
from datetime import datetime
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from colorlog import ColoredFormatter

app = Flask(__name__)
CORS(app)
DATABASE = 'forward.db'
LOCK = threading.Lock()
START_TIME = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# 默认端口范围
DEFAULT_PORT_RANGE = "1-65535"
ALLOWED_PORT_RANGE = None

# 默认 Flask 端口
DEFAULT_FLASK_PORT = 2017
FLASK_PORT = DEFAULT_FLASK_PORT

def setup_logger():
    formatter = ColoredFormatter(
        "%(log_color)s%(asctime)s [%(levelname)s] %(message)s",
        datefmt='%Y-%m-%d %H:%M:%S',
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        },
        style='%'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

setup_logger()

def check_socat_installed():
    if shutil.which("socat") is None:
        logging.critical("未找到 socat 命令，请先安装 socat 工具后再运行程序。")
        exit(1)

def is_valid_port(port):
    global ALLOWED_PORT_RANGE
    if not ALLOWED_PORT_RANGE:
        return False
    if not (1 <= port <= 65535):
        return False
    return ALLOWED_PORT_RANGE[0] <= port <= ALLOWED_PORT_RANGE[1]

def is_valid_flask_port(port):
    return 1 <= port <= 65535

def check_port_available(port, protocol='tcp', editing_id=None):
    if not is_valid_port(port):
        return False
    proto = protocol.lower()
    with socket.socket(socket.AF_INET,
                       socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except OSError:
            if editing_id:
                db = get_db()
                cursor = db.cursor()
                cursor.execute('SELECT source_port FROM forwarding WHERE id=?', (editing_id,))
                result = cursor.fetchone()
                if result and result[0] == port:
                    return True
            return False

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS forwarding (
                id TEXT PRIMARY KEY,
                source_port INTEGER,
                destination TEXT,
                destination_port INTEGER,
                protocol TEXT DEFAULT 'tcp',
                status TEXT CHECK(status IN ('running', 'stopped')),
                expire_minutes INTEGER,
                remaining_minutes INTEGER,  -- 新增字段，存储剩余时间
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                start_time DATETIME,
                pid INTEGER
            )
        ''')
        # 检查是否需要添加 remaining_minutes 字段
        cursor.execute("PRAGMA table_info(forwarding)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'remaining_minutes' not in columns:
            cursor.execute('ALTER TABLE forwarding ADD COLUMN remaining_minutes INTEGER')
            # 初始化现有规则的 remaining_minutes
            cursor.execute('UPDATE forwarding SET remaining_minutes = expire_minutes WHERE remaining_minutes IS NULL')
        db.commit()
        logging.info(f"数据库初始化完成, 启动时间: {START_TIME}")

def kill_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.kill()
        parent.kill()
    except psutil.NoSuchProcess:
        pass
    except Exception as e:
        logging.warning(f"递归杀死进程树失败: {e}")

def background_expiry_check():
    while True:
        time.sleep(60)
        with app.app_context():
            db = get_db()
            cursor = db.cursor()
            cursor.execute('''
                SELECT id, pid FROM forwarding 
                WHERE status='running' AND expire_minutes > 0 AND 
                datetime(start_time, '+' || remaining_minutes || ' minutes') < datetime('now')
            ''')
            for entry in cursor.fetchall():
                try:
                    if entry[1]:
                        kill_process_tree(entry[1])
                except Exception as e:
                    logging.warning(f"终止进程失败 PID={entry[1]}: {str(e)}")
                cursor.execute('DELETE FROM forwarding WHERE id=?', (entry[0],))
                logging.info(f"删除过期规则: ID={entry[0]}")
            db.commit()

def start_socat(source_port, destination, dest_port, protocol='tcp'):
    proto = protocol.lower()
    if proto == 'tcp':
        cmd = f"nohup socat TCP4-LISTEN:{source_port},reuseaddr,fork TCP4:{destination}:{dest_port} > /dev/null 2>&1 & echo $!"
    elif proto == 'udp':
        cmd = f"nohup socat -T 600 UDP4-LISTEN:{source_port},reuseaddr,fork UDP4:{destination}:{dest_port} > /dev/null 2>&1 & echo $!"
    else:
        raise ValueError("仅支持 TCP 和 UDP 协议")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        pid_str, err = proc.communicate()
        if proc.returncode not in [0, None]:
            raise RuntimeError(f"socat 启动失败: {err.strip()}")
        pid = int(pid_str.strip())
        logging.info(f"成功启动 {proto.upper()} 转发: PID={pid}")
        return pid
    except Exception as e:
        logging.error(f"{proto.upper()} 转发启动异常: {str(e)}")
        raise RuntimeError(f"{proto.upper()} 转发启动失败: {str(e)}")

@app.route('/api/forwardings', methods=['GET'])
def list_forwardings():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT id, source_port, destination, destination_port, protocol,
               status, expire_minutes, create_time, start_time, pid, remaining_minutes 
        FROM forwarding
    ''')
    data = []
    now_ts = datetime.now().timestamp()
    for row in cursor.fetchall():
        item = dict(zip([c[0] for c in cursor.description], row))
        expire_minutes = item['expire_minutes']
        remaining_minutes = item['remaining_minutes'] or 0
        if expire_minutes == 0:
            remaining_minutes = 0
        elif item['status'] == 'running' and item['start_time']:
            try:
                start_ts = datetime.strptime(item['start_time'], '%Y-%m-%d %H:%M:%S').timestamp()
                elapsed_minutes = int((now_ts - start_ts) / 60)
                remaining_minutes = max(0, remaining_minutes - elapsed_minutes)
            except Exception:
                pass
        item['remaining_minutes'] = remaining_minutes
        data.append(item)
    return jsonify({'code': 0, 'data': data})

def is_valid_id(rule_id):
    return isinstance(rule_id, str) and re.fullmatch(r'[\u4e00-\u9fa5\w-]+', rule_id)

@app.route('/api/forwardings', methods=['POST'])
def add_forwarding():
    try:
        data = request.get_json(force=True, silent=True) or {}
        required = ['id', 'source_port', 'destination', 'destination_port']
        if missing := [p for p in required if p not in data]:
            return jsonify({'code': 400, 'message': f"缺少参数: {','.join(missing)}"}), 400
        if not is_valid_id(data['id']):
            return jsonify({'code': 400, 'message': 'ID需为中文、英文、数字、_或-'}), 400
        try:
            source_port = int(data['source_port'])
            dest_port = int(data['destination_port'])
        except ValueError:
            return jsonify({'code': 400, 'message': '端口必须为整数'}), 400
        if not is_valid_port(source_port) or not is_valid_port(dest_port):
            return jsonify({'code': 400, 'message': f'端口必须在允许的范围内: {ALLOWED_PORT_RANGE[0]}-{ALLOWED_PORT_RANGE[1]}'}), 400
        protocol = data.get('protocol', 'tcp').lower()
        if protocol not in ('tcp', 'udp'):
            return jsonify({'code': 400, 'message': '协议仅支持TCP/UDP'}), 400
        editing_id = data.get('editing_id')
        with LOCK:
            if not check_port_available(source_port, protocol, editing_id):
                return jsonify({'code': 400, 'message': f'源端口 {source_port} 已被占用或不在可用范围内'}), 400
            db = get_db()
            if db.execute('SELECT id FROM forwarding WHERE id=?', (data['id'],)).fetchone():
                return jsonify({'code': 400, 'message': 'ID已存在'}), 400
            pid = start_socat(source_port, data['destination'], dest_port, protocol)
            expire_minutes = data.get('expire_minutes', 0)
            db.execute('''
                INSERT INTO forwarding 
                (id, source_port, destination, destination_port, protocol, 
                 status, expire_minutes, remaining_minutes, pid, start_time)
                VALUES (?,?,?,?,?,?,?, ?,?,datetime('now'))
            ''', (
                data['id'], source_port, data['destination'], dest_port, protocol,
                'running', expire_minutes, expire_minutes, pid
            ))
            db.commit()
            return jsonify({'code': 0})
    except Exception as e:
        logging.error(f"服务器内部错误: {str(e)}")
        return jsonify({'code': 500, 'message': '服务器处理错误'}), 500

@app.route('/api/forwardings/<string:fid>', methods=['DELETE'])
def delete_forwarding(fid):
    db = get_db()
    if entry := db.execute('SELECT pid, status FROM forwarding WHERE id=?', (fid,)).fetchone():
        pid, status = entry
        if status == 'running' and pid:
            kill_process_tree(pid)
        db.execute('DELETE FROM forwarding WHERE id=?', (fid,))
        db.commit()
        return jsonify({'code': 0})
    return jsonify({'code': 404, 'message': '规则不存在'}), 404

@app.route('/api/forwardings/<string:fid>/start', methods=['POST'])
def start_forward(fid):
    return update_forward_status(fid, 'running')

@app.route('/api/forwardings/<string:fid>/stop', methods=['POST'])
def stop_forward(fid):
    return update_forward_status(fid, 'stopped')

def update_forward_status(fid, status):
    db = get_db()
    cursor = db.execute('''
        SELECT pid, source_port, destination, destination_port, protocol, 
               start_time, expire_minutes, remaining_minutes
        FROM forwarding WHERE id=?
    ''', (fid,))
    if not (entry := cursor.fetchone()):
        return jsonify({'code': 404, 'message': '规则不存在'}), 404
    pid, sport, dest, dport, proto, start_time, expire_minutes, remaining_minutes = entry
    new_pid = None
    try:
        if status == 'running':
            if not check_port_available(sport, proto, fid):
                return jsonify({'code': 400, 'message': f'源端口 {sport} 已被占用或不在可用范围内，无法启动'}), 400
            if pid:
                kill_process_tree(pid)
            new_pid = start_socat(sport, dest, dport, proto)
            # 使用保存的 remaining_minutes
            db.execute('''
                UPDATE forwarding SET 
                status=?, pid=?, start_time=datetime('now')
                WHERE id=?
            ''', (status, new_pid, fid))
        else:  # stopped
            if pid:
                kill_process_tree(pid)
            # 计算并保存剩余时间
            if expire_minutes > 0 and start_time:
                try:
                    start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
                    elapsed_minutes = int((datetime.now() - start_dt).total_seconds() / 60)
                    remaining_minutes = max(0, (remaining_minutes or expire_minutes) - elapsed_minutes)
                except Exception:
                    remaining_minutes = remaining_minutes or expire_minutes
            else:
                remaining_minutes = expire_minutes
            db.execute('''
                UPDATE forwarding SET 
                status=?, pid=NULL, remaining_minutes=?
                WHERE id=?
            ''', (status, remaining_minutes, fid))
        db.commit()
        return jsonify({'code': 0})
    except Exception as e:
        db.rollback()
        logging.error(f"状态变更失败: {str(e)}")
        return jsonify({'code': 500, 'message': '状态更新失败'}), 500

@app.route('/api/system', methods=['GET'])
def system_info():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM forwarding")
    total_forwardings = cursor.fetchone()[0]
    used_ports = [row[0] for row in db.execute("SELECT source_port FROM forwarding").fetchall()]
    available_ports = []
    global ALLOWED_PORT_RANGE
    if ALLOWED_PORT_RANGE:
        for port in range(ALLOWED_PORT_RANGE[0], ALLOWED_PORT_RANGE[1] + 1):
            if port not in used_ports and check_port_available(port):
                available_ports.append(port)
    cpu_usage = psutil.cpu_percent(interval=0.5)
    mem_usage = psutil.virtual_memory().percent
    return jsonify({
        "code": 0,
        "data": {
            "total_forwardings": total_forwardings,
            "used_ports": used_ports,
            "available_ports": available_ports,
            "cpu_usage": cpu_usage,
            "mem_usage": mem_usage
        }
    })

def restore_forward_rules():
    logging.info("恢复已有规则...")
    with app.app_context():
        db = get_db()
        for fid, sport, dest, dport, proto in db.execute('''
            SELECT id, source_port, destination, destination_port, protocol 
            FROM forwarding WHERE status='running'
        ''').fetchall():
            try:
                pid = start_socat(sport, dest, dport, proto)
                db.execute('UPDATE forwarding SET pid=?, start_time=datetime("now") WHERE id=?', (pid, fid))
                logging.info(f"规则恢复成功: ID={fid}")
            except Exception as e:
                logging.error(f"规则恢复失败: ID={fid} error={str(e)}")
                db.execute('UPDATE forwarding SET status="stopped", pid=NULL WHERE id=?', (fid,))
        db.commit()

def parse_port_range(port_range_str):
    try:
        start, end = map(int, port_range_str.split('-'))
        if start >= end:
            raise ValueError("起始端口必须小于结束端口")
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError("端口号必须在1到65535之间")
        return (start, end)
    except ValueError as e:
        print(f"无效端口范围: {port_range_str} - {e}")
        exit(1)

if __name__ == '__main__':
    check_socat_installed()
    parser = argparse.ArgumentParser(description='端口转发工具')
    parser.add_argument('--port-range', type=str, default=DEFAULT_PORT_RANGE,
                        help=f'允许使用的端口范围，格式为 "起始端口-结束端口"，例如 "1-65535"。 默认"{DEFAULT_PORT_RANGE}"')
    parser.add_argument('--port', type=int, default=DEFAULT_FLASK_PORT,
                        help=f'Flask 应用监听的端口。 默认: {DEFAULT_FLASK_PORT}')
    args = parser.parse_args()
    ALLOWED_PORT_RANGE = parse_port_range(args.port_range)
    if not is_valid_flask_port(args.port):
        print(f"无效的 Flask 端口: {args.port}. 端口号必须在1到65535之间")
        exit(1)
    FLASK_PORT = args.port
    init_db()
    restore_forward_rules()
    threading.Thread(target=background_expiry_check, daemon=True).start()
    logging.info(f"服务已启动: http://0.0.0.0:{FLASK_PORT}, 端口范围: {ALLOWED_PORT_RANGE[0]}-{ALLOWED_PORT_RANGE[1]}")
    app.run(host='0.0.0.0', port=FLASK_PORT)
