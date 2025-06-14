import os
import sqlite3
import time
import subprocess
import threading
import logging
import re
import shutil
import socket
import psutil
from datetime import datetime
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from colorlog import ColoredFormatter

app = Flask(__name__)
CORS(app)
DATABASE = 'forward.db'
LOCK = threading.Lock()
START_TIME = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# 日志配置
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

def check_port_available(port, protocol='tcp'):
    proto = protocol.lower()
    with socket.socket(socket.AF_INET,
                       socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except OSError:
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
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                start_time DATETIME,
                pid INTEGER
            )
        ''')
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
                WHERE expire_minutes > 0 AND 
                datetime(start_time, '+' || expire_minutes || ' minutes') < datetime('now')
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
               status, expire_minutes, create_time, start_time, pid 
        FROM forwarding
    ''')

    data = []
    now_ts = datetime.now().timestamp()

    for row in cursor.fetchall():
        item = dict(zip([c[0] for c in cursor.description], row))
        expire_minutes = item['expire_minutes']
        start_time = item['start_time']
        remaining_minutes = 0

        if expire_minutes and start_time:
            try:
                start_ts = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S').timestamp()
                elapsed_minutes = int((now_ts - start_ts) / 60)
                remaining_minutes = max(0, expire_minutes - elapsed_minutes)
            except Exception:
                remaining_minutes = expire_minutes
        if expire_minutes == 0:
            remaining_minutes = 0

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

        protocol = data.get('protocol', 'tcp').lower()
        if protocol not in ('tcp', 'udp'):
            return jsonify({'code': 400, 'message': '协议仅支持TCP/UDP'}), 400

        with LOCK:
            if not check_port_available(source_port, protocol):
                return jsonify({'code': 400, 'message': f'源端口 {source_port} 已被占用'}), 400

            db = get_db()
            if db.execute('SELECT id FROM forwarding WHERE id=?', (data['id'],)).fetchone():
                return jsonify({'code': 400, 'message': 'ID已存在'}), 400

            pid = start_socat(source_port, data['destination'], dest_port, protocol)
            db.execute('''
                INSERT INTO forwarding 
                (id, source_port, destination, destination_port, protocol, 
                 status, expire_minutes, pid, start_time)
                VALUES (?,?,?,?,?,?,?,?,datetime('now'))
            ''', (
                data['id'], source_port, data['destination'], dest_port, protocol,
                'running', data.get('expire_minutes', 0), pid
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
    if not (entry := db.execute('''
        SELECT pid, source_port, destination, destination_port, protocol 
        FROM forwarding WHERE id=?
    ''', (fid,)).fetchone()):
        return jsonify({'code': 404, 'message': '规则不存在'}), 404

    pid, sport, dest, dport, proto = entry
    new_pid = None
    try:
        if status == 'running':
            if not check_port_available(sport, proto):
                return jsonify({'code': 400, 'message': f'源端口 {sport} 已被占用，无法启动'}), 400
            if pid:
                kill_process_tree(pid)
            new_pid = start_socat(sport, dest, dport, proto)
        elif pid:
            kill_process_tree(pid)

        db.execute('''
            UPDATE forwarding SET 
            status=?, pid=?, start_time=CASE WHEN ?='running' THEN datetime('now') ELSE start_time END
            WHERE id=?
        ''', (status, new_pid, status, fid))
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

    free_ports = []
    for port in range(5000, 5050):
        if port not in used_ports and check_port_available(port):
            free_ports.append(port)
        if len(free_ports) >= 50:
            break

    cpu_usage = psutil.cpu_percent(interval=0.5)
    mem_usage = psutil.virtual_memory().percent

    return jsonify({
        "code": 0,
        "data": {
            "total_forwardings": total_forwardings,
            "used_ports": used_ports,
            "sample_free_ports": free_ports,
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

if __name__ == '__main__':
    check_socat_installed()
    init_db()
    restore_forward_rules()
    threading.Thread(target=background_expiry_check, daemon=True).start()
    logging.info("服务已启动: http://0.0.0.0:2017")
    app.run(host='0.0.0.0', port=2017)