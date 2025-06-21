import sqlite3
import time
import subprocess
import threading
import logging
from logging.handlers import TimedRotatingFileHandler
import re
import shutil
import socket
import psutil
import argparse
import os
import signal
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

# 日志文件配置
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "forward.log")
LOG_RETENTION_DAYS = 30

def setup_logger():
    # 确保日志目录存在
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    # 创建格式化器
    console_formatter = ColoredFormatter(
        "%(log_color)s%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
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
    
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(process)d:%(threadName)s] [%(client_ip)s] [%(operation)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    
    # 文件处理器 - 每天轮换，保留30天
    file_handler = TimedRotatingFileHandler(
        LOG_FILE, when='midnight', interval=1, backupCount=LOG_RETENTION_DAYS
    )
    file_handler.setFormatter(file_formatter)
    
    # 获取根日志记录器
    logger = logging.getLogger()
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)
    
    # 添加操作日志过滤器
    class OperationLogFilter(logging.Filter):
        def filter(self, record):
            # 安全地获取客户端IP
            try:
                # 尝试获取请求上下文中的remote_addr
                record.client_ip = request.remote_addr
            except RuntimeError:
                # 如果不在请求上下文中，使用'system'
                record.client_ip = 'system'
            
            # 从日志消息中提取操作类型
            if hasattr(record, 'msg'):
                if record.msg.startswith('CREATE:'):
                    record.operation = 'CREATE'
                elif record.msg.startswith('UPDATE:'):
                    record.operation = 'UPDATE'
                elif record.msg.startswith('DELETE:'):
                    record.operation = 'DELETE'
                elif record.msg.startswith('START:'):
                    record.operation = 'START'
                elif record.msg.startswith('STOP:'):
                    record.operation = 'STOP'
                else:
                    record.operation = 'SYSTEM'
            else:
                record.operation = 'SYSTEM'
            return True
    
    file_handler.addFilter(OperationLogFilter())

setup_logger()

def log_operation(action, details, success=True, error=None):
    """记录操作日志的辅助函数"""
    status = "SUCCESS" if success else "FAILED"
    message = f"{action}: {details} | Status: {status}"
    if error:
        message += f" | Error: {str(error)}"
    logging.info(message)

def check_socat_installed():
    if shutil.which("socat") is None:
        log_operation("SYSTEM", "未找到socat命令", success=False)
        logging.critical("未找到 socat 命令，请先安装 socat 工具后再运行程序。")
        exit(1)

def is_valid_port(port, is_source_port=True):
    global ALLOWED_PORT_RANGE
    if not (1 <= port <= 65535):
        return False
    if is_source_port and ALLOWED_PORT_RANGE:
        return ALLOWED_PORT_RANGE[0] <= port <= ALLOWED_PORT_RANGE[1]
    return True

def is_valid_flask_port(port):
    return 1 <= port <= 65535

def check_port_available(port, protocol='tcp', editing_id=None):
    if not is_valid_port(port, is_source_port=True):
        return False
    proto = protocol.lower()
    with socket.socket(socket.AF_INET,
                      socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM) as s:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
            remaining_minutes INTEGER,
            create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            start_time DATETIME,
            pid INTEGER
        )
        ''')
        cursor.execute("PRAGMA table_info(forwarding)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'remaining_minutes' not in columns:
            cursor.execute('ALTER TABLE forwarding ADD COLUMN remaining_minutes INTEGER')
            cursor.execute('UPDATE forwarding SET remaining_minutes = expire_minutes WHERE remaining_minutes IS NULL')
        db.commit()
        logging.info(f"数据库初始化完成, 启动时间: {START_TIME}")

def kill_process_tree(pid):
    try:
        # 首先尝试使用pkill杀死所有相关的socat进程
        subprocess.run(f"pkill -9 -P {pid} 2>/dev/null", shell=True)
        subprocess.run(f"kill -9 {pid} 2>/dev/null", shell=True)
        
        # 然后使用psutil确保进程被终止
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            parent.kill()
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            logging.warning(f"递归杀死进程树失败: {e}")
    except Exception as e:
        logging.warning(f"终止进程失败 PID={pid}: {str(e)}")

def kill_processes_on_port(port, protocol='tcp'):
    """杀死占用指定端口的所有进程，返回终止的进程数"""
    try:
        cmd = f"lsof -i :{port} | awk '{{print $2}}' | tail -n +2 | sort | uniq"
        pids = subprocess.check_output(cmd, shell=True, text=True).split()
        if not pids:
            return 0
            
        logging.warning(f"发现占用端口 {port} 的进程: {','.join(pids)}，正在终止...")
        terminated_count = 0
        for pid_str in set(pids):
            try:
                pid = int(pid_str)
                kill_process_tree(pid)
                terminated_count += 1
            except ValueError:
                continue
        return terminated_count
    except Exception as e:
        logging.error(f"终止端口 {port} 上的进程失败: {str(e)}")
        return 0

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
            expired_count = 0
            for entry in cursor.fetchall():
                try:
                    if entry[1]:
                        kill_process_tree(entry[1])
                        log_operation("SYSTEM", f"终止过期规则进程 | PID: {entry[1]}")
                except Exception as e:
                    logging.warning(f"终止进程失败 PID={entry[1]}: {str(e)}")
                cursor.execute('DELETE FROM forwarding WHERE id=?', (entry[0],))
                expired_count += 1
                logging.info(f"删除过期规则: ID={entry[0]}")
            db.commit()
            if expired_count > 0:
                log_operation("SYSTEM", f"自动清理过期规则 | 数量: {expired_count}")

def start_socat(source_port, destination, dest_port, protocol='tcp'):
    proto = protocol.lower()
    if proto == 'tcp':
        cmd = f"nohup socat TCP4-LISTEN:{source_port},reuseaddr,fork TCP4:{destination}:{dest_port} > /dev/null 2>&1 & echo $!"
    elif proto == 'udp':
        cmd = f"nohup socat -T 600 UDP4-LISTEN:{source_port},reuseaddr,fork UDP4:{destination}:{dest_port} > /dev/null 2>&1 & echo $!"
    else:
        raise ValueError("仅支持 TCP 和 UDP 协议")
    try:
        # 确保端口没有被占用
        if not check_port_available(source_port, protocol):
            kill_processes_on_port(source_port, protocol)
            time.sleep(0.1)  # 等待进程终止
        
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

def is_valid_id(rule_id):
    return isinstance(rule_id, str) and re.fullmatch(r'[\u4e00-\u9fa5\w-]+', rule_id)

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

@app.route('/api/forwardings', methods=['POST'])
def add_forwarding():
    try:
        data = request.get_json(force=True, silent=True) or {}
        required = ['id', 'source_port', 'destination', 'destination_port']
        if missing := [p for p in required if p not in data]:
            error_msg = f"缺少参数: {','.join(missing)}"
            log_operation("CREATE", f"添加转发失败: {error_msg}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400
        
        rule_id = data['id']
        if not is_valid_id(rule_id):
            error_msg = 'ID需为中文、英文、数字、_或-'
            log_operation("CREATE", f"添加转发失败: {error_msg} | ID: {rule_id}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400
        
        try:
            source_port = int(data['source_port'])
            dest_port = int(data['destination_port'])
        except ValueError:
            error_msg = '端口必须为整数'
            log_operation("CREATE", f"添加转发失败: {error_msg} | ID: {rule_id}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400
        
        if not is_valid_port(source_port, is_source_port=True):
            error_msg = f'本地端口必须在允许的范围内: {ALLOWED_PORT_RANGE[0]}-{ALLOWED_PORT_RANGE[1]}'
            log_operation("CREATE", f"添加转发失败: {error_msg} | ID: {rule_id}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400
        
        if not is_valid_port(dest_port, is_source_port=False):
            error_msg = '目标端口必须在1-65535之间'
            log_operation("CREATE", f"添加转发失败: {error_msg} | ID: {rule_id}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400
        
        protocol = data.get('protocol', 'tcp').lower()
        if protocol not in ('tcp', 'udp'):
            error_msg = '协议仅支持TCP/UDP'
            log_operation("CREATE", f"添加转发失败: {error_msg} | ID: {rule_id}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400
        
        editing_id = data.get('editing_id')
        
        with LOCK:
            # 强制清除占用端口的进程
            if not check_port_available(source_port, protocol, editing_id):
                port_freed = kill_processes_on_port(source_port, protocol)
                time.sleep(0.1)
                if not check_port_available(source_port, protocol, editing_id):
                    error_msg = f'本地端口 {source_port} 已被占用或不在可用范围内'
                    log_operation("CREATE", f"添加转发失败: {error_msg} | ID: {rule_id}", success=False)
                    return jsonify({'code': 400, 'message': error_msg}), 400
                else:
                    log_operation("SYSTEM", f"释放端口 {source_port}/{protocol} | 进程终止: {port_freed}")
            
            db = get_db()
            if db.execute('SELECT id FROM forwarding WHERE id=?', (rule_id,)).fetchone():
                error_msg = 'ID已存在'
                log_operation("CREATE", f"添加转发失败: {error_msg} | ID: {rule_id}", success=False)
                return jsonify({'code': 400, 'message': error_msg}), 400
            
            try:
                pid = start_socat(source_port, data['destination'], dest_port, protocol)
                expire_minutes = data.get('expire_minutes', 0)
                db.execute('''
                INSERT INTO forwarding
                (id, source_port, destination, destination_port, protocol,
                status, expire_minutes, remaining_minutes, pid, start_time)
                VALUES (?,?,?,?,?,?,?, ?,?,datetime('now'))
                ''', (
                    rule_id, source_port, data['destination'], dest_port, protocol,
                    'running', expire_minutes, expire_minutes, pid
                ))
                db.commit()
                
                # 记录详细操作日志
                log_details = f"ID: {rule_id} | 端口: {source_port}→{data['destination']}:{dest_port}/{protocol} | 有效期: {expire_minutes}分钟 | PID: {pid}"
                log_operation("CREATE", log_details, success=True)
                
                return jsonify({'code': 0})
            except Exception as e:
                db.rollback()
                log_operation("CREATE", f"添加转发失败: ID={rule_id} | 错误: {str(e)}", success=False, error=e)
                return jsonify({'code': 500, 'message': '服务器处理错误'}), 500
                
    except Exception as e:
        logging.error(f"添加转发异常: {str(e)}")
        log_operation("CREATE", f"添加转发异常: {str(e)}", success=False, error=e)
        return jsonify({'code': 500, 'message': '服务器处理错误'}), 500

@app.route('/api/forwardings/<string:fid>', methods=['PUT'])
def update_forwarding(fid):
    try:
        data = request.get_json(force=True, silent=True) or {}
        required = ['id', 'source_port', 'destination', 'destination_port']
        if missing := [p for p in required if p not in data]:
            error_msg = f"缺少参数: {','.join(missing)}"
            log_operation("UPDATE", f"更新转发失败: {error_msg} | ID: {fid}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400

        new_id = data['id']
        if not is_valid_id(new_id): 
            error_msg = 'ID需为中文、英文、数字、_或-'
            log_operation("UPDATE", f"更新转发失败: {error_msg} | 原ID: {fid} 新ID: {new_id}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400 
        
        try: 
            source_port = int(data['source_port'])
            dest_port = int(data['destination_port'])
        except ValueError: 
            error_msg = '端口必须为整数'
            log_operation("UPDATE", f"更新转发失败: {error_msg} | ID: {fid}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400 
        
        if not is_valid_port(source_port, is_source_port=True): 
            error_msg = f'本地端口必须在允许的范围内: {ALLOWED_PORT_RANGE[0]}-{ALLOWED_PORT_RANGE[1]}'
            log_operation("UPDATE", f"更新转发失败: {error_msg} | ID: {fid}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400 
        
        if not is_valid_port(dest_port, is_source_port=False): 
            error_msg = '目标端口必须在1-65535之间'
            log_operation("UPDATE", f"更新转发失败: {error_msg} | ID: {fid}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400 
        
        protocol = data.get('protocol', 'tcp').lower() 
        if protocol not in ('tcp', 'udp'): 
            error_msg = '协议仅支持TCP/UDP'
            log_operation("UPDATE", f"更新转发失败: {error_msg} | ID: {fid}", success=False)
            return jsonify({'code': 400, 'message': error_msg}), 400 
        
        expire_minutes = data.get('expire_minutes', 0)
        
        with LOCK: 
            db = get_db() 
            cursor = db.cursor() 
            cursor.execute('SELECT * FROM forwarding WHERE id=?', (fid,)) 
            original_rule = cursor.fetchone() 
            
            if not original_rule: 
                error_msg = '规则不存在'
                log_operation("UPDATE", f"更新转发失败: {error_msg} | ID: {fid}", success=False)
                return jsonify({'code': 404, 'message': error_msg}), 404 
            
            # 记录原始值用于日志
            orig_values = {
                'id': original_rule[0],
                'source_port': original_rule[1],
                'destination': original_rule[2],
                'dest_port': original_rule[3],
                'protocol': original_rule[4],
                'status': original_rule[5],
                'expire_minutes': original_rule[6],
                'pid': original_rule[10]
            }
            
            if new_id != fid: 
                cursor.execute('SELECT id FROM forwarding WHERE id=?', (new_id,)) 
                if cursor.fetchone(): 
                    error_msg = '新ID已存在'
                    log_operation("UPDATE", f"更新转发失败: {error_msg} | 原ID: {fid} 新ID: {new_id}", success=False)
                    return jsonify({'code': 400, 'message': error_msg}), 400 
            
            original_source_port = orig_values['source_port']
            original_protocol = orig_values['protocol']
            
            # 检查新端口是否可用
            port_changed = source_port != original_source_port
            protocol_changed = protocol != original_protocol
            
            if port_changed or protocol_changed:
                # 强制清除占用新端口的进程
                if not check_port_available(source_port, protocol, fid):
                    port_freed = kill_processes_on_port(source_port, protocol)
                    time.sleep(0.1)
                    if not check_port_available(source_port, protocol, fid):
                        error_msg = f'本地端口 {source_port} 已被占用或不在可用范围内'
                        log_operation("UPDATE", f"更新转发失败: {error_msg} | ID: {fid}", success=False)
                        return jsonify({'code': 400, 'message': error_msg}), 400
                    else:
                        log_operation("SYSTEM", f"释放端口 {source_port}/{protocol} | 进程终止: {port_freed}")
            
            try:
                cursor.execute(''' 
                UPDATE forwarding SET id = ?, source_port = ?, destination = ?, destination_port = ?, protocol = ?, expire_minutes = ?, remaining_minutes = ? 
                WHERE id = ? 
                ''', ( 
                    new_id, source_port, data['destination'], dest_port, protocol, expire_minutes, expire_minutes, fid 
                )) 
                
                original_status = orig_values['status']
                original_pid = orig_values['pid']
                
                # 记录变更详情
                changes = []
                if fid != new_id:
                    changes.append(f"ID: {fid}→{new_id}")
                if source_port != original_source_port:
                    changes.append(f"端口: {original_source_port}→{source_port}")
                if data['destination'] != orig_values['destination'] or dest_port != orig_values['dest_port']:
                    changes.append(f"目标: {orig_values['destination']}:{orig_values['dest_port']}→{data['destination']}:{dest_port}")
                if protocol != original_protocol:
                    changes.append(f"协议: {original_protocol}→{protocol}")
                if expire_minutes != orig_values['expire_minutes']:
                    changes.append(f"有效期: {orig_values['expire_minutes']}→{expire_minutes}分钟")
                
                if original_status == 'running': 
                    try: 
                        if original_pid: 
                            kill_process_tree(original_pid)
                            log_operation("SYSTEM", f"终止旧进程 | PID: {original_pid}")
                        # 确保旧端口被释放
                        kill_processes_on_port(original_source_port, original_protocol)
                    except Exception as e:
                        logging.warning(f"终止旧进程失败 PID={original_pid}: {str(e)}")
                    
                    try:
                        new_pid = start_socat(source_port, data['destination'], dest_port, protocol) 
                        cursor.execute('UPDATE forwarding SET pid = ?, start_time = datetime("now") WHERE id = ?', (new_pid, new_id)) 
                        changes.append(f"重启转发 | 新PID: {new_pid}")
                    except Exception as e:
                        logging.error(f"启动新进程失败: {str(e)}")
                        log_operation("UPDATE", f"更新转发失败: 启动新转发失败 | ID: {fid}", success=False, error=e)
                        return jsonify({'code': 500, 'message': '启动新转发失败'}), 500
                
                db.commit()
                
                # 记录操作日志
                log_details = f"ID: {fid}→{new_id} | 变更: {'; '.join(changes)}"
                log_operation("UPDATE", log_details, success=True)
                
                return jsonify({'code': 0}) 
            except Exception as e:
                db.rollback()
                log_operation("UPDATE", f"更新转发失败: 数据库错误 | ID: {fid}", success=False, error=e)
                return jsonify({'code': 500, 'message': '数据库操作失败'}), 500
                
    except Exception as e: 
        logging.error(f"更新规则失败: {str(e)}")
        log_operation("UPDATE", f"更新转发失败: 未处理异常 | ID: {fid}", success=False, error=e)
        return jsonify({'code': 500, 'message': '服务器处理错误'}), 500 

@app.route('/api/forwardings/<string:fid>', methods=['DELETE'])
def delete_forwarding(fid):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
        SELECT id, source_port, destination, destination_port, protocol, status, pid 
        FROM forwarding WHERE id=?
        ''', (fid,))
        entry = cursor.fetchone()
        
        if not entry:
            log_operation("DELETE", f"删除转发失败: 规则不存在 | ID: {fid}", success=False)
            return jsonify({'code': 404, 'message': '规则不存在'}), 404
        
        rule_id, source_port, dest, dest_port, protocol, status, pid = entry
        ports_freed = 0
        
        if status == 'running' and pid:
            try:
                kill_process_tree(pid)
                log_operation("SYSTEM", f"终止转发进程 | PID: {pid}")
            except Exception as e:
                logging.warning(f"终止进程失败 PID={pid}: {str(e)}")
        
        # 确保端口被释放
        ports_freed = kill_processes_on_port(source_port, protocol)
        
        cursor.execute('DELETE FROM forwarding WHERE id=?', (fid,))
        db.commit()
        
        # 记录操作日志
        log_details = f"ID: {rule_id} | 端口: {source_port}/{protocol} | 目标: {dest}:{dest_port} | 终止进程: {pid if pid else '无'}"
        log_operation("DELETE", log_details, success=True)
        
        return jsonify({'code': 0})
    except Exception as e:
        db.rollback()
        log_operation("DELETE", f"删除转发失败 | ID: {fid}", success=False, error=e)
        return jsonify({'code': 500, 'message': '服务器处理错误'}), 500

@app.route('/api/forwardings/<string:fid>/start', methods=['POST'])
def start_forward(fid):
    return update_forward_status(fid, 'running')

@app.route('/api/forwardings/<string:fid>/stop', methods=['POST'])
def stop_forward(fid):
    return update_forward_status(fid, 'stopped')

def update_forward_status(fid, status):
    action = 'START' if status == 'running' else 'STOP'
    try:
        db = get_db()
        cursor = db.execute('''
        SELECT id, source_port, destination, destination_port, protocol,
        start_time, expire_minutes, remaining_minutes, pid
        FROM forwarding WHERE id=?
        ''', (fid,))
        
        if not (entry := cursor.fetchone()):
            log_operation(action, f"变更状态失败: 规则不存在 | ID: {fid}", success=False)
            return jsonify({'code': 404, 'message': '规则不存在'}), 404
        
        rule_id, sport, dest, dport, proto, start_time, expire_minutes, remaining_minutes, pid = entry
        
        if status == 'running':
            # 强制清除占用端口的进程
            if not check_port_available(sport, proto, fid):
                port_freed = kill_processes_on_port(sport, proto)
                time.sleep(0.1)
                if not check_port_available(sport, proto, fid):
                    error_msg = f'本地端口 {sport} 已被占用或不在可用范围内'
                    log_operation(action, f"变更状态失败: {error_msg} | ID: {fid}", success=False)
                    return jsonify({'code': 400, 'message': error_msg}), 400
                else:
                    log_operation("SYSTEM", f"释放端口 {sport}/{proto} | 进程终止: {port_freed}")
            
            try:
                if pid:
                    kill_process_tree(pid)
                    log_operation("SYSTEM", f"终止旧进程 | PID: {pid}")
                new_pid = start_socat(sport, dest, dport, proto)
                cursor.execute('''
                UPDATE forwarding SET
                status=?, pid=?, start_time=datetime('now')
                WHERE id=?
                ''', (status, new_pid, fid))
                db.commit()
                
                # 记录操作日志
                log_details = f"ID: {fid} | 端口: {sport}/{proto} | 目标: {dest}:{dport} | PID: {new_pid}"
                log_operation(action, log_details, success=True)
                
                return jsonify({'code': 0})
            except Exception as e:
                db.rollback()
                log_operation(action, f"变更状态失败: 启动转发失败 | ID: {fid}", success=False, error=e)
                return jsonify({'code': 500, 'message': '启动转发失败'}), 500
        else:  # 停止操作
            try:
                if pid:
                    kill_process_tree(pid)
                    log_operation("SYSTEM", f"终止进程 | PID: {pid}")
                
                if expire_minutes > 0 and start_time:
                    try:
                        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
                        elapsed_minutes = int((datetime.now() - start_dt).total_seconds() / 60)
                        remaining_minutes = max(0, (remaining_minutes or expire_minutes) - elapsed_minutes)
                    except Exception:
                        remaining_minutes = remaining_minutes or expire_minutes
                else:
                    remaining_minutes = expire_minutes
                
                cursor.execute('''
                UPDATE forwarding SET
                status=?, pid=NULL, remaining_minutes=?
                WHERE id=?
                ''', (status, remaining_minutes, fid))
                db.commit()
                
                # 记录操作日志
                log_details = f"ID: {fid} | 端口: {sport}/{proto} | 剩余时间: {remaining_minutes}分钟"
                log_operation(action, log_details, success=True)
                
                return jsonify({'code': 0})
            except Exception as e:
                db.rollback()
                log_operation(action, f"变更状态失败: 停止转发失败 | ID: {fid}", success=False, error=e)
                return jsonify({'code': 500, 'message': '停止转发失败'}), 500
    except Exception as e:
        log_operation(action, f"变更状态失败: 未处理异常 | ID: {fid}", success=False, error=e)
        return jsonify({'code': 500, 'message': '服务器处理错误'}), 500

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
        cursor = db.cursor()
        cursor.execute('''
        SELECT id, source_port, destination, destination_port, protocol
        FROM forwarding WHERE status='running'
        ''')
        restored_count = 0
        failed_count = 0
        
        for fid, sport, dest, dport, proto in cursor.fetchall():
            try:
                # 确保端口没有被占用
                if not check_port_available(sport, proto):
                    ports_freed = kill_processes_on_port(sport, proto)
                    time.sleep(0.1)
                
                pid = start_socat(sport, dest, dport, proto)
                cursor.execute('UPDATE forwarding SET pid=?, start_time=datetime("now") WHERE id=?', (pid, fid))
                restored_count += 1
                logging.info(f"规则恢复成功: ID={fid} | PID={pid}")
            except Exception as e:
                failed_count += 1
                cursor.execute('UPDATE forwarding SET status="stopped", pid=NULL WHERE id=?', (fid,))
                logging.error(f"规则恢复失败: ID={fid} error={str(e)}")
        
        db.commit()
        log_operation("SYSTEM", f"规则恢复完成 | 成功: {restored_count} | 失败: {failed_count}")

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