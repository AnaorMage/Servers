import os
import json
import re
import sys
import uuid
import urllib.error
import urllib.request
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2.extras import RealDictCursor


if getattr(sys, 'frozen', False):
    template_folder = os.path.join(sys._MEIPASS, 'templates')
    app = Flask(__name__, template_folder=template_folder)
    BASE_DIR = os.path.dirname(sys.executable)
else:
    app = Flask(__name__)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app.config['SECRET_KEY'] = 'server-inventory-secret-key-change-me'


ATTACHMENTS_DIR = os.path.join(BASE_DIR, 'attachments')
os.makedirs(ATTACHMENTS_DIR, exist_ok=True)

#PostgreSQL
DB_HOST = "127.0.0.1"
DB_NAME = "SERVERS"
DB_USER = "postgres"
DB_PASS = "arnold001"
DB_PORT = "5432"

# Разрешенные поля сортировки таблицы серверов
SORT_COLUMNS = {
    'id': 's.id',
    'name': 's.name',
    'ip': 's.ip_address',
    'cpu': 's.cpu_cores',
    'ram': 's.ram_gb',
    'disk': 's.disk_gb',
    'launch_year': 's.launch_year',
    'requirement': 'requirement_codes',
    'is_name': 'isys.name',
    'role': 'sr.name',
    'os': 'os.name',
    'env': 'env.name',
}

ALLOWED_REF_TABLES = ['operating_systems', 'environments', 'server_roles', 'information_systems', 'requirements']


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        port=DB_PORT,
        cursor_factory=RealDictCursor
    )


def is_ajax():
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def clean_int(value, default=None):
    """Преобразует пустые строки и '-- выберите --' в None (NULL для БД)"""
    if value is None:
        return default
    value_str = str(value).strip()
    if not value_str or value_str.startswith('--'):
        return default
    try:
        return int(value_str)
    except ValueError:
        return default


def has_column(cur, table, column):
    cur.execute('''
        SELECT 1 FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s;
    ''', (table, column))
    return cur.fetchone() is not None


#ИИ-помощник

IP_PATTERN = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def analyze_servers():
    conn = get_db_connection()
    cur = conn.cursor()
    findings = []

    has_archive = has_column(cur, 'servers', 'is_archived')
    where = 'WHERE is_archived = FALSE' if has_archive else ''
    cur.execute(f'''
        SELECT id, name, ip_address, dbms_version, launch_year,
               cpu_cores, ram_gb, disk_gb, os_id, environment_id, server_role_id, is_id
        FROM servers
        {where};
    ''')
    servers = cur.fetchall()

    ip_map = {}
    for s in servers:
        ip_map.setdefault(s['ip_address'], []).append(s['id'])

    req_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM server_requirements GROUP BY server_id;')
        req_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    comment_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM comments GROUP BY server_id;')
        comment_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    cur.close()
    conn.close()

    current_year = datetime.now().year

    def add(server_id, server_name, severity, message):
        findings.append({
            'server_id': server_id, 'server_name': server_name,
            'severity': severity, 'message': message
        })

    for s in servers:
        sid, name = s['id'], s['name']

        if len(ip_map.get(s['ip_address'], [])) > 1:
            add(sid, name, 'critical',
                f'IP-адрес {s["ip_address"]} совпадает еще с {len(ip_map[s["ip_address"]]) - 1} сервером(ами) — конфликт адресов.')

        if s['ip_address'] and not IP_PATTERN.match(s['ip_address']):
            add(sid, name, 'warning', 'IP-адрес не похож на корректный IPv4 — проверьте формат.')

        missing = []
        if not s['os_id']: missing.append('ОС')
        if not s['environment_id']: missing.append('среда')
        if not s['server_role_id']: missing.append('роль')
        if not s['is_id']: missing.append('информационная система')
        if missing:
            add(sid, name, 'critical', f'Не заполнено: {", ".join(missing)}. Сложно понять назначение и владельца сервера.')

        if not s['launch_year']:
            add(sid, name, 'info', 'Не указан год запуска — сложно планировать замену/обновление оборудования.')
        elif current_year - s['launch_year'] >= 6:
            age = current_year - s['launch_year']
            add(sid, name, 'warning',
                f'Сервер запущен в {s["launch_year"]} ({age} лет назад) — возможно устарел, стоит проверить и запланировать замену, пока он не "слетел".')

        cpu, ram = s['cpu_cores'] or 0, s['ram_gb'] or 0
        if cpu > 0 and ram > 0 and (ram / cpu) < 2:
            add(sid, name, 'warning', f'Мало RAM на ядро ({ram} ГБ на {cpu} vCPU) — риск нехватки памяти под нагрузкой.')

        disk = s['disk_gb'] or 0
        if 0 < disk < 50:
            add(sid, name, 'warning', f'Очень маленький диск ({disk} ГБ) — высокий риск переполнения.')

        if req_counts.get(sid, 0) == 0:
            add(sid, name, 'info', 'Не привязана ни одна потребность — непонятно, для какой задачи используется сервер.')

        if comment_counts.get(sid, 0) == 0:
            add(sid, name, 'info', 'Нет ни одного комментария — сервер не задокументирован.')

        if s['dbms_version']:
            m = re.match(r'^(\d+)', s['dbms_version'].strip())
            if m and int(m.group(1)) <= 10:
                add(sid, name, 'critical',
                    f'Версия СУБД {s["dbms_version"]} выглядит устаревшей — обновление снизит риски безопасности и совместимости.')

    severity_order = {'critical': 0, 'warning': 1, 'info': 2}
    findings.sort(key=lambda f: severity_order.get(f['severity'], 3))
    return findings


@app.route('/ai/analyze')
def ai_analyze():
    findings = analyze_servers()
    summary = {
        'critical': sum(1 for f in findings if f['severity'] == 'critical'),
        'warning': sum(1 for f in findings if f['severity'] == 'warning'),
        'info': sum(1 for f in findings if f['severity'] == 'info'),
    }
    return jsonify({'findings': findings, 'summary': summary})

#Ollama

OLLAMA_URL = 'http://127.0.0.1:11434/api/generate'
OLLAMA_MODEL = 'qwen2.5:1.5b'


def ask_local_ai(prompt, timeout=90):
    payload = json.dumps({
        'model': OLLAMA_MODEL,
        'prompt': prompt,
        'stream': False
    }).encode('utf-8')

    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        return (data.get('response') or '').strip()


@app.route('/ai/explain')
def ai_explain():
    findings = analyze_servers()
    if not findings:
        return jsonify({'text': 'Проблем не найдено — по текущим данным инфраструктура выглядит в порядке.'})

    lines = [f"- [{f['severity']}] {f['server_name']}: {f['message']}" for f in findings[:30]]
    findings_text = "\n".join(lines)

    prompt = (
        "Ты — опытный системный администратор. Ниже список найденных проблем на серверах "
        "(critical — критично, warning — нужно внимание, info — информационно). "
        "Кратко, простым языком по-русски (не более 6-8 предложений) объясни: "
        "1) какие проблемы самые срочные и почему, "
        "2) что сделать в первую очередь. "
        "Не пересказывай список дословно, дай именно осмысленный вывод.\n\n"
        f"Список проблем:\n{findings_text}"
    )

    try:
        text = ask_local_ai(prompt)
        if not text:
            return jsonify({'error': 'Локальная модель вернула пустой ответ. Попробуйте еще раз.'}), 502
        return jsonify({'text': text})
    except urllib.error.URLError:
        return jsonify({
            'error': f'Не удалось подключиться к Ollama на 127.0.0.1:11434. '
                     f'Убедитесь, что приложение Ollama запущено и модель загружена '
                     f'(в командной строке: ollama pull {OLLAMA_MODEL}).'
        }), 503
    except Exception as e:
        return jsonify({'error': f'Ошибка запроса к ИИ: {e}'}), 500


@app.route('/')
def index():
    conn = get_db_connection()
    cur = conn.cursor()

    # --- Сортировка ---
    sort = request.args.get('sort', 'id')
    order = request.args.get('order', 'desc')
    if sort not in SORT_COLUMNS:
        sort = 'id'
    if order not in ('asc', 'desc'):
        order = 'desc'
    order_sql = SORT_COLUMNS[sort]

    has_archive = has_column(cur, 'servers', 'is_archived')
    archive_where = 'WHERE s.is_archived = FALSE' if has_archive else ''
    if not has_archive:
        flash('Внимание: не выполнена миграция архива (migration_add_archive.sql). Функция архива недоступна.', 'error')

    # Загрузка всех серверов + агрегированный список кодов потребностей
    try:
        cur.execute(f'''
            SELECT
                s.id, s.name AS server_name, s.ip_address, s.dbms_version, s.launch_year,
                s.cpu_cores, s.ram_gb, s.disk_gb, s.is_id,
                isys.name AS is_name, sr.name AS role_name, os.name AS os_name, env.name AS env_name,
                (
                    SELECT STRING_AGG(r.code, ', ' ORDER BY r.code)
                    FROM server_requirements sreq
                    JOIN requirements r ON r.id = sreq.requirement_id
                    WHERE sreq.server_id = s.id
                ) AS requirement_codes
            FROM servers s
            LEFT JOIN information_systems isys ON s.is_id = isys.id
            LEFT JOIN server_roles sr ON s.server_role_id = sr.id
            LEFT JOIN operating_systems os ON s.os_id = os.id
            LEFT JOIN environments env ON s.environment_id = env.id
            {archive_where}
            ORDER BY {order_sql} {order.upper()} NULLS LAST;
        ''')
        servers = cur.fetchall()
    except Exception:
        conn.rollback()
        cur.execute(f'''
            SELECT
                s.id, s.name AS server_name, s.ip_address, s.dbms_version, NULL AS launch_year,
                s.cpu_cores, s.ram_gb, s.disk_gb, s.is_id,
                isys.name AS is_name, sr.name AS role_name, os.name AS os_name, env.name AS env_name,
                s.requirement_code AS requirement_codes
            FROM servers s
            LEFT JOIN information_systems isys ON s.is_id = isys.id
            LEFT JOIN server_roles sr ON s.server_role_id = sr.id
            LEFT JOIN operating_systems os ON s.os_id = os.id
            LEFT JOIN environments env ON s.environment_id = env.id
            {archive_where}
            ORDER BY s.id DESC;
        ''')
        servers = cur.fetchall()
        flash('Внимание: не выполнена миграция БД (requirements/launch_year). Часть функций недоступна.', 'error')

    # Количество комментариев к каждому серверу
    comment_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM comments GROUP BY server_id;')
        comment_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    # Количество прикреплённых файлов к каждому серверу
    attachment_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM attachments GROUP BY server_id;')
        attachment_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    # Количество версий в истории изменений каждого сервера
    history_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM server_history GROUP BY server_id;')
        history_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    # Расчет
    for s in servers:
        cpu = s['cpu_cores'] or 0
        ram = s['ram_gb'] or 0
        disk = s['disk_gb'] or 0
        s['usable_db_storage'] = round(disk * 0.85)
        s['max_load_users'] = (cpu * 25) + (ram * 5)
        s['comment_count'] = comment_counts.get(s['id'], 0)
        s['attachment_count'] = attachment_counts.get(s['id'], 0)
        s['history_count'] = history_counts.get(s['id'], 0)

    #Суммарная аналитика
    cur.execute('''
        SELECT
            COUNT(*) AS total_servers,
            COALESCE(SUM(cpu_cores), 0) AS total_cpu,
            COALESCE(SUM(ram_gb), 0) AS total_ram,
            COALESCE(SUM(disk_gb), 0) AS total_disk
        FROM servers;
    ''')
    totals = cur.fetchone()

    # Выпадающие списки / справочники
    cur.execute('SELECT id, name FROM operating_systems ORDER BY name;')
    os_list = cur.fetchall()
    cur.execute('SELECT id, name FROM environments ORDER BY name;')
    env_list = cur.fetchall()
    cur.execute('SELECT id, name FROM server_roles ORDER BY name;')
    role_list = cur.fetchall()
    cur.execute('SELECT id, code, name FROM information_systems ORDER BY name;')
    is_list = cur.fetchall()

    requirements_list = []
    try:
        cur.execute('SELECT id, code, description FROM requirements ORDER BY code;')
        requirements_list = cur.fetchall()
    except Exception:
        conn.rollback()

    cur.close()
    conn.close()

    return render_template('index.html',
                           servers=servers,
                           totals=totals,
                           os_list=os_list,
                           env_list=env_list,
                           role_list=role_list,
                           is_list=is_list,
                           requirements_list=requirements_list,
                           current_sort=sort,
                           current_order=order)


@app.route('/add', methods=['POST'])
def add_server():
    conn = get_db_connection()
    cur = conn.cursor()

    name = request.form.get('name')
    ip_address = request.form.get('ip_address')
    dbms_version = request.form.get('dbms_version') or None
    launch_year = clean_int(request.form.get('launch_year'))

    cpu_cores = clean_int(request.form.get('cpu_cores'), default=4)
    ram_gb = clean_int(request.form.get('ram_gb'), default=16)
    disk_gb = clean_int(request.form.get('disk_gb'), default=100)

    os_id = clean_int(request.form.get('os_id'))
    env_id = clean_int(request.form.get('env_id'))
    role_id = clean_int(request.form.get('role_id'))
    is_id = clean_int(request.form.get('is_id'))

    requirement_ids = [clean_int(v) for v in request.form.getlist('requirement_ids')]
    requirement_ids = [r for r in requirement_ids if r]


    is_name = (request.form.get('is_name') or '').strip()
    new_is_code = (request.form.get('new_is_code') or '').strip() or None
    if is_name:
        cur.execute('SELECT id FROM information_systems WHERE name = %s;', (is_name,))
        existing_is = cur.fetchone()
        if existing_is:
            is_id = existing_is['id']
        else:
            cur.execute(
                'INSERT INTO information_systems (code, name) VALUES (%s, %s) RETURNING id;',
                (new_is_code, is_name)
            )
            is_id = cur.fetchone()['id']

    # Новая потребность
    new_requirement_code = (request.form.get('new_requirement_code') or '').strip()
    if new_requirement_code:
        cur.execute('SELECT id FROM requirements WHERE code = %s;', (new_requirement_code,))
        existing_req = cur.fetchone()
        if existing_req:
            requirement_ids.append(existing_req['id'])
        else:
            cur.execute('INSERT INTO requirements (code) VALUES (%s) RETURNING id;', (new_requirement_code,))
            requirement_ids.append(cur.fetchone()['id'])

    cur.execute('''
        INSERT INTO servers (
            name, ip_address, dbms_version, launch_year,
            cpu_cores, ram_gb, disk_gb,
            os_id, environment_id, server_role_id, is_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    ''', (
        name, ip_address, dbms_version, launch_year,
        cpu_cores, ram_gb, disk_gb,
        os_id, env_id, role_id, is_id
    ))
    new_id = cur.fetchone()['id']

    for req_id in requirement_ids:
        try:
            cur.execute('''
                INSERT INTO server_requirements (server_id, requirement_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING;
            ''', (new_id, req_id))
        except Exception:
            conn.rollback()

    conn.commit()
    cur.close()
    conn.close()
    flash(f'Сервер "{name}" успешно добавлен.', 'success')
    return redirect(url_for('index'))


@app.route('/delete/<int:id>')
def delete_server(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if has_column(cur, 'servers', 'is_archived'):
            cur.execute('UPDATE servers SET is_archived = TRUE, archived_at = NOW() WHERE id = %s;', (id,))
            conn.commit()
            flash('Сервер перемещен в архив.', 'success')
        else:
            cur.execute('DELETE FROM servers WHERE id = %s;', (id,))
            conn.commit()
            flash('Сервер удален (архив не настроен — выполните миграцию).', 'success')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('index'))


#архив

@app.route('/archive/page')
def archive_page():
    conn = get_db_connection()
    cur = conn.cursor()

    sort = request.args.get('sort', 'id')
    order = request.args.get('order', 'desc')
    if sort not in SORT_COLUMNS:
        sort = 'id'
    if order not in ('asc', 'desc'):
        order = 'desc'
    order_sql = SORT_COLUMNS[sort]

    try:
        cur.execute(f'''
            SELECT
                s.id, s.name AS server_name, s.ip_address, s.dbms_version, s.launch_year,
                s.cpu_cores, s.ram_gb, s.disk_gb, s.is_id, s.archived_at,
                isys.name AS is_name, sr.name AS role_name, os.name AS os_name, env.name AS env_name,
                (
                    SELECT STRING_AGG(r.code, ', ' ORDER BY r.code)
                    FROM server_requirements sreq
                    JOIN requirements r ON r.id = sreq.requirement_id
                    WHERE sreq.server_id = s.id
                ) AS requirement_codes
            FROM servers s
            LEFT JOIN information_systems isys ON s.is_id = isys.id
            LEFT JOIN server_roles sr ON s.server_role_id = sr.id
            LEFT JOIN operating_systems os ON s.os_id = os.id
            LEFT JOIN environments env ON s.environment_id = env.id
            WHERE s.is_archived = TRUE
            ORDER BY {order_sql} {order.upper()} NULLS LAST;
        ''')
        servers = cur.fetchall()
    except Exception:
        conn.rollback()
        flash('Внимание: архив недоступен — выполните migration_add_archive.sql.', 'error')
        servers = []

    comment_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM comments GROUP BY server_id;')
        comment_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    attachment_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM attachments GROUP BY server_id;')
        attachment_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    history_counts = {}
    try:
        cur.execute('SELECT server_id, COUNT(*) AS cnt FROM server_history GROUP BY server_id;')
        history_counts = {row['server_id']: row['cnt'] for row in cur.fetchall()}
    except Exception:
        conn.rollback()

    for s in servers:
        cpu = s['cpu_cores'] or 0
        ram = s['ram_gb'] or 0
        disk = s['disk_gb'] or 0
        s['usable_db_storage'] = round(disk * 0.85)
        s['max_load_users'] = (cpu * 25) + (ram * 5)
        s['comment_count'] = comment_counts.get(s['id'], 0)
        s['attachment_count'] = attachment_counts.get(s['id'], 0)
        s['history_count'] = history_counts.get(s['id'], 0)
        if s['archived_at']:
            s['archived_at'] = s['archived_at'].strftime('%d.%m.%Y %H:%M')

    cur.execute('SELECT id, name FROM operating_systems ORDER BY name;')
    os_list = cur.fetchall()
    cur.execute('SELECT id, name FROM environments ORDER BY name;')
    env_list = cur.fetchall()
    cur.execute('SELECT id, name FROM server_roles ORDER BY name;')
    role_list = cur.fetchall()
    cur.execute('SELECT id, code, name FROM information_systems ORDER BY name;')
    is_list = cur.fetchall()
    requirements_list = []
    try:
        cur.execute('SELECT id, code, description FROM requirements ORDER BY code;')
        requirements_list = cur.fetchall()
    except Exception:
        conn.rollback()

    cur.close()
    conn.close()

    return render_template('archive.html',
                           servers=servers,
                           os_list=os_list,
                           env_list=env_list,
                           role_list=role_list,
                           is_list=is_list,
                           requirements_list=requirements_list,
                           current_sort=sort,
                           current_order=order)


@app.route('/archive/restore/<int:id>', methods=['POST'])
def restore_from_archive(id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE servers SET is_archived = FALSE, archived_at = NULL WHERE id = %s;', (id,))
    conn.commit()
    cur.close()
    conn.close()
    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('archive_page'))


@app.route('/archive/delete/<int:id>', methods=['POST'])
def delete_from_archive(id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM servers WHERE id = %s AND is_archived = TRUE;', (id,))
    conn.commit()
    cur.close()
    conn.close()
    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('archive_page'))


# Группировка таблиц

@app.route('/servers/grouped')
def servers_grouped():
    by = request.args.get('by', 'requirement')
    conn = get_db_connection()
    cur = conn.cursor()

    has_archive = has_column(cur, 'servers', 'is_archived')
    where = 'WHERE s.is_archived = FALSE' if has_archive else ''

    if by == 'is':
        cur.execute(f'''
            SELECT
                COALESCE(isys.name, 'Без ИС') AS group_label,
                s.id, s.name AS server_name, s.ip_address,
                s.cpu_cores, s.ram_gb, s.disk_gb,
                sr.name AS role_name, os.name AS os_name, env.name AS env_name
            FROM servers s
            LEFT JOIN information_systems isys ON s.is_id = isys.id
            LEFT JOIN server_roles sr ON s.server_role_id = sr.id
            LEFT JOIN operating_systems os ON s.os_id = os.id
            LEFT JOIN environments env ON s.environment_id = env.id
            {where}
            ORDER BY group_label, s.name;
        ''')
    else:
        try:
            archive_extra = 'AND s.is_archived = FALSE' if has_archive else ''
            cur.execute(f'''
                SELECT
                    COALESCE(r.code, 'Без потребности') AS group_label,
                    COALESCE(isys.name, 'Без ИС') AS subgroup_label,
                    s.id, s.name AS server_name, s.ip_address,
                    s.cpu_cores, s.ram_gb, s.disk_gb,
                    sr.name AS role_name, os.name AS os_name, env.name AS env_name
                FROM requirements r
                LEFT JOIN system_requirements sysreq ON sysreq.requirement_id = r.id
                LEFT JOIN information_systems isys ON isys.id = sysreq.is_id
                LEFT JOIN servers s ON s.is_id = isys.id {archive_extra}
                LEFT JOIN server_roles sr ON s.server_role_id = sr.id
                LEFT JOIN operating_systems os ON s.os_id = os.id
                LEFT JOIN environments env ON s.environment_id = env.id
                ORDER BY group_label, subgroup_label, s.name;
            ''')
        except Exception:
            conn.rollback()
            cur.close()
            conn.close()
            return jsonify([])

    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


#Редактирование

@app.route('/server/<int:server_id>/edit', methods=['GET', 'POST'])
def edit_server(server_id):
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'GET':
        cur.execute('''
            SELECT id, name, ip_address, dbms_version, launch_year,
                   cpu_cores, ram_gb, disk_gb, os_id, environment_id, server_role_id, is_id
            FROM servers WHERE id = %s;
        ''', (server_id,))
        server = cur.fetchone()
        if not server:
            cur.close()
            conn.close()
            return jsonify({'error': 'not found'}), 404

        try:
            cur.execute('SELECT requirement_id FROM server_requirements WHERE server_id = %s;', (server_id,))
            server['requirement_ids'] = [row['requirement_id'] for row in cur.fetchall()]
        except Exception:
            conn.rollback()
            server['requirement_ids'] = []

        cur.close()
        conn.close()
        return jsonify(server)

    # POST — сохранение изменений
    name = request.form.get('name')
    ip_address = request.form.get('ip_address')
    dbms_version = request.form.get('dbms_version') or None
    launch_year = clean_int(request.form.get('launch_year'))

    cpu_cores = clean_int(request.form.get('cpu_cores'), default=4)
    ram_gb = clean_int(request.form.get('ram_gb'), default=16)
    disk_gb = clean_int(request.form.get('disk_gb'), default=100)

    os_id = clean_int(request.form.get('os_id'))
    env_id = clean_int(request.form.get('env_id'))
    role_id = clean_int(request.form.get('role_id'))
    is_id = clean_int(request.form.get('is_id'))

    requirement_ids = [clean_int(v) for v in request.form.getlist('requirement_ids')]
    requirement_ids = [r for r in requirement_ids if r]

    # сохранение состояния сервера
    try:
        cur.execute('''
            SELECT
                s.name, s.ip_address, s.dbms_version, s.launch_year,
                s.cpu_cores, s.ram_gb, s.disk_gb,
                os.name AS os_name, env.name AS env_name, sr.name AS role_name, isys.name AS is_name,
                (
                    SELECT STRING_AGG(r.code, ', ' ORDER BY r.code)
                    FROM server_requirements sreq
                    JOIN requirements r ON r.id = sreq.requirement_id
                    WHERE sreq.server_id = s.id
                ) AS requirement_codes
            FROM servers s
            LEFT JOIN operating_systems os ON s.os_id = os.id
            LEFT JOIN environments env ON s.environment_id = env.id
            LEFT JOIN server_roles sr ON s.server_role_id = sr.id
            LEFT JOIN information_systems isys ON s.is_id = isys.id
            WHERE s.id = %s;
        ''', (server_id,))
        old_state = cur.fetchone()
        if old_state:
            cur.execute('''
                INSERT INTO server_history (
                    server_id, name, ip_address, dbms_version, launch_year,
                    cpu_cores, ram_gb, disk_gb, os_name, env_name, role_name, is_name, requirement_codes
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            ''', (
                server_id, old_state['name'], old_state['ip_address'], old_state['dbms_version'], old_state['launch_year'],
                old_state['cpu_cores'], old_state['ram_gb'], old_state['disk_gb'],
                old_state['os_name'], old_state['env_name'], old_state['role_name'], old_state['is_name'],
                old_state['requirement_codes']
            ))
    except Exception:
        conn.rollback()

    cur.execute('''
        UPDATE servers SET
            name = %s, ip_address = %s, dbms_version = %s, launch_year = %s,
            cpu_cores = %s, ram_gb = %s, disk_gb = %s,
            os_id = %s, environment_id = %s, server_role_id = %s, is_id = %s
        WHERE id = %s;
    ''', (
        name, ip_address, dbms_version, launch_year,
        cpu_cores, ram_gb, disk_gb,
        os_id, env_id, role_id, is_id,
        server_id
    ))

    try:
        cur.execute('DELETE FROM server_requirements WHERE server_id = %s;', (server_id,))
        for req_id in requirement_ids:
            cur.execute('''
                INSERT INTO server_requirements (server_id, requirement_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING;
            ''', (server_id, req_id))
    except Exception:
        conn.rollback()

    conn.commit()
    cur.close()
    conn.close()
    flash(f'Сервер "{name}" обновлен.', 'success')

    return_to = request.form.get('return_to', 'index')
    if return_to == 'archive':
        return redirect(url_for('archive_page'))
    return redirect(url_for('index'))


@app.route('/server/<int:server_id>/history')
def get_server_history(server_id):
    conn = get_db_connection()
    cur = conn.cursor()
    history = []
    try:
        cur.execute('''
            SELECT id, changed_at, name, ip_address, dbms_version, launch_year,
                   cpu_cores, ram_gb, disk_gb, os_name, env_name, role_name, is_name, requirement_codes
            FROM server_history
            WHERE server_id = %s
            ORDER BY changed_at DESC;
        ''', (server_id,))
        history = cur.fetchall()
    except Exception:
        conn.rollback()
    cur.close()
    conn.close()

    for h in history:
        if h['changed_at']:
            h['changed_at'] = h['changed_at'].strftime('%d.%m.%Y %H:%M')
    return jsonify(history)


# Справочники

@app.route('/ref/add/<table_name>', methods=['POST'])
def add_reference_item(table_name):
    if table_name not in ALLOWED_REF_TABLES:
        return redirect(url_for('index'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if table_name == 'requirements':
            code = (request.form.get('code') or '').strip()
            description = request.form.get('description') or None
            if not code:
                if is_ajax():
                    cur.close(); conn.close()
                    return jsonify({'error': 'Укажите код потребности.'}), 400
                flash('Укажите код потребности.', 'error')
            else:
                cur.execute('SELECT id, code, description FROM requirements WHERE code = %s;', (code,))
                existing = cur.fetchone()
                if existing:
                    result = existing
                else:
                    cur.execute(
                        "INSERT INTO requirements (code, description) VALUES (%s, %s) RETURNING id, code, description;",
                        (code, description)
                    )
                    result = cur.fetchone()
                    conn.commit()
                if is_ajax():
                    cur.close(); conn.close()
                    return jsonify(result)
                flash('Потребность добавлена.', 'success')
        elif table_name == 'information_systems':
            name = request.form.get('name')
            code = request.form.get('code')
            if not name:
                flash('Укажите название информационной системы.', 'error')
            else:
                cur.execute(
                    "INSERT INTO information_systems (code, name) VALUES (%s, %s);",
                    (code, name)
                )
                conn.commit()
                flash('Информационная система добавлена.', 'success')
        else:
            name = request.form.get('name')
            if not name:
                flash('Укажите название.', 'error')
            else:
                cur.execute(f"INSERT INTO {table_name} (name) VALUES (%s);", (name,))
                conn.commit()
                flash('Элемент справочника добавлен.', 'success')
    except Exception as e:
        conn.rollback()
        if is_ajax():
            cur.close(); conn.close()
            return jsonify({'error': str(e)}), 400
        flash(f'Ошибка добавления: {e}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('index'))


@app.route('/ref/delete/<table_name>/<int:item_id>')
def delete_reference_item(table_name, item_id):
    if table_name not in ALLOWED_REF_TABLES:
        return redirect(url_for('index'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(f"DELETE FROM {table_name} WHERE id = %s;", (item_id,))
        conn.commit()
        flash('Элемент удален.', 'success')
    except Exception:
        conn.rollback()
        flash('Ошибка удаления: элемент используется и не может быть удален.', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('index'))


# Привязка 

@app.route('/requirement/<int:requirement_id>/servers')
def get_requirement_servers(requirement_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT s.id, s.name, s.ip_address
        FROM server_requirements sr
        JOIN servers s ON s.id = sr.server_id
        WHERE sr.requirement_id = %s
        ORDER BY s.name;
    ''', (requirement_id,))
    linked = cur.fetchall()
    linked_ids = {s['id'] for s in linked}

    cur.execute('SELECT id, name, ip_address FROM servers ORDER BY name;')
    all_servers = cur.fetchall()
    cur.close()
    conn.close()

    available = [s for s in all_servers if s['id'] not in linked_ids]
    return jsonify({'linked': linked, 'available': available})


@app.route('/requirement/<int:requirement_id>/servers/add', methods=['POST'])
def attach_server_to_requirement(requirement_id):
    server_id = clean_int(request.form.get('server_id'))
    if server_id:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO server_requirements (server_id, requirement_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING;
            ''', (server_id, requirement_id))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            cur.close()
            conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


@app.route('/requirement/<int:requirement_id>/servers/remove/<int:server_id>', methods=['POST'])
def detach_server_from_requirement(requirement_id, server_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        DELETE FROM server_requirements WHERE server_id = %s AND requirement_id = %s;
    ''', (server_id, requirement_id))
    conn.commit()
    cur.close()
    conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))



@app.route('/requirement/<int:requirement_id>/is')
def get_requirement_is(requirement_id):
    conn = get_db_connection()
    cur = conn.cursor()
    linked = []
    try:
        cur.execute('''
            SELECT isys.id, isys.name
            FROM system_requirements sysreq
            JOIN information_systems isys ON isys.id = sysreq.is_id
            WHERE sysreq.requirement_id = %s
            ORDER BY isys.name;
        ''', (requirement_id,))
        linked = cur.fetchall()
    except Exception:
        conn.rollback()

    cur.execute('SELECT id, name FROM information_systems ORDER BY name;')
    all_is = cur.fetchall()
    cur.close()
    conn.close()

    linked_ids = {i['id'] for i in linked}
    available = [i for i in all_is if i['id'] not in linked_ids]
    return jsonify({'linked': linked, 'available': available})


@app.route('/requirement/<int:requirement_id>/is/add', methods=['POST'])
def attach_is_to_requirement(requirement_id):
    is_id = clean_int(request.form.get('is_id'))
    if is_id:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO system_requirements (is_id, requirement_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING;
            ''', (is_id, requirement_id))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            cur.close()
            conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


@app.route('/requirement/<int:requirement_id>/is/remove/<int:is_id>', methods=['POST'])
def detach_is_from_requirement(requirement_id, is_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM system_requirements WHERE requirement_id = %s AND is_id = %s;', (requirement_id, is_id))
        conn.commit()
    except Exception:
        conn.rollback()
    cur.close()
    conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


@app.route('/is/<int:is_id>/requirements')
def get_is_requirements(is_id):
    conn = get_db_connection()
    cur = conn.cursor()
    linked = []
    try:
        cur.execute('''
            SELECT r.id, r.code, r.description
            FROM system_requirements sysreq
            JOIN requirements r ON r.id = sysreq.requirement_id
            WHERE sysreq.is_id = %s
            ORDER BY r.code;
        ''', (is_id,))
        linked = cur.fetchall()
    except Exception:
        conn.rollback()

    requirements_all = []
    try:
        cur.execute('SELECT id, code, description FROM requirements ORDER BY code;')
        requirements_all = cur.fetchall()
    except Exception:
        conn.rollback()
    cur.close()
    conn.close()

    linked_ids = {r['id'] for r in linked}
    available = [r for r in requirements_all if r['id'] not in linked_ids]
    return jsonify({'linked': linked, 'available': available})


@app.route('/is/<int:is_id>/requirements/add', methods=['POST'])
def attach_requirement_to_is(is_id):
    requirement_id = clean_int(request.form.get('requirement_id'))
    if requirement_id:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO system_requirements (is_id, requirement_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING;
            ''', (is_id, requirement_id))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            cur.close()
            conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


@app.route('/is/<int:is_id>/requirements/remove/<int:requirement_id>', methods=['POST'])
def detach_requirement_from_is(is_id, requirement_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM system_requirements WHERE is_id = %s AND requirement_id = %s;', (is_id, requirement_id))
        conn.commit()
    except Exception:
        conn.rollback()
    cur.close()
    conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


# Привязка

@app.route('/is/<int:is_id>/servers')
def get_is_servers(is_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, name, ip_address FROM servers WHERE is_id = %s ORDER BY name;', (is_id,))
    linked = cur.fetchall()
    cur.execute('SELECT id, name, ip_address FROM servers WHERE is_id IS DISTINCT FROM %s ORDER BY name;', (is_id,))
    available = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({'linked': linked, 'available': available})


@app.route('/is/<int:is_id>/servers/add', methods=['POST'])
def attach_server_to_is(is_id):
    server_id = clean_int(request.form.get('server_id'))
    if server_id:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE servers SET is_id = %s WHERE id = %s;', (is_id, server_id))
        conn.commit()
        cur.close()
        conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


@app.route('/is/<int:is_id>/servers/remove/<int:server_id>', methods=['POST'])
def detach_server_from_is(is_id, server_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE servers SET is_id = NULL WHERE id = %s AND is_id = %s;', (server_id, is_id))
    conn.commit()
    cur.close()
    conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


# Комментарии

@app.route('/server/<int:server_id>/comments')
def get_comments(server_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT id, author, comment_text, created_at
        FROM comments
        WHERE server_id = %s
        ORDER BY created_at DESC;
    ''', (server_id,))
    comments = cur.fetchall()
    cur.close()
    conn.close()

    for c in comments:
        if c['created_at']:
            c['created_at'] = c['created_at'].strftime('%d.%m.%Y %H:%M')
    return jsonify(comments)


@app.route('/comment/add/<int:server_id>', methods=['POST'])
def add_comment(server_id):
    author = (request.form.get('author') or 'Аноним').strip() or 'Аноним'
    text = (request.form.get('comment_text') or '').strip()

    if text:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO comments (server_id, author, comment_text)
            VALUES (%s, %s, %s);
        ''', (server_id, author, text))
        conn.commit()
        cur.close()
        conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM comments WHERE id = %s;', (comment_id,))
    conn.commit()
    cur.close()
    conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


@app.route('/comments/search')
def search_comments():
    q = (request.args.get('q') or '').strip()
    if not q:
        return jsonify([])

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT c.id, c.author, c.comment_text, c.created_at, c.server_id, s.name AS server_name
        FROM comments c
        JOIN servers s ON s.id = c.server_id
        WHERE c.comment_text ILIKE %s OR c.author ILIKE %s OR s.name ILIKE %s
        ORDER BY c.created_at DESC
        LIMIT 100;
    ''', (f'%{q}%', f'%{q}%', f'%{q}%'))
    results = cur.fetchall()
    cur.close()
    conn.close()

    for r in results:
        if r['created_at']:
            r['created_at'] = r['created_at'].strftime('%d.%m.%Y %H:%M')
    return jsonify(results)


# документы

@app.route('/server/<int:server_id>/attachments')
def get_attachments(server_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''
            SELECT id, original_name, uploaded_at
            FROM attachments WHERE server_id = %s ORDER BY uploaded_at DESC;
        ''', (server_id,))
        rows = cur.fetchall()
    except Exception:
        conn.rollback()
        rows = []
    cur.close()
    conn.close()

    for r in rows:
        if r['uploaded_at']:
            r['uploaded_at'] = r['uploaded_at'].strftime('%d.%m.%Y %H:%M')
    return jsonify(rows)


@app.route('/server/<int:server_id>/attachments/upload', methods=['POST'])
def upload_attachment(server_id):
    file = request.files.get('file')
    if not file or file.filename == '':
        if is_ajax():
            return jsonify({'error': 'Файл не выбран.'}), 400
        flash('Файл не выбран.', 'error')
        return redirect(url_for('index'))

    original_name = file.filename
    safe_name = secure_filename(original_name) or 'file'
    stored_filename = f'{uuid.uuid4().hex}_{safe_name}'
    dest_path = os.path.join(ATTACHMENTS_DIR, stored_filename)
    file.save(dest_path)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO attachments (server_id, original_name, stored_filename)
            VALUES (%s, %s, %s) RETURNING id, original_name, stored_filename, uploaded_at;
        ''', (server_id, original_name, stored_filename))
        row = cur.fetchone()
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        try:
            os.remove(dest_path)
        except OSError:
            pass
        if is_ajax():
            return jsonify({'error': f'Ошибка сохранения (выполнена ли миграция вложений?): {e}'}), 500
        flash(f'Ошибка сохранения файла: {e}', 'error')
        return redirect(url_for('index'))

    cur.close()
    conn.close()

    if row['uploaded_at']:
        row['uploaded_at'] = row['uploaded_at'].strftime('%d.%m.%Y %H:%M')
    if is_ajax():
        return jsonify(row)
    flash('Файл прикреплён.', 'success')
    return redirect(url_for('index'))


@app.route('/attachments/<int:attachment_id>/open')
def open_attachment(attachment_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT stored_filename, original_name FROM attachments WHERE id = %s;', (attachment_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({'error': 'Файл не найден в базе.'}), 404

    path = os.path.join(ATTACHMENTS_DIR, row['stored_filename'])
    if not os.path.exists(path):
        return jsonify({'error': 'Файл отсутствует на диске (возможно, был перемещен вручную).'}), 404

    try:
        os.startfile(path)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': f'Не удалось открыть файл: {e}'}), 500


@app.route('/attachments/<int:attachment_id>/delete', methods=['POST'])
def delete_attachment(attachment_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT stored_filename FROM attachments WHERE id = %s;', (attachment_id,))
    row = cur.fetchone()
    if row:
        cur.execute('DELETE FROM attachments WHERE id = %s;', (attachment_id,))
        conn.commit()
        path = os.path.join(ATTACHMENTS_DIR, row['stored_filename'])
        try:
            os.remove(path)
        except OSError:
            pass
    cur.close()
    conn.close()

    if is_ajax():
        return jsonify({'status': 'ok'})
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
