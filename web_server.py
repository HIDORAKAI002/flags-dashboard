# web_server.py
from flask import Flask, request, redirect, render_template, session, jsonify
from flask_socketio import SocketIO
import requests
from threading import Thread
import psycopg2
from psycopg2 import pool
import os
from functools import wraps
from datetime import datetime, timezone
import io
import json
import urllib.parse as up

# --- CONFIGURATION ---
# These are now loaded SECURELY from the hosting environment (Render)
# DO NOT put actual keys here. Use the Render Dashboard to set them.
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
BOT_TOKEN = os.environ.get("BOT_TOKEN")
SECRET_KEY = os.environ.get("SECRET_KEY", "default_insecure_key_for_dev")
HCAPTCHA_SECRET_KEY = os.environ.get("HCAPTCHA_SECRET_KEY")
PRIMARY_DOMAIN = os.environ.get("PRIMARY_DOMAIN", "http://127.0.0.1:5000")

# Derived configurations
REDIRECT_URI = f"{PRIMARY_DOMAIN}/callback"
BOT_INVITE_URL = f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}&permissions=8&scope=bot%20applications.commands"

# --- DATABASE SETUP ---
DB_URL = os.environ.get("DB_URL")

db_pool = None
if DB_URL:
    try:
        # Parse the DB_URL to get connection details
        up.uses_netloc.append("postgres")
        url = up.urlparse(DB_URL)
        db_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1, maxconn=10,
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
        print("Web Server: Connected to Database.")
    except Exception as e:
        print(f"Web Server: Failed to connect to DB: {e}")
else:
    print("Web Server: DB_URL not set.")

# --- FLASK SETUP ---
app = Flask(__name__)
app.secret_key = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*")

# --- COMMAND LISTS (Synced with Bot) ---
MOD_COMMANDS = ['kick', 'ban', 'unban', 'timeout', 'clear', 'lock', 'unlock', 'fping', 'jail', 'unjail']
UTILITY_COMMANDS = [
    'todchannel', 'flagstop', 'flagskip', 'birthday_channel', 'difficulty',
    'flaglog', 'welcomec', 'lightmode', 'demonmode', 'muteai', 'unmuteai',
    'highlights', 'gstart', 'greroll', 'gend', 'resetoffenses',
    'professormode', 'stoicmode', 'robotmode', 'genzmode', 'dadjokemode',
    'butlermode', 'gladosmode', 'eboymode', 'partnermode',
    'logging setup', 'logging disable', 'logging all',
    'automod set-log-channel', 'automod image-only',
    'counting setup', 'counting disable',
    'gw-monitor set-bots', 'gw-monitor set-channel-time',
    'interview', 'jail_role', 'ping_limit',
    'scavenger begin', 'scavenger end', 'scavenger frequency',
    'follow anime', 'unfollow anime',
    'tts_watch', 'tts_unwatch', 'dossier'
]
MANAGEABLE_COMMANDS = MOD_COMMANDS + UTILITY_COMMANDS

# --- HELPERS ---

def get_db():
    if not db_pool: return None
    return db_pool.getconn()

def return_db(conn):
    if conn and db_pool: db_pool.putconn(conn)

def discord_api_request(endpoint, method="GET", data=None):
    """Makes a request to Discord API using the BOT token."""
    if not BOT_TOKEN:
        print("Error: BOT_TOKEN is missing")
        return None
        
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    url = f"https://discord.com/api/v10{endpoint}"
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=data)
        
        if resp.status_code in [200, 201]:
            return resp.json()
        else:
            print(f"Discord API Error {resp.status_code}: {resp.text}")
            return None
    except Exception as e:
        print(f"Discord API Request Failed: {e}")
        return None

def get_bot_info():
    """Fetches bot user info from API."""
    data = discord_api_request("/users/@me")
    if data:
        return { "name": data['username'], "avatar_url": f"https://cdn.discordapp.com/avatars/{data['id']}/{data['avatar']}.png" }
    return { "name": "FLAG'S", "avatar_url": "https://cdn.discordapp.com/embed/avatars/0.png" }

# --- DECORATORS ---
def captcha_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_human'): return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/')
def home():
    bot_info = get_bot_info()
    user_info = { "name": session.get('user_name'), "avatar_url": session.get('avatar_url') } if 'user_id' in session else None
    return render_template('homepage.html', bot_info=bot_info, user=user_info, bot_invite_url=BOT_INVITE_URL)

@app.route('/verify-captcha', methods=['POST'])
def verify_captcha():
    data = request.get_json()
    token = data.get('token')
    if not token: return jsonify({'success': False, 'error': 'No token provided.'}), 400
    
    if not HCAPTCHA_SECRET_KEY:
        print("Error: HCAPTCHA_SECRET_KEY is missing")
        return jsonify({'success': False, 'error': 'Server config error'}), 500

    resp = requests.post('https://api.hcaptcha.com/siteverify', data={'secret': HCAPTCHA_SECRET_KEY, 'response': token})
    result = resp.json()
    
    if result.get('success'):
        session['is_human'] = True
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/login')
def login():
    scopes = "identify guilds"
    return redirect(
        f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={scopes.replace(' ', '%20')}"
    )

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code: return "<h1>Error: No code.</h1>", 400

    # Exchange Code
    data = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    token_resp = requests.post('https://discord.com/api/v10/oauth2/token', data=data, headers=headers)
    if token_resp.status_code != 200: return f"Auth Error: {token_resp.text}"
    
    session['access_token'] = token_resp.json()['access_token']

    # Get User Info
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    user_resp = requests.get('https://discord.com/api/v10/users/@me', headers=headers)
    user_data = user_resp.json()
    
    session['user_id'] = user_data['id']
    session['user_name'] = user_data['username']
    session['avatar_url'] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
    session['is_human'] = True # Auto-verify on login

    return redirect('/select-server')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard-auth')
def dashboard_auth():
    if 'user_id' in session: return redirect('/select-server')
    return redirect('/login')

@app.route('/select-server')
@login_required
def select_server():
    # Get user's guilds
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    try:
        user_guilds = requests.get('https://discord.com/api/v10/users/@me/guilds', headers=headers).json()
    except Exception as e:
        return f"Failed to fetch guilds: {e}", 500
    
    # Filter: User is admin & Bot is in server
    conn = get_db()
    if not conn: return "Database Error", 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT guild_id FROM guilds")
            bot_guild_ids = {row[0] for row in cursor.fetchall()}
    finally:
        return_db(conn)

    manageable_servers = []
    if isinstance(user_guilds, list):
        for g in user_guilds:
            # Check MANAGE_GUILD (0x20) permission
            if (int(g['permissions']) & 0x20) == 0x20 and g['id'] in bot_guild_ids:
                manageable_servers.append({
                    "id": g['id'],
                    "name": g['name'],
                    "icon_url": f"https://cdn.discordapp.com/icons/{g['id']}/{g['icon']}.png" if g['icon'] else "https://cdn.discordapp.com/embed/avatars/0.png"
                })

    return render_template(
        'select_server.html', 
        servers=manageable_servers, 
        user={"name": session['user_name'], "avatar_url": session['avatar_url']},
        bot_info=get_bot_info()
    )

@app.route('/dashboard/<int:guild_id>')
@login_required
def dashboard(guild_id):
    # Get Server Info via API
    guild_data = discord_api_request(f"/guilds/{guild_id}")
    if not guild_data: return "Bot not in server or API Error", 404

    server_info = {
        "id": guild_id, 
        "name": guild_data['name'], 
        "icon_url": f"https://cdn.discordapp.com/icons/{guild_data['id']}/{guild_data['icon']}.png" if guild_data['icon'] else "https://cdn.discordapp.com/embed/avatars/0.png"
    }
    
    # Load Settings from DB
    conn = get_db()
    if not conn: return "Database Connection Error", 500

    try:
        with conn.cursor() as cursor:
            # 1. Settings
            cursor.execute("SELECT * FROM guilds WHERE guild_id = %s", (str(guild_id),))
            row = cursor.fetchone()
            if row:
                cols = [desc[0] for desc in cursor.description]
                guild_settings = dict(zip(cols, row))
            else:
                # Defaults
                guild_settings = {'welcome_message': 'Welcome {user}!', 'welcome_text_color': '#FFFFFF'}

            # 2. Leaderboard
            cursor.execute("SELECT user_id, score FROM users WHERE guild_id = %s ORDER BY score DESC LIMIT 10", (str(guild_id),))
            lb_raw = cursor.fetchall()

            # 3. Permissions
            cursor.execute("SELECT command_name, role_id FROM command_permissions WHERE guild_id = %s", (str(guild_id),))
            perms_raw = cursor.fetchall()
            current_permissions = {}
            for cmd, role in perms_raw:
                if cmd not in current_permissions: current_permissions[cmd] = []
                current_permissions[cmd].append(role)

    finally:
        return_db(conn)

    # Fetch Channels & Roles via API
    channels_data = discord_api_request(f"/guilds/{guild_id}/channels") or []
    roles_data = discord_api_request(f"/guilds/{guild_id}/roles") or []

    # Filter text channels
    text_channels = sorted([c for c in channels_data if c['type'] == 0], key=lambda x: x['name'])
    # Sort roles
    all_roles = sorted(roles_data, key=lambda x: x['position'], reverse=True)
    formatted_roles = [{'id': r['id'], 'name': r['name'], 'color': f"#{r['color']:06x}"} for r in all_roles]

    # Process Leaderboard Names
    leaderboard_data = []
    for uid, score in lb_raw:
        u_data = discord_api_request(f"/users/{uid}")
        if u_data:
            leaderboard_data.append({"name": u_data['username'], "avatar_url": f"https://cdn.discordapp.com/avatars/{u_data['id']}/{u_data['avatar']}.png", "score": score})
        else:
            leaderboard_data.append({"name": "Unknown", "avatar_url": "", "score": score})

    ai_questions_text = ""
    if guild_settings.get('ai_intro_questions'):
        try:
            q_list = json.loads(guild_settings['ai_intro_questions'])
            ai_questions_text = "\n".join(q_list)
        except: pass

    return render_template('dashboard.html', 
        server=server_info, user={"name": session['user_name'], "avatar_url": session['avatar_url']},
        settings=guild_settings, channels=text_channels, all_roles=formatted_roles,
        leaderboard=leaderboard_data, mod_commands=MOD_COMMANDS, utility_commands=UTILITY_COMMANDS,
        current_permissions=current_permissions, ai_questions_text=ai_questions_text
    )

@app.route('/dashboard/<int:guild_id>/update', methods=['POST'])
@login_required
def update_dashboard(guild_id):
    conn = get_db()
    if not conn: return "Database Error", 500

    try:
        with conn.cursor() as cursor:
            questions_text = request.form.get('ai_intro_questions')
            questions_json = json.dumps([q.strip() for q in questions_text.split('\n') if q.strip()]) if questions_text else None
            
            # Basic updates (Add other fields as needed)
            cursor.execute("""
                UPDATE guilds SET 
                log_channel = %s, 
                welcome_channel_id = %s, 
                ai_intro_questions = %s,
                welcome_banner_enabled = %s,
                welcome_message = %s,
                welcome_text_color = %s,
                ai_intro_enabled = %s,
                ai_intro_channel_id = %s,
                bot_mode = %s,
                difficulty = %s,
                tod_channel_id = %s
                WHERE guild_id = %s
            """, (
                request.form.get('log_channel') or None,
                request.form.get('welcome_channel_id') or None,
                questions_json,
                'welcome_banner_enabled' in request.form,
                request.form.get('welcome_message'),
                request.form.get('welcome_text_color'),
                'ai_intro_enabled' in request.form,
                request.form.get('ai_intro_channel_id') or None,
                request.form.get('bot_mode'),
                request.form.get('difficulty'),
                request.form.get('tod_channel_id') or None,
                str(guild_id)
            ))
            
            # Permissions
            cursor.execute("DELETE FROM command_permissions WHERE guild_id = %s", (str(guild_id),))
            for cmd in MANAGEABLE_COMMANDS:
                roles = request.form.getlist(f'permissions_{cmd}')
                for r in roles:
                    cursor.execute("INSERT INTO command_permissions (guild_id, command_name, role_id) VALUES (%s, %s, %s)", (str(guild_id), cmd, r))

        conn.commit()
    except Exception as e:
        print(f"Update Error: {e}")
        if conn: conn.rollback()
    finally:
        return_db(conn)
        
    return redirect(f'/dashboard/{guild_id}')

@app.route('/terms')
def terms(): return render_template('tos.html', bot_info=get_bot_info())

@app.route('/privacy')
def privacy(): return render_template('privacy.html', bot_info=get_bot_info())

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)