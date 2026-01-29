import telebot
import sqlite3
import time
import threading
import requests
import re
import urllib.parse
from telebot.types import ChatPermissions

# --------------------------------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------------------------------
# REPLACE WITH YOUR ACTUAL BOT TOKEN
API_TOKEN = '8488403945:AAFUTo8SqhgFIeJ8ehuFa_VNktklnXcPcvs' 

# AI API ENDPOINT (STRICTLY AS REQUESTED)
AI_API_URL = "https://gpt4.apisimpacientes.workers.dev/chat"

# DATABASE FILE
DB_FILE = "group_guard.db"

# ADMIN ID (Optional hardcoded fallback, though dynamic detection is primary)
OWNER_ID = 0 

bot = telebot.TeleBot(API_TOKEN)

# --------------------------------------------------------------------------------
# DATABASE LAYER
# --------------------------------------------------------------------------------
def init_db():
    """Initializes the SQLite database with required tables."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Users Table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    first_name TEXT,
                    warns INTEGER DEFAULT 0,
                    last_seen REAL,
                    is_muted INTEGER DEFAULT 0
                )''')

    # Filters Table
    c.execute('''CREATE TABLE IF NOT EXISTS filters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filter_type TEXT,
                    pattern TEXT,
                    action TEXT,
                    enabled INTEGER DEFAULT 1
                )''')

    # Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    content TEXT,
                    action_taken TEXT,
                    timestamp REAL
                )''')

    # Seed default filters if empty
    c.execute("SELECT count(*) FROM filters")
    if c.fetchone()[0] == 0:
        defaults = [
            ('keyword', 'badword', 'warn', 1),
            ('keyword', 'scam', 'ban', 1),
            ('regex', r'(https?://\S+)', 'warn', 0), # Link filter disabled by default
            ('keyword', 'porn', 'delete', 1),
            ('keyword', 'xxx', 'delete', 1)
        ]
        c.executemany("INSERT INTO filters (filter_type, pattern, action, enabled) VALUES (?, ?, ?, ?)", defaults)
        print("[INFO] Default filters seeded.")

    conn.commit()
    conn.close()

def db_query(query, args=(), fetch_one=False, fetch_all=False, commit=False):
    """Helper to execute DB queries safely."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    res = None
    try:
        c.execute(query, args)
        if commit:
            conn.commit()
        if fetch_one:
            res = c.fetchone()
        if fetch_all:
            res = c.fetchall()
    except Exception as e:
        print(f"[ERROR] DB Error: {e}")
    finally:
        conn.close()
    return res

def log_event(user_id, content, action):
    """Logs actions to the database."""
    db_query("INSERT INTO logs (user_id, content, action_taken, timestamp) VALUES (?, ?, ?, ?)", 
             (user_id, content, action, time.time()), commit=True)

def update_user_activity(user_id, first_name):
    """Updates last seen and ensures user exists."""
    exists = db_query("SELECT 1 FROM users WHERE user_id = ?", (user_id,), fetch_one=True)
    if not exists:
        db_query("INSERT INTO users (user_id, first_name, last_seen) VALUES (?, ?, ?)", 
                 (user_id, first_name, time.time()), commit=True)
    else:
        db_query("UPDATE users SET last_seen = ?, first_name = ? WHERE user_id = ?", 
                 (time.time(), first_name, user_id), commit=True)

# --------------------------------------------------------------------------------
# MODERATION ENGINE
# --------------------------------------------------------------------------------
def get_group_admins(chat_id):
    """Dynamically fetches admin IDs from Telegram."""
    try:
        admins = bot.get_chat_administrators(chat_id)
        return [admin.user.id for admin in admins]
    except Exception as e:
        print(f"[ERROR] Failed to fetch admins: {e}")
        return []

def scan_content(message):
    """
    Scans message content against DB filters.
    Returns: (bool: violation_found, str: action_type)
    """
    text = message.text.lower() if message.text else ""
    if not text:
        return False, None

    filters = db_query("SELECT filter_type, pattern, action FROM filters WHERE enabled = 1", fetch_all=True)
    
    for f_type, pattern, action in filters:
        try:
            if f_type == 'keyword':
                if pattern.lower() in text:
                    return True, action
            elif f_type == 'regex':
                if re.search(pattern, text, re.IGNORECASE):
                    return True, action
        except Exception as e:
            print(f"[ERROR] Filter error ({pattern}): {e}")
            continue
            
    return False, None

def execute_moderation(message, action):
    """Executes the punishment logic."""
    user_id = message.from_user.id
    chat_id = message.chat.id
    name = message.from_user.first_name

    # Always delete the message first for safety
    try:
        bot.delete_message(chat_id, message.message_id)
    except:
        pass # Message might already be gone

    log_event(user_id, message.text, action)

    if action == 'delete':
        # Just delete, maybe a silent log
        pass

    elif action == 'warn':
        db_query("UPDATE users SET warns = warns + 1 WHERE user_id = ?", (user_id,), commit=True)
        user_data = db_query("SELECT warns FROM users WHERE user_id = ?", (user_id,), fetch_one=True)
        warns = user_data[0] if user_data else 1
        
        bot.send_message(chat_id, f"⚠️ User {name} warned. Reason: Policy Violation. Count: {warns}/3")
        
        if warns >= 3:
            mute_user(chat_id, user_id, 10, name) # Auto mute 10 mins

    elif action == 'mute':
        mute_user(chat_id, user_id, 60, name) # Immediate mute

    elif action == 'ban':
        try:
            bot.ban_chat_member(chat_id, user_id)
            bot.send_message(chat_id, f"🚫 User {name} has been banned for severe violation.")
        except Exception as e:
            bot.send_message(chat_id, f"❌ Failed to ban user: {e}")

def mute_user(chat_id, user_id, minutes, name):
    """Mutes a user for X minutes."""
    try:
        until = time.time() + (minutes * 60)
        permissions = ChatPermissions(can_send_messages=False)
        bot.restrict_chat_member(chat_id, user_id, until_date=until, permissions=permissions)
        
        db_query("UPDATE users SET is_muted = 1, warns = 0 WHERE user_id = ?", (user_id,), commit=True)
        bot.send_message(chat_id, f"🔇 User {name} muted for {minutes} minutes due to repeated violations.")
    except Exception as e:
        print(f"[ERROR] Mute failed: {e}")

# --------------------------------------------------------------------------------
# AI CHAT LOGIC
# --------------------------------------------------------------------------------
def get_ai_reply(user_text):
    """Fetches response from the configured worker API."""
    system_prompt = (
        "You are a Senior Python Developer and Technical Mentor. "
        "Your goal is to be logical, direct, and explanatory. "
        "Do not use jokes, emojis, or fake positivity. "
        "If a user is wrong, explain why technically. "
        "Keep responses concise and professional."
    )
    
    full_prompt = f"{system_prompt}\n\nUser: {user_text}\nAnswer:"
    encoded_prompt = urllib.parse.quote(full_prompt)
    
    try:
        # Using GET as requested with encoded prompt
        url = f"{AI_API_URL}?question={encoded_prompt}&model=gpt-4"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Logic error: External compute resource unavailable."
    except Exception:
        return "System error: Unable to process logic request at this time."

# --------------------------------------------------------------------------------
# COMMAND HANDLERS
# --------------------------------------------------------------------------------

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, 
                 "System Online.\n"
                 "Role: Group Moderation & Technical Assistance.\n"
                 "Commands: /me, /warn, /mute, /ban, /filters.\n"
                 "Maintain professional conduct.")

@bot.message_handler(commands=['me'])
def user_status(message):
    u_id = message.from_user.id
    data = db_query("SELECT warns, last_seen, is_muted FROM users WHERE user_id = ?", (u_id,), fetch_one=True)
    
    if data:
        warns, last, muted = data
        last_fmt = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last))
        status = "Muted" if muted else "Active"
        response = (f"User Report for {message.from_user.first_name}:\n"
                    f"ID: {u_id}\n"
                    f"Status: {status}\n"
                    f"Warnings: {warns}\n"
                    f"Last Active: {last_fmt}")
        bot.reply_to(message, response)
    else:
        bot.reply_to(message, "No data found. Interaction initialized.")

# ADMIN COMMANDS
@bot.message_handler(commands=['warn'])
def admin_warn(message):
    if message.chat.type == "private": return
    if message.from_user.id not in get_group_admins(message.chat.id):
        return # Silent ignore for non-admins

    if not message.reply_to_message:
        bot.reply_to(message, "Syntax error: Command must reply to a user.")
        return

    target_id = message.reply_to_message.from_user.id
    target_name = message.reply_to_message.from_user.first_name
    
    # Manual warn triggers logic (increment -> check threshold -> mute)
    # We reuse execute_moderation but force 'warn'
    # Note: We don't delete the message on manual warn unless specified, 
    # but here we just increment counter.
    
    db_query("UPDATE users SET warns = warns + 1 WHERE user_id = ?", (target_id,), commit=True)
    user_data = db_query("SELECT warns FROM users WHERE user_id = ?", (target_id,), fetch_one=True)
    warns = user_data[0] if user_data else 1
    
    bot.reply_to(message, f"⚠️ Manual warning issued to {target_name}. Count: {warns}/3")
    
    if warns >= 3:
        mute_user(message.chat.id, target_id, 10, target_name)

@bot.message_handler(commands=['mute'])
def admin_mute(message):
    if message.from_user.id not in get_group_admins(message.chat.id): return

    if not message.reply_to_message:
        bot.reply_to(message, "Syntax error: Reply to a user.")
        return
        
    args = message.text.split()
    minutes = 10 # default
    if len(args) > 1 and args[1].isdigit():
        minutes = int(args[1])

    target_id = message.reply_to_message.from_user.id
    target_name = message.reply_to_message.from_user.first_name
    mute_user(message.chat.id, target_id, minutes, target_name)

@bot.message_handler(commands=['unmute'])
def admin_unmute(message):
    if message.from_user.id not in get_group_admins(message.chat.id): return
    if not message.reply_to_message: return

    target_id = message.reply_to_message.from_user.id
    permissions = ChatPermissions(can_send_messages=True, can_send_media_messages=True)
    
    try:
        bot.restrict_chat_member(message.chat.id, target_id, permissions=permissions)
        db_query("UPDATE users SET is_muted = 0, warns = 0 WHERE user_id = ?", (target_id,), commit=True)
        bot.reply_to(message, f"User {message.reply_to_message.from_user.first_name} privileges restored.")
    except Exception as e:
        bot.reply_to(message, f"Error: {e}")

@bot.message_handler(commands=['filters'])
def list_filters(message):
    if message.from_user.id not in get_group_admins(message.chat.id): return
    
    filters = db_query("SELECT id, filter_type, pattern, action FROM filters", fetch_all=True)
    if not filters:
        bot.reply_to(message, "No filters defined.")
        return
        
    resp = "Active Filters:\n"
    for f in filters:
        resp += f"{f[0]}. [{f[1]}] '{f[2]}' -> {f[3]}\n"
    bot.reply_to(message, resp)

@bot.message_handler(commands=['add_filter'])
def add_filter(message):
    # Usage: /add_filter keyword badword warn
    if message.from_user.id not in get_group_admins(message.chat.id): return
    
    try:
        parts = message.text.split(maxsplit=3)
        if len(parts) < 4:
            bot.reply_to(message, "Syntax: /add_filter <type> <pattern> <action>")
            return
            
        f_type, pattern, action = parts[1], parts[2], parts[3]
        if f_type not in ['keyword', 'regex'] or action not in ['warn', 'delete', 'mute', 'ban']:
             bot.reply_to(message, "Invalid parameters. Type: keyword/regex. Action: warn/delete/mute/ban.")
             return
             
        db_query("INSERT INTO filters (filter_type, pattern, action, enabled) VALUES (?, ?, ?, 1)", 
                 (f_type, pattern, action), commit=True)
        bot.reply_to(message, "Filter added successfully.")
    except Exception as e:
        bot.reply_to(message, f"Database error: {e}")

# --------------------------------------------------------------------------------
# MAIN MESSAGE HANDLER (CHAT & MODERATION)
# --------------------------------------------------------------------------------
@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    # 1. Update User DB
    update_user_activity(message.from_user.id, message.from_user.first_name)
    
    # 2. Check Admin Status
    admins = get_group_admins(message.chat.id)
    is_admin = message.from_user.id in admins

    # 3. Content Scanning (Admins are usually exempt from auto-punishment, but we scan for logs/safety)
    # If you want strict safety even for admins, remove the 'if not is_admin' check for execution.
    violation, action = scan_content(message)
    
    if violation and not is_admin:
        execute_moderation(message, action)
        return # Stop processing, do not chat
    
    # 4. Chat System
    # Only chat if: Not a violation, Message is text, Not a command (handled above), Not just an emoji
    if message.text and not message.text.startswith('/'):
        
        # Simple heuristic to ignore short noise/emojis
        if len(message.text) < 4: 
            return

        # Rate limiting logic could go here (omitted for brevity)
        
        # Determine if bot should reply. 
        # For a personal group bot, it might reply to mentions or reply_to_message pointing at it.
        # OR randomly for engagement. 
        # Here: Reply if replied to OR mentioned, OR randomly (10% chance) to be a "Mentor".
        
        should_reply = (f"@{bot.get_me().username}" in message.text) or \
                       (message.reply_to_message and message.reply_to_message.from_user.id == bot.get_me().id)
        
        if should_reply:
            bot.send_chat_action(message.chat.id, 'typing')
            
            # Use threading to not block the polling loop during API call
            def chat_thread():
                reply = get_ai_reply(message.text)
                try:
                    bot.reply_to(message, reply)
                except Exception as e:
                    print(f"Send error: {e}")
            
            threading.Thread(target=chat_thread).start()

# --------------------------------------------------------------------------------
# ENTRY POINT
# --------------------------------------------------------------------------------
if __name__ == "__main__":
    print("--- SYSTEM BOOT ---")
    print("Initializing Database...")
    init_db()
    print("Database Mounted.")
    print("Loading Filters...")
    print("Starting Polling Loop...")
    
    while True:
        try:
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            print(f"Network Error: {e}")
            time.sleep(5)
      
