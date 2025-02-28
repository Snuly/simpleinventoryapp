from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta


app = Flask(__name__)
app.secret_key = '58195673'

# CSRF protection
csrf = CSRFProtect(app)

# Brute force protection
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Session expiration timer
app.permanent_session_lifetime = timedelta(minutes=30)


# Database connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Home Route
@app.route('/')
def home():
    return redirect(url_for('login'))

# Flask limiter error page
@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('rate_limited.html'), 429

# Login Route
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Limits to 5 attempts per minute
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user is None:
            flash("Lietotājs nav atrasts!", "danger")
        elif not check_password_hash(user['password'], password):
            flash("Nepareiza parole!", "danger")
        else:
            session['user_id'] = user['id']
            flash("Veiksmīga pievienošanās!", "success")
            conn.close()
            return redirect(url_for('dashboard'))

        conn.close()

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Jūs esat izgājis!", "info")
    return redirect(url_for('login'))

# Admin check
def is_admin(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user['is_admin'] == 1 

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Jums jāpieslēdzas!", "warning")
        return redirect(url_for('login'))

    admin_status = is_admin(session['user_id'])
    
    sort_option = request.args.get('sort', 'alphabet')
    
    conn = get_db_connection()
    if sort_option == 'asc':
        # Sort by ascending
        items = conn.execute("SELECT * FROM inventory ORDER BY quantity ASC").fetchall()
    elif sort_option == 'desc':
        # Sort by descending
        items = conn.execute("SELECT * FROM inventory ORDER BY quantity DESC").fetchall()
    else:
        # Default sorting (alphabetical)
        items = conn.execute("SELECT * FROM inventory ORDER BY name ASC").fetchall()
    conn.close()

    return render_template('dashboard.html', items=items, is_admin=admin_status)

# Add Item Route
@app.route('/add_item', methods=['POST'])
def add_item():
    if 'user_id' not in session:
        flash("Jums jāpieslēdzas!", "warning")
        return redirect(url_for('login'))

    name = request.form['name']
    quantity = request.form['quantity']

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if the item already exists
    cursor.execute("SELECT * FROM inventory WHERE name = ?", (name,))
    existing_item = cursor.fetchone()

    if existing_item:
        new_quantity = existing_item['quantity'] + int(quantity)
        cursor.execute("UPDATE inventory SET quantity = ? WHERE id = ?", (new_quantity, existing_item['id']))
    else:
        cursor.execute("INSERT INTO inventory (name, quantity) VALUES (?, ?)", (name, quantity))

    conn.commit()
    conn.close()

    flash("Prece pievienota vai atjaunināta!", "success")
    return redirect(url_for('dashboard'))

# Delete Item Route
@app.route('/delete_item/<int:item_id>')
def delete_item(item_id):
    if 'user_id' not in session:
        flash("Jums jāpieslēdzas!", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inventory WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

    flash("Prece dzēsta!", "success")
    return redirect(url_for('dashboard'))

# Add user function
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Tikai administratori var pievienot lietotājus!", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        admin = request.form.get('is_admin')

        if admin == "on":
            admin = 1
        else:
            admin = 0

        if len(username) < 3:
            flash("Lietotājvārdam jābūt vismaz 3 rakstzīmēm!", "danger")
            return redirect(url_for('add_user'))
        elif len(username) > 25:
            flash("Lietotājvārdam jābūt īsākam!", "danger")
            return redirect(url_for('add_user'))

        if len(password) < 8 or not any(c.isdigit() for c in password) or not any(c in "!@#$%^&*" for c in password):
            flash("Parolei jābūt vismaz 8 rakstzīmēm, vienam ciparam un vienam simbolam", "danger")
            return redirect(url_for('add_user'))
        elif len(password) > 25:
            flash("Parolei jābūt īsākai!", "danger")
            return redirect(url_for('add_user'))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("Lietotājvārds jau eksistē!", "danger")
                return redirect(url_for('add_user'))

            # Insert new user
            cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", (username, hashed_password, admin))
            conn.commit()
            flash("Jauns lietotājs pievienots!", "success")
            return redirect(url_for('dashboard'))
        finally:
            conn.close()

    return render_template('add_user.html')

# Autocomplete
@app.route('/autocomplete', methods=['GET'])
def autocomplete():
    query = request.args.get('query', '')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM inventory WHERE name LIKE ? LIMIT 5", (f"%{query}%",))
    results = [row['name'] for row in cursor.fetchall()]
    conn.close()

    return jsonify(results)

# Session handler
@app.before_request
def check_session_timeout():
    session.modified = True  # Updates session timer on user activity
    if 'user_id' not in session:
        if request.endpoint not in ['login', 'static']:
            flash("Your session has expired. Please log in again.", "warning")
            return redirect(url_for('login'))




def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INT NOT NULL
        )
    ''')

    # Create Inventory Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            quantity INTEGER NOT NULL
        )
    ''')

    # Insert an admin user
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        hashed_password = generate_password_hash("admin")
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("admin", hashed_password, 1))

    conn.commit()
    conn.close()



if __name__ == '__main__':
    init_db()
    app.run(debug=True)
