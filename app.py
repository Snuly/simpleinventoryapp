from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta, datetime


app = Flask(__name__)
app.secret_key = '58195673'

# CSRF protection
csrf = CSRFProtect(app)

# Brute force protection
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Session expiration timer
app.permanent_session_lifetime = timedelta(minutes=30)

# Local time converter
def convert_to_local_time(utc_time):
    if utc_time:
        local_time = utc_time + timedelta(hours=2)
        return local_time.strftime('%Y-%m-%d, %H:%M:%S')
    return "N/A"

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
    search_query = request.args.get('search', '').strip()

    try:
        conn = get_db_connection()
        query = "SELECT * FROM inventory"
        params = []

        if search_query:
            query += " WHERE name LIKE ?"
            params.append('%' + search_query + '%')

        if sort_option == 'asc':
            query += " ORDER BY quantity ASC"
        elif sort_option == 'desc':
            query += " ORDER BY quantity DESC"
        else:
            query += " ORDER BY name ASC"

        items = conn.execute(query, tuple(params)).fetchall()

        # Process the items and return the response
        updated_items = []
        for item in items:
            item_dict = dict(item)
            if item_dict['last_modified_by']:
                cursor = conn.execute("SELECT username FROM users WHERE id = ?", (item_dict['last_modified_by'],))
                result = cursor.fetchone()
                item_dict['last_modified_by_username'] = result['username'] if result else "N/A"
            else:
                item_dict['last_modified_by_username'] = "N/A"
            if item_dict.get('last_modified_at'):
                try:
                    last_modified_date = datetime.strptime(item_dict['last_modified_at'], '%Y-%m-%d %H:%M:%S')
                    item_dict['last_modified_at'] = last_modified_date
                except ValueError:
                    item_dict['last_modified_at'] = None
            updated_items.append(item_dict)

        conn.close()


        return render_template('dashboard.html', items=updated_items, is_admin=admin_status, convert_to_local_time=convert_to_local_time)
    except Exception as e:
        app.logger.error(f"Error in dashboard route: {e}")
        return "An error occurred while processing your request.", 500


# Add Item Route
@app.route('/add_item', methods=['POST'])
def add_item():
    if 'user_id' not in session:
        flash("Jums jāpieslēdzas!", "warning")
        return redirect(url_for('login'))

    name = request.form['name']
    quantity = request.form['quantity']
    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the item already exists
    cursor.execute("SELECT * FROM inventory WHERE name = ?", (name,))
    existing_item = cursor.fetchone()

    if existing_item:
        new_quantity = existing_item['quantity'] + int(quantity)
        cursor.execute("UPDATE inventory SET quantity = ?, last_modified_by = ?, last_modified_at = CURRENT_TIMESTAMP WHERE id = ?", 
                       (new_quantity, user_id, existing_item['id']))
    else:
        cursor.execute("INSERT INTO inventory (name, quantity, last_modified_by) VALUES (?, ?, ?)", 
                       (name, quantity, user_id))

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

        # Check username requirements
        if len(username) < 3:
            flash("Lietotājvārdam jābūt vismaz 3 rakstzīmēm!", "danger")
            return redirect(url_for('add_user'))
        elif len(username) > 25:
            flash("Lietotājvārdam jābūt īsākam!", "danger")
            return redirect(url_for('add_user'))
    
        # Check password requirements
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

# View all users tab
@app.route('/view_users')
def view_users():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Jums nav atļaujas skatīt šo lapu.", "danger")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template('view_users.html', users=users)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash("Vajag pieslēgties lai mainītu paroli!", "warning")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        # Get current user's data
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()

        # Check if the old password is correct
        if not check_password_hash(user['password'], old_password):
            flash("Vecā parole ir nepareiza!", "danger")
            return redirect(url_for('change_password'))

        # Check password requirements
        if len(new_password) < 8 or not any(c.isdigit() for c in new_password) or not any(c in "!@#$%^&*" for c in new_password):
            flash("Parolei jābūt vismaz 8 rakstzīmēm, vienam ciparam un vienam simbolam", "danger")
            return redirect(url_for('change_password'))
        elif len(new_password) > 25:
            flash("Parolei jābūt īsākai!", "danger")
            return redirect(url_for('change_password'))

        # Update password
        hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, session['user_id']))
        conn.commit()
        conn.close()

        flash("Parole mainīta!", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

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

# Item quantity updater
@app.route('/update_quantity', methods=['POST'])
def update_quantity():
    if 'user_id' not in session:
        flash("Lūdzu, piesakieties, lai veiktu izmaiņas.", "warning")
        return redirect(url_for('login'))

    item_id = request.form.get('item_id')
    new_quantity = request.form.get('quantity')
    user_id = session['user_id']

    if not item_id or not new_quantity.isdigit():
        flash("Nederīga ievade!", "danger")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE inventory SET quantity = ?, last_modified_by = ?, last_modified_at = CURRENT_TIMESTAMP WHERE id = ?", 
                   (int(new_quantity), user_id, item_id))
    conn.commit()
    conn.close()

    flash("Daudzums atjaunināts!", "success")
    return redirect(url_for('dashboard'))

# Password change function
@app.route('/reset_password', methods=['POST'])
def reset_password():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Jums nav atļaujas veikt šo darbību.", "danger")
        return redirect(url_for('dashboard'))

    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')

    if not user_id or not new_password:
        flash("Lūdzu ievadiet jauno paroli.", "danger")
        return redirect(url_for('view_users'))

    hashed_password = generate_password_hash(new_password)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
    conn.commit()
    conn.close()

    flash("Lietotāja parole atjaunināta!", "success")
    return redirect(url_for('view_users'))

# Session handler
@app.before_request
def check_session_timeout():
    session.modified = True  # Updates session timer on user activity
    if 'user_id' not in session:
        if request.endpoint not in ['login', 'static']:
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
            quantity INTEGER NOT NULL,
            last_modified_by INTEGER,
            last_modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (last_modified_by) REFERENCES users (id)
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
