from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '58195673'

# Database connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Home Route
@app.route('/')
def home():
    return redirect(url_for('login'))

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user is None:
            flash("Lietotājs nav atrasts!", "danger")
        elif not check_password_hash(user['password'], password):
            flash("Nepareiza parole!", "danger")
        else:
            flash("Veiksmīga pievienošanās!", "success")
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Jūs esat atteicies!", "info")
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Jums jāpieslēdzas!", "warning")
        return redirect(url_for('login'))

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

    return render_template('dashboard.html', items=items)

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

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
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
        hashed_password = generate_password_hash("test123")
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed_password))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
