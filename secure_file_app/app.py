import os
import io
from datetime import datetime
from functools import wraps

from flask import Flask, request, send_file, redirect, url_for, session, render_template
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db_test import Base, User, EncryptedFile
from crypto_utils import encrypt_bytes, decrypt_bytes, hash_password, verify_password

# ----------------------
# 🔧 App Configuration
# ----------------------
app = Flask(__name__)
app.secret_key = 'change_this_to_a_strong_secret_key'

# Database setup
db_path = os.path.abspath("files.db")
engine = create_engine(f"sqlite:///{db_path}", echo=True)
SessionLocal = sessionmaker(bind=engine)

# ----------------------
# 🔒 Login Decorator
# ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------
# 🔐 Register
# ----------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = SessionLocal()
        existing_user = db.query(User).filter_by(username=username).first()
        if existing_user:
            db.close()
            return "Username already exists. <a href='/register'>Try again</a>"

        hashed = hash_password(password)
        new_user = User(username=username, password=hashed)
        db.add(new_user)
        db.commit()
        db.close()
        return redirect(url_for('login'))

    return render_template('register.html')

# ----------------------
# 🔐 Login
# ----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = SessionLocal()
        user = db.query(User).filter_by(username=username).first()
        db.close()

        if user and verify_password(password, user.password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('home'))
        return "Invalid username or password. <a href='/login'>Try again</a>"

    return render_template('login.html')

# ----------------------
# 🚪 Logout
# ----------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------------------
# 🏠 Home / Upload Page
# ----------------------
@app.route('/')
@login_required
def home():
    return render_template('upload.html', username=session['username'])

# ----------------------
# 📤 Upload
# ----------------------
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return "No file uploaded", 400

    file_bytes = uploaded_file.read()
    encrypted_data = encrypt_bytes(file_bytes)

    db = SessionLocal()
    new_file = EncryptedFile(
        filename=uploaded_file.filename,
        data=encrypted_data,
        user_id=session["user_id"]
    )
    db.add(new_file)
    db.commit()
    db.close()

    return redirect(url_for('list_files'))

# ----------------------
# 📁 List Files
# ----------------------
@app.route('/files')
@login_required
def list_files():
    db = SessionLocal()
    user_files = db.query(EncryptedFile).filter_by(user_id=session["user_id"]).all()
    db.close()

    return render_template('files.html', files=user_files, username=session['username'])

# ----------------------
# ⬇️ Download File
# ----------------------
@app.route('/download/<file_id>')
@login_required
def download(file_id):
    db = SessionLocal()
    file_record = db.query(EncryptedFile).filter_by(id=file_id, user_id=session["user_id"]).first()
    db.close()

    if not file_record:
        return "File not found or access denied", 403

    decrypted_data = decrypt_bytes(file_record.data)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_record.filename
    )

# ----------------------
# 👁️ View File (Decrypted Text)
# ----------------------
@app.route('/view/<file_id>')
@login_required
def view_file(file_id):
    print(f"[DEBUG] Viewing file with ID: {file_id}")
    db = SessionLocal()
    file_record = db.query(EncryptedFile).filter_by(id=file_id, user_id=session["user_id"]).first()
    db.close()

    if not file_record:
        print("[ERROR] File not found or user does not own it")
        return "File not found or access denied", 403

    try:
        decrypted_data = decrypt_bytes(file_record.data)
        print(f"[DEBUG] Raw decrypted bytes: {repr(decrypted_data[:100])}...")  # show first 100 bytes
        text_content = decrypted_data.decode('utf-8', errors='replace').strip()
        print(f"[DEBUG] Decoded text content: {repr(text_content[:100])}...")  # show first 100 characters

        if not text_content:
            return render_template('view.html', filename=file_record.filename,
                                   content="⚠️ This file has no readable text or is empty.")
    except Exception as e:
        print(f"[ERROR] Decryption or decoding failed: {str(e)}")
        return render_template('view.html', filename=file_record.filename,
                               content=f"⚠️ Error decrypting or decoding this file: {str(e)}")

    return render_template('view.html', filename=file_record.filename, content=text_content)

# ----------------------
# 🗑️ Delete File
# ----------------------
@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    db = SessionLocal()
    file_record = db.query(EncryptedFile).filter_by(id=file_id, user_id=session["user_id"]).first()

    if not file_record:
        db.close()
        return "File not found or access denied", 403

    db.delete(file_record)
    db.commit()
    db.close()

    return redirect(url_for('list_files'))

# ----------------------
# 🚀 Run App
# ----------------------
if __name__ == '__main__':
    app.run(debug=True)
