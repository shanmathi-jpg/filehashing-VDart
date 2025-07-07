import os
import io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload
from db_test import Base, User, EncryptedFile
from crypto_utils import encrypt_bytes, decrypt_bytes, hash_password, verify_password

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database setup
db_path = os.path.abspath("files.db")
engine = create_engine(f"sqlite:///{db_path}", echo=False)
SessionLocal = sessionmaker(bind=engine)

# ---------------------- Decorators ----------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return "Access Denied", 403
        return f(*args, **kwargs)
    return decorated

# ---------------------- Routes ----------------------
@app.route('/')
def index():
    return render_template('index.html')

# ---------- User Register/Login --------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = SessionLocal()
        username = request.form['username']
        password = request.form['password']
        if db.query(User).filter_by(username=username).first():
            db.close()
            return "Username already exists."
        user = User(username=username, password=hash_password(password), is_admin=False)
        db.add(user)
        db.commit()
        db.close()
        return redirect(url_for('login', user_username=username, user_password=password))
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    pre_username = request.args.get('user_username', '')
    pre_password = request.args.get('user_password', '')

    if request.method == 'POST':
        db = SessionLocal()
        user = db.query(User).filter_by(username=request.form['username']).first()
        if user and verify_password(request.form['password'], user.password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            db.close()
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('home'))
        db.close()
        return "Invalid credentials."

    return render_template('login.html', pre_username=pre_username, pre_password=pre_password)


# ---------- Admin Register/Login ----------
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        db = SessionLocal()
        username = request.form['username']
        password = request.form['password']
        if db.query(User).filter_by(username=username).first():
            db.close()
            return "Username already exists."
        admin = User(username=username, password=hash_password(password), is_admin=True)
        db.add(admin)
        db.commit()
        db.close()
        return redirect(url_for('admin_login', admin_username=username, admin_password=password))
    return render_template('admin_register.html')



@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        db = SessionLocal()
        admin = db.query(User).filter_by(username=request.form['username'], is_admin=True).first()
        if admin and verify_password(request.form['password'], admin.password):
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['is_admin'] = True
            db.close()
            return redirect(url_for('admin_dashboard'))
        db.close()
        return "Invalid admin credentials."  # This was missing before

    # GET method: Show admin login form with prefilled default credentials
    return render_template('admin_login.html', pre_username="admin", pre_password="admin123")


@app.route('/logout')
def logout():
    db = SessionLocal()
    user = db.query(User).filter_by(id=session.get('user_id')).first()
    if user:
        user.last_logout = datetime.utcnow()
        db.commit()
    db.close()
    session.clear()
    return redirect(url_for('index'))

# ---------- User File Routes ----------
@app.route('/home')
@login_required
def home():
    return render_template('upload.html', username=session['username'])

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return "No file uploaded", 400

    file_data = uploaded_file.read()
    encrypted_data = encrypt_bytes(file_data)

    db = SessionLocal()
    file = EncryptedFile(
        filename=uploaded_file.filename,
        data=encrypted_data,
        user_id=session['user_id']
    )
    db.add(file)
    db.commit()
    db.close()

    return redirect(url_for('list_files'))

@app.route('/files')
@login_required
def list_files():
    db = SessionLocal()
    files = db.query(EncryptedFile).filter_by(user_id=session['user_id']).all()
    db.close()
    return render_template('files.html', files=files, username=session['username'])
@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    db = SessionLocal()
    file = db.query(EncryptedFile).filter_by(id=file_id, user_id=session['user_id']).first()
    db.close()

    if not file:
        return "Access denied or file not found", 403

    decrypted_bytes = decrypt_bytes(file.data)
    ext = os.path.splitext(file.filename)[1].lower()

    # Save to static folder
    temp_filename = f"temp_{file.id}{ext}"
    temp_path = os.path.join("static", temp_filename)

    with open(temp_path, "wb") as f:
        f.write(decrypted_bytes)

    # File accessible via external URL
    file_url = url_for('static', filename=temp_filename, _external=True)

    # Choose viewer
    if ext == ".pdf":
        preview_url = file_url
    elif ext in [".docx", ".pptx", ".xlsx"]:
        # Microsoft Office Viewer (requires public access)
        preview_url = f"https://view.officeapps.live.com/op/embed.aspx?src={file_url}"
    elif ext == ".txt":
        content = decrypted_bytes.decode("utf-8", errors="replace")
        return render_template("view.html", filename=file.filename, content=content)
    else:
        return "❌ Unsupported file type for preview."

    return render_template("view.html", filename=file.filename, preview_url=preview_url)


@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    db = SessionLocal()
    file = db.query(EncryptedFile).filter_by(id=file_id, user_id=session['user_id']).first()
    db.close()
    if not file:
        return "File not found", 404
    return send_file(io.BytesIO(decrypt_bytes(file.data)), as_attachment=True, download_name=file.filename)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    db = SessionLocal()
    file = db.query(EncryptedFile).filter_by(id=file_id, user_id=session['user_id']).first()
    if file:
        db.delete(file)
        db.commit()
    db.close()
    return redirect(url_for('list_files'))

# ---------- Admin Dashboard ----------
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = SessionLocal()
    files = db.query(EncryptedFile).options(joinedload(EncryptedFile.owner)).all()
    users = db.query(User).all()
    db.close()
    return render_template('admin_dashboard.html', files=files, users=users, username=session['username'])

@app.route('/admin/view/<int:file_id>')
@admin_required
def admin_view_file(file_id):
    db = SessionLocal()
    file = db.query(EncryptedFile).filter_by(id=file_id).options(joinedload(EncryptedFile.owner)).first()
    db.close()

    if not file:
        return "File not found", 404

    decrypted_bytes = decrypt_bytes(file.data)
    ext = os.path.splitext(file.filename)[1].lower()

    if ext == ".pdf":
        temp_filename = f"temp_admin_{file.id}.pdf"
        temp_path = os.path.join("static", temp_filename)
        with open(temp_path, "wb") as f:
            f.write(decrypted_bytes)
        return render_template("view.html", filename=file.filename, preview_url=url_for('static', filename=temp_filename))
    elif ext == ".txt":
        content = decrypted_bytes.decode("utf-8", errors="replace")
        return render_template("view.html", filename=file.filename, content=content)
    else:
        return "Preview not supported for this file type."

@app.route('/admin/download/<int:file_id>')
@admin_required
def admin_download(file_id):
    db = SessionLocal()
    file = db.query(EncryptedFile).filter_by(id=file_id).first()
    db.close()
    if not file:
        return "File not found", 404
    return send_file(io.BytesIO(decrypt_bytes(file.data)), as_attachment=True, download_name=file.filename)

@app.route('/admin/delete/<int:file_id>')
@admin_required
def admin_delete_file(file_id):
    db = SessionLocal()
    file = db.query(EncryptedFile).filter_by(id=file_id).first()
    if file:
        db.delete(file)
        db.commit()
    db.close()
    return redirect(url_for('admin_dashboard'))

# ---------------------- Run ----------------------
if __name__ == '__main__':
    app.run(debug=True)
