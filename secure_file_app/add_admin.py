from sqlalchemy.orm import sessionmaker
from db_test import engine, User
from crypto_utils import hash_password

Session = sessionmaker(bind=engine)
db = Session()

admin_user = User(
    username="admin",
    password=hash_password("admin123"),
    is_admin=True
)

db.add(admin_user)
db.commit()
db.close()

print("✅ Admin user created successfully.")
