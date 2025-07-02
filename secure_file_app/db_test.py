print("Starting script...")

import os
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

# -------------------------
# 💾 Database Initialization
# -------------------------
print("Working directory:", os.getcwd())

# Path to SQLite DB file
db_path = os.path.abspath("files.db")
print(f"Creating DB at: {db_path}")

# Create SQLAlchemy engine
engine = create_engine(f"sqlite:///{db_path}", echo=True)

# Create base class for models
Base = declarative_base()

# -------------------------
# 👤 User Table
# -------------------------
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)  # Hashed password

    # A user can upload many files
    files = relationship("EncryptedFile", back_populates="owner")

# -------------------------
# 📁 File Table
# -------------------------
class EncryptedFile(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    data = Column(LargeBinary, nullable=False)  # Encrypted data
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    upload_time = Column(DateTime, default=datetime.utcnow)

    # File belongs to a specific user
    owner = relationship("User", back_populates="files")

# -------------------------
# 🚀 Create Tables
# -------------------------
Base.metadata.create_all(engine)
print("DB created successfully")
