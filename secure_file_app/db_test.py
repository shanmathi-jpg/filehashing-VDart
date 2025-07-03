import os
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

# Initialize base for models
Base = declarative_base()

# User Table
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    last_login = Column(DateTime)
    last_logout = Column(DateTime)

    files = relationship("EncryptedFile", back_populates="owner")

# Encrypted File Table
class EncryptedFile(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    data = Column(LargeBinary, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    upload_time = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="files")

# Create engine
db_path = os.path.abspath("files.db")
engine = create_engine(f"sqlite:///{db_path}", echo=True)
