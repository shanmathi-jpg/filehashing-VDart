# create_db.py

from db_test import Base, engine

# Create all tables in the database
Base.metadata.create_all(engine)

print("✅ Database created successfully.")
