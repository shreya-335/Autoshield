# backend/init_db.py

from database import engine
from models import Base

Base.metadata.drop_all(bind=engine)   # optional (for clean reset)
Base.metadata.create_all(bind=engine)

print("Tables created successfully.")