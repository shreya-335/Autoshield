# backend/seed_db.py
from database import SessionLocal, engine
import models

def seed():
    db = SessionLocal()
    
    # 1. Create a Sample User
    test_user = models.User(email="shreya@example.com", password_hash="hashed_pw_123")
    db.add(test_user)
    db.flush() # Gets the ID without committing yet

    # 2. Create a Sample Project
    test_project = models.Project(user_id=test_user.id, name="AutoShield-Demo-Repo")
    db.add(test_project)
    db.flush()

    # 3. Create a Sample Scan
    test_scan = models.Scan(project_id=test_project.id, scan_type="dev", status="completed")
    db.add(test_scan)
    db.flush()

    # 4. Create Sample Vulnerabilities (Semgrep & ESLint)
    v1 = models.Vulnerability(
        scan_id=test_scan.id,
        tool="semgrep",
        file_path="src/auth.js",
        line=42,
        message="Hardcoded API Key detected",
        severity="HIGH"
    )
    v2 = models.Vulnerability(
        scan_id=test_scan.id,
        tool="eslint",
        file_path="src/app.js",
        line=10,
        message="Unused variable 'data'",
        severity="LOW"
    )
    
    db.add_all([v1, v2])
    db.commit()
    print("Database seeded successfully with dummy data!")
    db.close()

if __name__ == "__main__":
    seed()