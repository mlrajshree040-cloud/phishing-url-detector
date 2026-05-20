# check_db.py
from app import app, db, User, ScanHistory

with app.app_context():
    # Count all users
    users = User.query.all()
    print(f"Total users: {len(users)}")
    
    for user in users:
        print(f"\nUser: {user.username} (ID: {user.id})")
        scans = ScanHistory.query.filter_by(user_id=user.id).all()
        print(f"  Scans found: {len(scans)}")
        for scan in scans:
            print(f"    - {scan.scan_date} | {scan.url} | {scan.verdict}")