import db

def seed_users():
    print("[*] Adding dummy users...")
    users = [
        ("E2507-8420-1275","48504575664f347533494d6c3147"),
        ("E2507-8420-1274","HPEufO4u3IMl1G"),
        ("charger_01", "pass123"),
        ("charger_02", "pass456"),
        ("admin", "admin"),
    ]
    for user, pwd in users:
        try:
            db.add_user(user, pwd)
            print(f" [+] Added user: {user}")
        except Exception as e:
            print(f" [!] Skipped {user}: {e}")

def seed_events():
    print("[*] Adding dummy events...")
    events = [
        ("BootNotification", "charger_01", {"status": "Accepted"}),
        ("Authorize", "charger_02", {"idTag": "ABC123"}),
        ("Heartbeat", "charger_01", {"interval": 300}),
    ]
    for evt_type, target, data in events:
        try:
            db.add_event(evt_type, target, data)
            print(f" [+] Added event: {evt_type} for {target}")
        except Exception as e:
            print(f" [!] Failed to add event: {e}")

def main():
    print("⚡ Seeding database with dummy data...")
    db.purge_events()
    seed_users()
    #seed_events()
    print("✅ Done! Database is ready.")

if __name__ == "__main__":
    main()