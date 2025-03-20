from sqlalchemy.orm import Session
from main import SessionLocal, User, Room, bcrypt, uuid4

def populate_db():
    db: Session = SessionLocal()

    # Check if database is empty
    user_count = db.query(User).count()
    room_count = db.query(Room).count()

    if user_count == 0 and room_count == 0:
        print("Database is empty. Populating with initial data...")

        # Add Admin User
        admin_password = bcrypt.hashpw("admin123".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        admin = User(id=str(uuid4()), email="admin@example.com", password=admin_password, is_admin=True)
        db.add(admin)

        # Add 10 Users
        users = []
        for i in range(1, 11):
            password = bcrypt.hashpw(f"user{i}pass".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            user = User(id=str(uuid4()), email=f"user{i}@example.com", password=password, is_admin=False)
            users.append(user)

        db.add_all(users)

        # Add 15 Rooms
        rooms = []
        for i in range(1, 16):
            room = Room(
                name=f"Room {i}",
                description=f"Description of Room {i}",
                base_price=100 + i * 10,
                capacity=i
            )
            rooms.append(room)

        db.add_all(rooms)

        db.commit()
        print("Database populated successfully!")
    else:
        print("Database already contains data. No changes made.")

    db.close()

if __name__ == "__main__":
    populate_db()
