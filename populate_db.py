from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from main import Base, Room  # Ensure models.py has the Room model
import random

# Define the database URL (change if using a different DB)
DATABASE_URL = "sqlite:///hotel.db"

# Create engine and session
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)

# Sample rooms data
rooms_data = [
    {"name": "Deluxe Suite", "description": "Spacious suite with a sea view", "base_price": 150.0, "capacity": 2},
    {"name": "Standard Room", "description": "Cozy room with modern amenities", "base_price": 100.0, "capacity": 2},
    {"name": "Family Room", "description": "Large room for a family of four", "base_price": 200.0, "capacity": 4},
    {"name": "Presidential Suite", "description": "Luxury suite with premium features", "base_price": 500.0, "capacity": 5},
    {"name": "Budget Room", "description": "Affordable room for solo travelers", "base_price": 50.0, "capacity": 1}
]

# Insert rooms into the database
with Session(engine) as session:
    for room in rooms_data:
        new_room = Room(
            name=room["name"],
            description=room["description"],
            base_price=room["base_price"],
            capacity=room["capacity"]
        )
        session.add(new_room)
    
    session.commit()

print("Database populated successfully!")
