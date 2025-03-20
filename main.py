from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import bcrypt
from uuid import uuid4
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "9439e712e39298ccde02d1c8a1e6d2784e1ed64628915dd74d5e78c6b6e85b65"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

Base = declarative_base()
engine = create_engine("sqlite:///hotel.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_admin = Column(Boolean, default=False)
    bookings = relationship("Booking", back_populates="user")

class Room(Base):
    __tablename__ = "rooms"
    id = Column(Integer, primary_key=True, autoincrement=True)  # Fix: Auto-increment ID
    name = Column(String)
    description = Column(String)
    base_price = Column(Float)
    capacity = Column(Integer)
    bookings = relationship("Booking", back_populates="room")

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    room_id = Column(String, ForeignKey("rooms.id"))
    check_in = Column(DateTime)
    check_out = Column(DateTime)
    final_price = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="bookings")
    room = relationship("Room", back_populates="bookings")

class PricePoint(Base):
    __tablename__ = "price_points"
    id = Column(String, primary_key=True, index=True)
    room_id = Column(String, ForeignKey("rooms.id"))
    date = Column(DateTime)
    booking_count = Column(Integer, default=0)
    price_multiplier = Column(Float, default=1.0)

Base.metadata.create_all(bind=engine)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[str] = None

class UserCreate(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    is_admin: bool

class RoomCreate(BaseModel):
    name: str
    description: str
    base_price: float
    capacity: int

class RoomResponse(BaseModel):
    id: int
    name: str
    description: str
    base_price: float
    capacity: int
    current_price: Optional[float] = None

class BookingCreate(BaseModel):
    room_id: str
    check_in: datetime
    check_out: datetime

class BookingResponse(BaseModel):
    id: str
    room_id: str
    check_in: datetime
    check_out: datetime
    final_price: float
    created_at: datetime

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        token_data = TokenData(user_id=user_id)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    user = db.query(User).filter(User.id == token_data.user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

class FenwickTree:
    def __init__(self, size):
        self.size = size
        self.tree = [0] * (size + 1)
    
    def update(self, idx, delta):
        while idx <= self.size:
            self.tree[idx] += delta
            idx += idx & -idx
    
    def query(self, idx):
        result = 0
        while idx > 0:
            result += self.tree[idx]
            idx -= idx & -idx
        return result
    
    def range_query(self, left, right):
        return self.query(right) - self.query(left - 1)

def calculate_dynamic_price(room_id, check_in, check_out, db: Session):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    
    date_range = (check_out - check_in).days
    bookings_in_period = db.query(Booking).filter(
        Booking.room_id == room_id,
        Booking.check_in <= check_out,
        Booking.check_out >= check_in
    ).count()
    
    total_days = (check_out - check_in).days
    
    ft = FenwickTree(100)
    for i in range(1, bookings_in_period + 1):
        ft.update(i, 1)
    
    demand_factor = ft.range_query(1, bookings_in_period) / 10 + 1
    
    seasonal_factor = 1.0
    month = check_in.month
    if month in [6, 7, 8, 12]:  
        seasonal_factor = 1.5
    elif month in [1, 2, 5, 9]:
        seasonal_factor = 1.2
    
    final_price = room.base_price * demand_factor * seasonal_factor * total_days
    
    return final_price

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    print(f"Received request: {user.dict()}")
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    db_user = User(
        id=str(uuid4()),
        email=user.email,
        password=hashed_password.decode('utf-8'),
        is_admin=False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not bcrypt.checkpw(form_data.password.encode('utf-8'), user.password.encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/token", response_model=Token)
# def login_for_access_token(
#     form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
# ):
#     user = db.query(User).filter(User.email == form_data.username).first()
#     if not user or not bcrypt.checkpw(form_data.password.encode(), user.password.encode()):
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
    
#     access_token = create_access_token(data={"sub": user.id})
#     return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/rooms", response_model=RoomResponse)
def create_room(room: RoomCreate, current_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    db_room = Room(
        id=str(uuid4()),
        name=room.name,
        description=room.description,
        base_price=room.base_price,
        capacity=room.capacity
    )
    db.add(db_room)
    db.commit()
    db.refresh(db_room)
    return db_room

@app.get("/rooms", response_model=List[RoomResponse])
def get_rooms(db: Session = Depends(get_db)):
    rooms = db.query(Room).all()
    response = []
    for room in rooms:
        room_dict = {
            "id": room.id,
            "name": room.name,
            "description": room.description,
            "base_price": room.base_price,
            "capacity": room.capacity
        }
        response.append(room_dict)
    return response

@app.get("/rooms/{room_id}", response_model=RoomResponse)
def get_room(room_id: int, check_in: Optional[datetime] = None, check_out: Optional[datetime] = None, db: Session = Depends(get_db)):
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    
    room_dict = {
        "id": room.id,
        "name": room.name,
        "description": room.description,
        "base_price": room.base_price,
        "capacity": room.capacity
    }
    
    if check_in and check_out:
        room_dict["current_price"] = calculate_dynamic_price(room_id, check_in, check_out, db) / (check_out - check_in).days
    
    return room_dict

@app.post("/bookings", response_model=BookingResponse)
def create_booking(booking: BookingCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if booking.check_in >= booking.check_out:
        raise HTTPException(status_code=400, detail="Check-out must be after check-in")
    
    room = db.query(Room).filter(Room.id == booking.room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    
    overlapping_bookings = db.query(Booking).filter(
        Booking.room_id == booking.room_id,
        Booking.check_in < booking.check_out,
        Booking.check_out > booking.check_in
    ).all()
    
    if overlapping_bookings:
        raise HTTPException(status_code=400, detail="Room is already booked for these dates")
    
    final_price = calculate_dynamic_price(booking.room_id, booking.check_in, booking.check_out, db)
    
    db_booking = Booking(
        id=str(uuid4()),
        user_id=current_user.id,
        room_id=booking.room_id,
        check_in=booking.check_in,
        check_out=booking.check_out,
        final_price=final_price
    )
    
    db.add(db_booking)
    db.commit()
    db.refresh(db_booking)
    
    return db_booking

@app.get("/bookings", response_model=List[BookingResponse])
def get_bookings(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.is_admin:
        bookings = db.query(Booking).all()
    else:
        bookings = db.query(Booking).filter(Booking.user_id == current_user.id).all()
    return bookings

@app.get("/bookings/{booking_id}", response_model=BookingResponse)
def get_booking(booking_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    if booking.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return booking

@app.post("/admin/create", response_model=UserResponse)
def create_admin(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).count() > 0:
        raise HTTPException(status_code=400, detail="Admin can only be created for an empty database")
    
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    db_user = User(
        id=str(uuid4()),
        email=user.email,
        password=hashed_password.decode('utf-8'),
        is_admin=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.delete("/bookings/{booking_id}")
def delete_booking(booking_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    if booking.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    db.delete(booking)
    db.commit()
    
    return {"message": "Booking deleted successfully"}

def populate_db(db):

    # Check if database is empty



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


db = SessionLocal()
populate_db(db)
db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)