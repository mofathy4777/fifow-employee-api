# FIFOW Employee Management API
# FastAPI Backend for Mobile App

from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
import bcrypt
import os

# FastAPI App
app = FastAPI(
    title="FIFOW Employee API",
    description="Backend API for FIFOW Employee Mobile Application",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./fifow_employees.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security
JWT_SECRET = os.getenv("JWT_SECRET", "fifow_secret_key_2024")
JWT_ALGORITHM = "HS256"
security = HTTPBearer()

# Database Models
class Employee(Base):
    __tablename__ = "employees"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    full_name = Column(String)
    phone = Column(String)
    position = Column(String)
    department = Column(String)
    hire_date = Column(DateTime, default=func.now())
    salary = Column(Float)
    is_active = Column(Boolean, default=True)
    profile_photo = Column(Text)
    address = Column(Text)
    emergency_contact = Column(String)
    emergency_phone = Column(String)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    attendances = relationship("Attendance", back_populates="employee")
    tasks = relationship("Task", back_populates="employee")

class Attendance(Base):
    __tablename__ = "attendance"
    
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    date = Column(DateTime, default=func.now())
    check_in_time = Column(DateTime)
    check_out_time = Column(DateTime)
    check_in_latitude = Column(Float)
    check_in_longitude = Column(Float)
    check_out_latitude = Column(Float)
    check_out_longitude = Column(Float)
    check_in_photo = Column(Text)
    check_out_photo = Column(Text)
    total_hours = Column(Float)
    status = Column(String, default="present")
    notes = Column(Text)
    created_at = Column(DateTime, default=func.now())
    
    employee = relationship("Employee", back_populates="attendances")

class Task(Base):
    __tablename__ = "tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, ForeignKey("employees.id"))
    title = Column(String)
    description = Column(Text)
    assigned_date = Column(DateTime, default=func.now())
    due_date = Column(DateTime)
    priority = Column(String, default="medium")
    status = Column(String, default="pending")
    completion_notes = Column(Text)
    completion_photos = Column(Text)
    assigned_by = Column(String)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    employee = relationship("Employee", back_populates="tasks")

class WorkZone(Base):
    __tablename__ = "work_zones"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    center_latitude = Column(Float)
    center_longitude = Column(Float)
    radius_meters = Column(Integer, default=100)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
class EmployeeLogin(BaseModel):
    username: str
    password: str

class EmployeeCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    phone: str
    position: str
    department: str
    salary: Optional[float] = 0.0

class AttendanceCheckIn(BaseModel):
    latitude: float
    longitude: float
    photo: Optional[str] = None
    notes: Optional[str] = ""

class AttendanceCheckOut(BaseModel):
    latitude: float
    longitude: float
    photo: Optional[str] = None
    notes: Optional[str] = ""

# Utility Functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_employee(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    username = verify_token(credentials.credentials)
    employee = db.query(Employee).filter(Employee.username == username).first()
    if employee is None:
        raise HTTPException(status_code=401, detail="Employee not found")
    return employee

# Authentication Endpoints
@app.post("/api/auth/login")
async def login_employee(employee_data: EmployeeLogin, db: Session = Depends(get_db)):
    employee = db.query(Employee).filter(Employee.username == employee_data.username).first()
    
    if not employee or not verify_password(employee_data.password, employee.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    if not employee.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Employee account is deactivated"
        )
    
    access_token = create_access_token(data={"sub": employee.username})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "employee": {
            "id": employee.id,
            "username": employee.username,
            "full_name": employee.full_name,
            "position": employee.position,
            "department": employee.department,
            "profile_photo": employee.profile_photo
        }
    }

@app.post("/api/auth/register")
async def register_employee(employee_data: EmployeeCreate, db: Session = Depends(get_db)):
    existing = db.query(Employee).filter(
        (Employee.username == employee_data.username) | 
        (Employee.email == employee_data.email)
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    hashed_password = hash_password(employee_data.password)
    
    new_employee = Employee(
        username=employee_data.username,
        email=employee_data.email,
        password_hash=hashed_password,
        full_name=employee_data.full_name,
        phone=employee_data.phone,
        position=employee_data.position,
        department=employee_data.department,
        salary=employee_data.salary
    )
    
    db.add(new_employee)
    db.commit()
    db.refresh(new_employee)
    
    return {"message": "Employee registered successfully", "employee_id": new_employee.id}

# Employee Endpoints
@app.get("/api/employee/profile")
async def get_employee_profile(current_employee: Employee = Depends(get_current_employee)):
    return {
        "id": current_employee.id,
        "username": current_employee.username,
        "email": current_employee.email,
        "full_name": current_employee.full_name,
        "phone": current_employee.phone,
        "position": current_employee.position,
        "department": current_employee.department,
        "profile_photo": current_employee.profile_photo,
        "hire_date": current_employee.hire_date
    }

# Attendance Endpoints
@app.post("/api/attendance/checkin")
async def check_in(
    attendance_data: AttendanceCheckIn,
    current_employee: Employee = Depends(get_current_employee),
    db: Session = Depends(get_db)
):
    today = datetime.now().date()
    existing_attendance = db.query(Attendance).filter(
        Attendance.employee_id == current_employee.id,
        func.date(Attendance.date) == today
    ).first()
    
    if existing_attendance and existing_attendance.check_in_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Already checked in today"
        )
    
    if existing_attendance:
        existing_attendance.check_in_time = func.now()
        existing_attendance.check_in_latitude = attendance_data.latitude
        existing_attendance.check_in_longitude = attendance_data.longitude
        existing_attendance.check_in_photo = attendance_data.photo
        existing_attendance.notes = attendance_data.notes
        attendance = existing_attendance
    else:
        attendance = Attendance(
            employee_id=current_employee.id,
            check_in_time=func.now(),
            check_in_latitude=attendance_data.latitude,
            check_in_longitude=attendance_data.longitude,
            check_in_photo=attendance_data.photo,
            notes=attendance_data.notes
        )
        db.add(attendance)
    
    db.commit()
    db.refresh(attendance)
    
    return {
        "message": "Checked in successfully",
        "check_in_time": attendance.check_in_time,
        "attendance_id": attendance.id
    }

@app.post("/api/attendance/checkout")
async def check_out(
    attendance_data: AttendanceCheckOut,
    current_employee: Employee = Depends(get_current_employee),
    db: Session = Depends(get_db)
):
    today = datetime.now().date()
    attendance = db.query(Attendance).filter(
        Attendance.employee_id == current_employee.id,
        func.date(Attendance.date) == today
    ).first()
    
    if not attendance or not attendance.check_in_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No check-in found for today"
        )
    
    if attendance.check_out_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Already checked out today"
        )
    
    check_out_time = datetime.now()
    attendance.check_out_time = check_out_time
    attendance.check_out_latitude = attendance_data.latitude
    attendance.check_out_longitude = attendance_data.longitude
    attendance.check_out_photo = attendance_data.photo
    
    if attendance.check_in_time:
        time_diff = check_out_time - attendance.check_in_time
        attendance.total_hours = round(time_diff.total_seconds() / 3600, 2)
    
    if attendance_data.notes:
        attendance.notes += f" | Checkout: {attendance_data.notes}"
    
    db.commit()
    db.refresh(attendance)
    
    return {
        "message": "Checked out successfully",
        "check_out_time": attendance.check_out_time,
        "total_hours": attendance.total_hours
    }

@app.get("/api/attendance/today")
async def get_today_attendance(
    current_employee: Employee = Depends(get_current_employee),
    db: Session = Depends(get_db)
):
    today = datetime.now().date()
    attendance = db.query(Attendance).filter(
        Attendance.employee_id == current_employee.id,
        func.date(Attendance.date) == today
    ).first()
    
    if not attendance:
        return {
            "status": "not_checked_in",
            "check_in_time": None,
            "check_out_time": None,
            "total_hours": 0
        }
    
    return {
        "status": "checked_out" if attendance.check_out_time else "checked_in",
        "check_in_time": attendance.check_in_time,
        "check_out_time": attendance.check_out_time,
        "total_hours": attendance.total_hours or 0,
        "notes": attendance.notes
    }

# Tasks Endpoints
@app.get("/api/tasks")
async def get_employee_tasks(
    status: Optional[str] = None,
    current_employee: Employee = Depends(get_current_employee),
    db: Session = Depends(get_db)
):
    query = db.query(Task).filter(Task.employee_id == current_employee.id)
    
    if status:
        query = query.filter(Task.status == status)
    
    tasks = query.order_by(Task.created_at.desc()).all()
    
    return {
        "tasks": [
            {
                "id": task.id,
                "title": task.title,
                "description": task.description,
                "due_date": task.due_date,
                "priority": task.priority,
                "status": task.status,
                "assigned_by": task.assigned_by,
                "completion_notes": task.completion_notes,
                "created_at": task.created_at
            }
            for task in tasks
        ]
    }

# Admin Endpoints
@app.get("/api/admin/employees")
async def get_all_employees(db: Session = Depends(get_db)):
    employees = db.query(Employee).all()
    return {
        "employees": [
            {
                "id": emp.id,
                "username": emp.username,
                "full_name": emp.full_name,
                "position": emp.position,
                "department": emp.department,
                "is_active": emp.is_active,
                "hire_date": emp.hire_date
            }
            for emp in employees
        ]
    }

@app.get("/api/admin/attendance/live")
async def get_live_attendance(db: Session = Depends(get_db)):
    today = datetime.now().date()
    
    attendances = db.query(Attendance).filter(
        func.date(Attendance.date) == today
    ).all()
    
    return {
        "date": today,
        "attendances": [
            {
                "employee_id": att.employee_id,
                "employee_name": att.employee.full_name,
                "check_in_time": att.check_in_time,
                "check_out_time": att.check_out_time,
                "total_hours": att.total_hours,
                "status": att.status,
                "location": {
                    "check_in": {"lat": att.check_in_latitude, "lng": att.check_in_longitude} if att.check_in_latitude else None,
                    "check_out": {"lat": att.check_out_latitude, "lng": att.check_out_longitude} if att.check_out_latitude else None
                }
            }
            for att in attendances
        ]
    }

@app.post("/api/admin/tasks/assign")
async def assign_task(
    employee_id: int = Form(...),
    title: str = Form(...),
    description: str = Form(...),
    due_date: str = Form(...),
    priority: str = Form("medium"),
    assigned_by: str = Form("Manager"),
    db: Session = Depends(get_db)
):
    employee = db.query(Employee).filter(Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Employee not found"
        )
    
    task = Task(
        employee_id=employee_id,
        title=title,
        description=description,
        due_date=datetime.fromisoformat(due_date.replace('Z', '+00:00')),
        priority=priority,
        assigned_by=assigned_by
    )
    
    db.add(task)
    db.commit()
    db.refresh(task)
    
    return {"message": "Task assigned successfully", "task_id": task.id}

# Health Check
@app.get("/")
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "FIFOW Employee API",
        "version": "1.0.0",
        "timestamp": datetime.now()
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
