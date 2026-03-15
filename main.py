from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File as FastAPIFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, ConfigDict
from datetime import datetime
import os
import uuid

import models
import auth
from database import engine, get_db

models.Base.metadata.create_all(bind=engine)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://frontend-pi-orpin-46.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer()


class UserIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    username: str


class FileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    size: int
    created_at: datetime


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    username = auth.decode_token(credentials.credentials)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@app.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(body: UserIn, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == body.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    user = models.User(
        username=body.username,
        hashed_password=auth.hash_password(body.password),
    )
    db.add(user)
    db.commit()
    return TokenOut(access_token=auth.create_access_token(user.username))


@app.post("/login", response_model=TokenOut)
def login(body: UserIn, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == body.username).first()
    if not user or not auth.verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return TokenOut(access_token=auth.create_access_token(user.username))


@app.get("/me", response_model=UserOut)
def me(current_user: models.User = Depends(get_current_user)):
    return UserOut(username=current_user.username)


@app.post("/files/upload", response_model=FileOut, status_code=201)
async def upload_file(
    file: UploadFile = FastAPIFile(...),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="只支持 PDF 文件")

    user_dir = os.path.join(UPLOAD_DIR, str(current_user.id))
    os.makedirs(user_dir, exist_ok=True)

    unique_name = f"{uuid.uuid4()}.pdf"
    filepath = os.path.join(user_dir, unique_name)

    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)

    db_file = models.File(
        user_id=current_user.id,
        filename=file.filename,
        filepath=filepath,
        size=len(content),
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    return db_file


@app.get("/files", response_model=list[FileOut])
def list_files(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.File)
        .filter(models.File.user_id == current_user.id)
        .order_by(models.File.created_at.desc())
        .all()
    )


@app.get("/files/{file_id}")
def download_file(
    file_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db_file = db.query(models.File).filter(
        models.File.id == file_id,
        models.File.user_id == current_user.id,
    ).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(db_file.filepath, media_type="application/pdf", filename=db_file.filename)


@app.delete("/files/{file_id}", status_code=204)
def delete_file(
    file_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db_file = db.query(models.File).filter(
        models.File.id == file_id,
        models.File.user_id == current_user.id,
    ).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    if os.path.exists(db_file.filepath):
        os.remove(db_file.filepath)
    db.delete(db_file)
    db.commit()
