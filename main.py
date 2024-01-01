from fastapi import FastAPI, Response, Depends,HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
import mysql.connector
from mysql.connector import Error
import os
from pydantic import BaseModel,EmailStr,UUID4
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import logging
from dotenv import load_dotenv
import uuid
import logging

load_dotenv()
app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY")
print(SECRET_KEY)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

class Database:
    connection = None
    @staticmethod
    def get_connection():
        if Database.connection is None:
            try:
                Database.connection = mysql.connector.connect(
                    host=os.getenv('DB_HOST'),
                    user=os.getenv('DB_USER'),
                    password=os.getenv('DB_PASSWORD'),
                    database=os.getenv('DB_NAME')
                )
            except Error as e:
                print(os.getenv('DB_HOST'))
                print(f"The error '{e}' occurred")
        return Database.connection
    
    def close_connection(self):
        if Database.connection is not None and Database.connection.is_connected():
            Database.connection.close()

def get_db_connection():
    try:
        db = Database.get_connection()
        if db is not None and db.is_connected():
            return db
        else:
            logging.error("Failed to connect to the database.")
            raise HTTPException(status_code=500, detail="Database connection error")
    except Error as e:
        logging.error(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail="Database connection error")


def create_table():
    """Create tables if they do not exist."""
    connection = Database.get_connection()
    cursor = connection.cursor()
    
    # List of table creation queries
    table_queries = [
        """
        CREATE TABLE IF NOT EXISTS Users (
            ID VARCHAR(255) PRIMARY KEY,
            username TEXT,
            email TEXT,
            password_hash VARCHAR(255),
            auth_token VARCHAR(255),
            expireat DATETIME
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Bookmark (
            ID INT AUTO_INCREMENT PRIMARY KEY,
            userid VARCHAR(255),
            addedat DATETIME,
            modifiedat DATETIME,
            url VARCHAR(255),
            openedat DATETIME,
            timesopened INT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Categories (
            ID INT AUTO_INCREMENT PRIMARY KEY,
            userid VARCHAR(255),
            category TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Logs (
            ID INT AUTO_INCREMENT PRIMARY KEY,
            username TEXT,
            timestamp DATETIME,
            type TEXT,
            service TEXT,
            message TEXT
        );
        """,
    ]

    try:
        for query in table_queries:
            cursor.execute(query)
        connection.commit()
    except Error as e:
        print(f"The error '{e}' occurred")
    finally:
        cursor.close()

async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> UUID4:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: UUID4 = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return user_id
    except JWTError:
        raise credentials_exception
@app.on_event("startup")
async def startup_event():
    """Event that runs at application startup to check/create the tables."""
    create_table()

@app.get("/")
async def read_root():
    return {"message": "FastAPI app connected to MySQL"}

def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

# Pydantic model for stored user (without password)
class UserInDB(BaseModel):
    username: str
    email: EmailStr

class PasswordReset(BaseModel):
    old_password: str
    new_password: str

@app.post("/v1/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, response: Response, db=Depends(get_db_connection)):
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM Users WHERE username = %s", (user.username,))
    existing_user = cursor.fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    cursor.execute("SELECT * FROM Users WHERE email = %s", (user.email,))
    existing_email = cursor.fetchone()
    if existing_email:
        raise HTTPException(status_code=400, detail="email already used. please do login.")
    
    hashed_password = pwd_context.hash(user.password)
    user_id = str(uuid.uuid4())
    access_token = create_access_token(data={"sub": existing_user["ID"]})

    try:
        cursor.execute("INSERT INTO Users (ID, username, email, password_hash, auth_token) VALUES (%s, %s, %s, %s, %s)", 
                        (user_id, user.username, user.email, hashed_password, access_token))
        db.commit()
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error saving user")

    # Add token to response headers
    response.headers["Authorization"] = f"Bearer {access_token}"

    cursor.close()
    db.close()

    return UserInDB(username=user.username, email=user.email)

class UserLogin(BaseModel):
    username: str
    password: str

@app.post("/v1/login")
def login(user: UserLogin, response: Response, db=Depends(get_db_connection)):
    cursor = db.cursor(dictionary=True)

    # Retrieve user from database by username
    cursor.execute("SELECT * FROM Users WHERE username = %s", (user.username,))
    user_record = cursor.fetchone()

    if not user_record:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Verify password
    if not pwd_context.verify(user.password, user_record["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    print(user)
    access_token = create_access_token(data={"sub": user_record["ID"]})

    # Update token and expiry in the database
    try:
        cursor.execute("UPDATE Users SET auth_token = %s WHERE username = %s", 
                        (access_token, user_record["username"]))
        db.commit()
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error updating user token")

    # Add token to response headers
    response.headers["Authorization"] = f"Bearer {access_token}"

    cursor.close()
    db.close()

    return {"message": "Login successful"}

@app.put("/v1/reset-password")
async def reset_password(password_data: PasswordReset, user_id: UUID4 = Depends(get_current_user_id), db=Depends(get_db_connection)):
    # Step 1: Retrieve the user from the database using user_id
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM Users WHERE ID = %s", (str(user_id),))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Step 2: Verify the old password
    if not pwd_context.verify(password_data.old_password, user['password_hash']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect")

    # Step 3: Update to the new password
    new_hashed_password = pwd_context.hash(password_data.new_password)
    cursor.execute("UPDATE Users SET password_hash = %s WHERE ID = %s", (new_hashed_password, str(user_id)))
    db.commit()

    return {"message": "Password updated successfully"}

class Category(BaseModel):
    id: int
    name: str
    user_id: UUID4

    class Config:
        from_attributes = True

@app.get("/v1/categories/", response_model=List[Category])
def list_categories(db=Depends(get_db_connection), user_id: UUID4 = Depends(get_current_user_id)):
    if db is None or not db.is_connected():
        raise HTTPException(status_code=500, detail="Database connection error")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM Categories WHERE userid = %s", (str(user_id),))
        db_categories = cursor.fetchall()
        # Map the database results to the Pydantic model
        categories = [
            {
                "id": category["ID"],
                "name": category["category"],
                "user_id": category["userid"]
            }
            for category in db_categories
        ]
        return categories
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()

class CategoryCreate(BaseModel):
    category: str

@app.post("/v1/categories/create", status_code=status.HTTP_201_CREATED)
def create_category(category_data: CategoryCreate, userid: UUID4 = Depends(get_current_user_id), db=Depends(get_db_connection)):
    cursor = db.cursor()
    try:
        # Check if the category already exists for the user
        cursor.execute(
            "SELECT * FROM Categories WHERE userid = %s AND category = %s",
            (str(userid), category_data.category)
        )
        existing_category = cursor.fetchone()
        if existing_category:
            raise HTTPException(status_code=400, detail="Category already exists")
        
        cursor.execute(
            "INSERT INTO Categories (userid, category) VALUES (%s, %s)",
            (str(userid), category_data.category)
        )
        db.commit()
        return {"message": "Category created successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error creating category")
    finally:
        cursor.close()

class CategoryUpdate(BaseModel):
    category: str

@app.put("/v1/categories/edit/{category_id}", status_code=status.HTTP_200_OK)
def edit_category(category_id: int, category_data: CategoryUpdate, db=Depends(get_db_connection)):
    cursor = db.cursor()
    try:
        cursor.execute(
            "UPDATE Categories SET category = %s WHERE ID = %s",
            (category_data.category, category_id)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Category not found")
        db.commit()
        return {"message": "Category updated successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error updating category")
    finally:
        cursor.close()

@app.delete("/v1/categories/delete/{category_id}", status_code=status.HTTP_200_OK)
def delete_category(category_id: int, db=Depends(get_db_connection), user_id: UUID4 = Depends(get_current_user_id)):
    cursor = db.cursor()
    try:
        # Optional: Check if the category exists and belongs to the user
        cursor.execute("SELECT * FROM Categories WHERE ID = %s AND userid = %s", (category_id, str(user_id)))
        category = cursor.fetchone()
        if not category:
            raise HTTPException(status_code=404, detail="Category not found or not authorized to delete")

        # Perform deletion
        cursor.execute("DELETE FROM Categories WHERE ID = %s", (category_id,))
        db.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Category not found")
        
        return {"message": "Category deleted successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error deleting category")
    finally:
        cursor.close()

class Bookmark(BaseModel):
    id: int
    url: str
    user_id: UUID4
    openedat: Optional[str]
    timesopened: Optional[int]
    addedat: str
    modifiedat: Optional[str]
    
    class Config:
        from_attributes = True

class BookmarkUrl(BaseModel):
    url: str

@app.post("/v1/bookmark/create", status_code=status.HTTP_201_CREATED)
def create_bookmark(bookmark_data: BookmarkUrl, userid: UUID4 = Depends(get_current_user_id), db=Depends(get_db_connection)):
    cursor = db.cursor()
    try:
        # Check if the bookmark already exists for the user
        cursor.execute(
            "SELECT * FROM Bookmark WHERE userid = %s AND url = %s",
            (str(userid), bookmark_data.url)
        )
        existing_bookmark = cursor.fetchone()
        if existing_bookmark:
            raise HTTPException(status_code=400, detail="bookmark already exists")
        current_time = datetime.now()
        
        cursor.execute(
            "INSERT INTO Bookmark (userid, url, addedat, timesopened) VALUES (%s, %s, %s, %s)",
            (str(userid), bookmark_data.url, current_time, '0')
        )
        db.commit()
        return {"message": "bookmark added successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error adding bookmark")
    finally:
        cursor.close()

@app.get("/v1/bookmarks/", response_model=List[Bookmark])
def list_bookmarks(db=Depends(get_db_connection), user_id: UUID4 = Depends(get_current_user_id)):
    if db is None or not db.is_connected():
        raise HTTPException(status_code=500, detail="Database connection error")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM Bookmark WHERE userid = %s", (str(user_id),))
        db_bookmarks = cursor.fetchall()
        # Map the database results to the Pydantic model
        bookmarks = [
            {
                "id": bookmark["ID"],
                "url": bookmark["url"],
                "user_id": bookmark["userid"],
                "addedat": bookmark["addedat"].strftime("%Y-%m-%d %H:%M:%S") if bookmark["addedat"] else None,
                "modifiedat": bookmark["modifiedat"].strftime("%Y-%m-%d %H:%M:%S") if bookmark["modifiedat"] else None,
                "openedat": bookmark["openedat"].strftime("%Y-%m-%d %H:%M:%S") if bookmark["openedat"] else None,
                "timesopened": bookmark["timesopened"]
            }
            for bookmark in db_bookmarks
        ]
        return bookmarks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()

@app.put("/v1/bookmark/edit/{bookmark_id}", status_code=status.HTTP_200_OK)
def edit_bookmark(bookmark_id: int, bookmark_data: BookmarkUrl, db=Depends(get_db_connection)):
    cursor = db.cursor()
    try:
        current_time = datetime.now()
        cursor.execute(
            "UPDATE Bookmark SET url = %s,modifiedat = %s WHERE ID = %s",
            (bookmark_data.url,current_time, bookmark_id)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Bookmark not found")
        db.commit()
        return {"message": "Bookmark updated successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error updating Bookmark")
    finally:
        cursor.close()

@app.delete("/v1/bookmark/delete/{bookmark_id}", status_code=status.HTTP_200_OK)
def delete_bookmark(bookmark_id: int, db=Depends(get_db_connection), user_id: UUID4 = Depends(get_current_user_id)):
    cursor = db.cursor()
    try:
        # Optional: Check if the bookmark exists and belongs to the user
        cursor.execute("SELECT * FROM Bookmark WHERE ID = %s AND userid = %s", (bookmark_id, str(user_id)))
        category = cursor.fetchone()
        if not category:
            raise HTTPException(status_code=404, detail="Bookmark not found or not authorized to delete")

        # Perform deletion
        cursor.execute("DELETE FROM Bookmark WHERE ID = %s", (bookmark_id,))
        db.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Bookmark not found")
        
        return {"message": "Bookmark deleted successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error deleting Bookmark")
    finally:
        cursor.close()

@app.patch("/v1/bookmark/open/{bookmark_id}", status_code=status.HTTP_200_OK)
def update_bookmark_opened(bookmark_id: int, db=Depends(get_db_connection), user_id: UUID4 = Depends(get_current_user_id)):
    cursor = db.cursor()
    try:
        current_time = datetime.now()

        # Update the openedat and increment timesopened
        cursor.execute(
            "UPDATE Bookmark SET openedat = %s, timesopened = timesopened + 1 WHERE ID = %s AND userid = %s",
            (current_time, bookmark_id, str(user_id))
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Bookmark not found or not authorized to update")

        db.commit()
        return {"message": "Bookmark opened time updated successfully"}
    except Error as e:
        print(f"The error '{e}' occurred")
        raise HTTPException(status_code=500, detail="Error updating Bookmark")
    finally:
        cursor.close()

@app.get("/v1/bookmark/{bookmark_id}", response_model=Bookmark)
def get_bookmark(bookmark_id: int, db=Depends(get_db_connection), user_id: UUID4 = Depends(get_current_user_id)):
    if db is None or not db.is_connected():
        raise HTTPException(status_code=500, detail="Database connection error")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM Bookmark WHERE ID = %s AND userid = %s", 
            (bookmark_id, str(user_id))
        )
        bookmark = cursor.fetchone()

        if not bookmark:
            raise HTTPException(status_code=404, detail="Bookmark not found")

        return {
            "id": bookmark["ID"],
            "url": bookmark["url"],
            "user_id": bookmark["userid"],
            "addedat": bookmark["addedat"].strftime("%Y-%m-%d %H:%M:%S") if bookmark["addedat"] else None,
            "modifiedat": bookmark["modifiedat"].strftime("%Y-%m-%d %H:%M:%S") if bookmark["modifiedat"] else None,
            "openedat": bookmark["openedat"].strftime("%Y-%m-%d %H:%M:%S") if bookmark["openedat"] else None,
            "timesopened": bookmark["timesopened"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
