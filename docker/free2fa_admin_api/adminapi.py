# adminapi.py
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Api module for database administration via website"""

import os
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from sqlite3 import IntegrityError
import uvicorn

import aiosqlite
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt


# Logging Setup
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

logging.basicConfig(level=logging.INFO,
                    format=LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": LOG_FORMAT,
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": "ext://sys.stdout"
        },
    },
    "loggers": {
        "free2fa4rdg_admin_api": {
            "handlers": ["console"],
            "level": "INFO"
        }
    }
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Executes at the start of the FastAPI application, handling initial setup tasks.
    It's responsible for initializing databases, ensuring the application starts with
    the necessary database structure. The `init_db()` function sets up the primary
    database, while `init_admin_db()` prepares the administrative database. This setup
    typically involves creating required tables and structures if they don't exist, thus
    providing the essential database schema for the application to function properly
    from the start.
    """
    await init_db()
    await init_admin_db()
    yield

app = FastAPI(lifespan=lifespan)

# Setting up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all sources
    allow_credentials=True,
    allow_methods=["POST", "GET", "PUT", "DELETE"],  # Allows method
    allow_headers=["Content-Type", "Authorization"],  # Allows headers
)

logging.config.dictConfig(logging_config)
logger = logging.getLogger("free2fa4rdg_admin_api")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/admin", scopes={"admin": "Admin privileges"})
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ERROR404 = "User not found"


class ResetPasswordRequest(BaseModel):
    """class Reset Password Request"""
    secret_key: str


class TokenData(BaseModel):
    """class TokenData for stored JWT"""
    username: Optional[str] = None
    scopes: List[str] = []


class AdminAuth(BaseModel):
    """class Authorization for administrator"""
    username: str
    password: str


class PasswordChange(BaseModel):
    """class Password Change for administrator"""
    old_password: str
    new_password: str


SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")
RESET_PASSWORD = os.getenv("RESET_PASSWORD", "false").lower() == "true"


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Model for user data

DATABASE_PATH = '/opt/db/users.db'


class User(BaseModel):
    """
    Pydantic model for representing user data.

    Attributes:
        domain_and_username (str): The user's unique domain username.
        telegram_id (int): The user's Telegram identifier.
        is_bypass (bool, optional):
        Flag indicating whether there are special rules to let in without request.
        The default value is False.
    """
    domain_and_username: str
    telegram_id: int
    is_bypass: bool = False


async def generate_password_hash(password):
    """
    Generates a password hash using Bcrypt.

    Args:
        password (str): The plain text password to hash.

    Returns:
        str: A hashed version of the password.
    """
    return pwd_context.hash(password)


def create_access_token(data: dict, scopes: List[str]):
    """
    Create a new access token.

    Args:
        data (dict): The data to encode in the token.
        scopes (List[str]): List of scopes (permissions) for the token.

    Returns:
        str: Encoded JWT token.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "scopes": scopes})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def authenticate_user(username: str, password: str):
    """
    Authenticate a user by their username and password.

    Args:
        username (str): Username of the user to authenticate.
        password (str): Password of the user for authentication.

    Returns:
        dict or None: User object if authentication is successful; None otherwise.
    """
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        query = ('SELECT username, hashed_password FROM admins WHERE username = ?')
        async with db_connection.execute(query, (username,)) as cursor:
            admin = await cursor.fetchone()
            if admin and await verify_password(password, admin[1]):
                return {"username": admin[0]}
    return None


async def verify_password(plain_password, hashed_password):
    """
    Verify a plain password against the hashed password.

    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The hashed password to verify against.

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


async def get_db():
    """
    Asynchronous generator that establishes and manages a database connection context.

    This function opens an asynchronous connection to the database using aiosqlite and
    provides this connection for use in database operations. After the completion of
    operations, the connection is automatically closed, ensuring proper resource
    management.

    Yields:
        db_connection: A context manager providing the database connection.

    Usage example in FastAPI:
        @app.get("/items/")
        async def read_items(db_connection=Depends(get_db)):
            async with db_connection.execute("SELECT * FROM items") as cursor:
                items = await cursor.fetchall()
                return items

    This ensures efficient and safe management of database connections, especially
    in asynchronous applications.
    """
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        yield db_connection


async def init_db():
    """
    Asynchronously initializes the database.

    This function establishes a connection to the SQLite database using aiosqlite. It
    creates the 'users' table if it doesn't already exist. The 'users' table includes
    columns for 'domain_and_username', 'telegram_id', and 'is_bypass'. The
    'domain_and_username' column is set as the primary key and is unique for each
    record. The 'is_bypass' column is a boolean value, defaulting to FALSE if not
    specified.

    The database schema is essential for storing and managing user data effectively,
    especially in applications integrating with Telegram bots or requiring user
    authentication and management.

    This function should be called when the application starts, ensuring that the
    necessary database structure is in place for the application to function correctly.
    """
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        await db_connection.execute('''
            CREATE TABLE IF NOT EXISTS users (
                domain_and_username TEXT PRIMARY KEY UNIQUE,
                telegram_id INTEGER,
                is_bypass BOOLEAN NOT NULL DEFAULT FALSE
            )
        ''')
        await db_connection.commit()


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Retrieves the current authenticated user based on the provided JWT token.

    Args:
        token (str): JWT token obtained from the request header.

    Raises:
        HTTPException: If the token is not provided,
        invalid, or the user does not have 'admin' scope.

    Returns:
        TokenData: The username and scopes from the token if validation is successful.
    """
    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except JWTError as jwt_error:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        ) from jwt_error

    if "admin" not in token_data.scopes:
        raise HTTPException(
            status_code=403,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return token_data


@app.post("/users/")
async def add_user(user: User, _: User = Depends(get_current_user)):
    """
    Adds a new user to the database.

    This function receives user data, connects asynchronously to the database, and
    attempts to insert the new user's data. It handles unique constraint violations
    by raising an HTTP 400 error if a user with the same domain_and_username already exists.

    Args:
        user (User): User object containing user data for insertion.
        current_user (User): Current authenticated user (obtained through dependency).

    Raises:
        HTTPException: 400 error if a user with the same domain_and_username already exists.

    Returns:
        dict: Confirmation message upon successful addition of the user.
    """
    user.domain_and_username = user.domain_and_username.lower()
    sql_query = (
        'INSERT INTO users (domain_and_username, telegram_id, is_bypass) '
        'VALUES (?, ?, ?)'
    )
    async with aiosqlite.connect(DATABASE_PATH) as db_conn:
        try:
            await db_conn.execute(sql_query,
                                  (user.domain_and_username, user.telegram_id, user.is_bypass))
            await db_conn.commit()
            return {"message": "User added successfully"}
        except aiosqlite.IntegrityError as integrity_error:
            raise HTTPException(
                status_code=400,
                detail="User already exists"
            ) from integrity_error


@app.get("/users/")
async def get_all_users(_: User = Depends(get_current_user)):
    """
    Fetches and returns a list of all users from the database.

    This function connects to the database asynchronously and retrieves all user records.
    Access is restricted to authenticated users only.

    Args:
        current_user (User): The authenticated user, obtained via dependency injection.

    Returns:
        List[dict]: A list of dictionaries, each representing a user record.
    """
    logger.info("get_all_users")
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        async with db_connection.execute('SELECT * FROM users') as cursor:
            users = await cursor.fetchall()
            return users


@app.delete("/users/{domain_and_username}")
async def delete_user(domain_and_username: str, _: User = Depends(get_current_user)):
    """
    Retrieves all users from the database.

    Connects asynchronously to the database and fetches records from the 'users' table.
    Accessible only to authenticated users.

    Args:
        _ (User): The current authenticated user, via dependency injection.

    Returns:
        List: A list of user records with all fields from the 'users' table.

    Note:
    Intended for administrative use. Access should be restricted to authorized users.
    """
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        await db_connection.execute(
            'DELETE FROM users WHERE domain_and_username = ?', (domain_and_username,))
        await db_connection.commit()
        return {"message": "User deleted successfully"}


@app.get("/verify-token")
async def verify_token(_: User = Depends(get_current_user)):
    """
    Verifies the validity of the user's authentication token.

    This endpoint checks if the provided JWT token is valid. It is accessible only to
    authenticated users, as it uses the dependency `get_current_user` to validate the
    token.

    Args:
        _ (User): The authenticated user, verified by the JWT token.

    Returns:
        dict: A message confirming the token is valid.

    This endpoint is useful for frontend applications to validate user sessions.
    """
    return {"message": "Token is valid"}

# Function for user update


@app.put("/users/{username}")
async def update_user(
    username: str,
    user_update: Optional[User] = None,
    _: User = Depends(get_current_user)
):
    """
    Updates the specified user's information in the database.

    This endpoint allows updating user data such as domain_and_username, telegram_id, and
    is_bypass flag for a given username. It is accessible only to authenticated users.

    Args:
        username (str): The username of the user to be updated.
        user_update (User): Object containing the updated data.
        _ (User): The authenticated user, verified by the JWT token.

    Raises:
        HTTPException: 404 error if the user is not found, 400 error for unique constraint
                       violations, and 500 error for unexpected database errors.

    Returns:
        dict: A confirmation message upon successful update of the user.
    """
    if user_update is None:  # Проверка на None
        raise HTTPException(status_code=400, detail="User update data is required")

    username = username.lower()
    user_update.domain_and_username = user_update.domain_and_username.lower()
    logger.info("Updating user")
    try:
        async with aiosqlite.connect(DATABASE_PATH) as db_connection:
            # Checking user existence
            cursor = await db_connection.execute(
                'SELECT * FROM users WHERE domain_and_username = ?', (username,))
            existing_user = await cursor.fetchone()
            if not existing_user:
                raise HTTPException(status_code=404, detail=ERROR404)

            # Updating user data
            await db_connection.execute('''
                UPDATE users SET domain_and_username = ?, telegram_id = ?, is_bypass = ? 
                WHERE domain_and_username = ?''',
                                        (user_update.domain_and_username,
                                         user_update.telegram_id, user_update.is_bypass, username))
            await db_connection.commit()
            return {"message": "User updated successfully"}

    except IntegrityError as error:
        if "UNIQUE constraint failed" in str(error):
            logger.error("Unique constraint error: %s", error)
            raise HTTPException(
                status_code=400, detail="User with this domain_and_username"
                "already exists") from error
        logger.error("Database integrity error: %s", error)
        raise HTTPException(
            status_code=500, detail="Database integrity error") from error

    except Exception as error:
        logger.error("Unexpected error: %s", error)
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred") from error


@app.get("/users/{username}")
async def get_user(username: str, db_connection=Depends(get_db),
                   _: User = Depends(get_current_user)):
    """
    Retrieves a specific user by username from the database.

    Args:
        username (str): Username of the user to retrieve.
        db_connection: Database connection dependency.
        _ (User): Placeholder for the authenticated user. Used for authentication check.

    Returns:
        dict: A dictionary containing the user's information if found.

    Raises:
        HTTPException: 404 error if the user is not found.
    """
    async with db_connection.execute(
            'SELECT * FROM users WHERE domain_and_username = ?', (username,)) as cursor:
        user = await cursor.fetchone()
        if user:
            return {"domain_and_username": user[0], "telegram_id": user[1], "is_bypass": user[2]}
        raise HTTPException(status_code=404, detail=ERROR404)


@app.get("/health")
async def health_check():
    """
    Health check endpoint.

    This endpoint provides a simple way to check if the service is up and running.
    It's useful for monitoring and automation purposes, like in Kubernetes liveness
    and readiness probes.

    Returns:
        dict: A dictionary with the status of the service.
    """
    return {"status": "ok"}


async def init_admin_db():
    """
    Initializes the admin database.

    Creates the 'admins' table if it does not exist and adds a default admin user
    if not already present. The default admin is useful for initial setup and testing.
    """
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        await db_connection.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                hashed_password TEXT,
                last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await db_connection.commit()

        # Check if the admin user already exists
        async with db_connection.execute(
                'SELECT username FROM admins WHERE username = ?', ('admin',)) as cursor:
            if await cursor.fetchone() is None:
                # Add a default administrator if you don't already have one
                default_admin = "admin"
                default_password_hash = await generate_password_hash("admin")
                await db_connection.execute(
                    'INSERT INTO admins (username, hashed_password) VALUES (?, ?)',
                    (default_admin, default_password_hash))
                await db_connection.commit()


@app.post("/auth/admin")
async def admin_auth(auth_details: AdminAuth):
    """
    Authenticates an admin user.

    Verifies the admin's credentials and returns an access token if authentication is
    successful. The token is used for accessing protected admin endpoints.

    Args:
        auth_details (AdminAuth): Authentication details including username and password.

    Returns:
        dict: Access token and token type if authentication is successful.

    Raises:
        HTTPException: 401 error if the username or password is incorrect.
    """
    # User verification
    user = await authenticate_user(auth_details.username, auth_details.password)
    if not user:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password")
    # Token creation
    access_token = create_access_token(
        data={"sub": user["username"]}, scopes=["admin"])
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/change-password")
async def change_password(password_change: PasswordChange,
                          _: User = Depends(get_current_user)):
    """
    Allows the authenticated user to change their password.

    This endpoint updates the user's password after verifying the old password.
    It is accessible only to the authenticated user.

    Args:
        password_change (PasswordChange): Object containing the old and new passwords.

    Raises:
        HTTPException: 403 error if the old password is incorrect.
                       404 error if the user is not found.

    Returns:
        dict: A message indicating successful password change.
    """

    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        # Getting hashed current password from the database
        async with db_connection.execute(
            'SELECT hashed_password FROM admins WHERE username = ?',
                ("admin",)) as cursor:
            current_hashed_password = await cursor.fetchone()

            if current_hashed_password is None:
                raise HTTPException(status_code=404, detail=ERROR404)

            # Checking old password
            if not pwd_context.verify(password_change.old_password, current_hashed_password[0]):
                raise HTTPException(
                    status_code=403, detail="Old password is incorrect")

            # Password update
            new_hashed_password = await generate_password_hash(password_change.new_password)
            await db_connection.execute(
                'UPDATE admins SET hashed_password = ? WHERE username = ?',
                (new_hashed_password, "admin"))
            await db_connection.commit()

    return {"message": "Password changed successfully"}


@app.post("/reset-password")
async def reset_password(request: ResetPasswordRequest):
    """
    Resets the password of the admin user to a default value.

    This endpoint is used to reset the admin password using a secret key. The new
    password is set to a predefined default ('admin').

    Args:
        request (ResetPasswordRequest): Request object containing the secret key.

    Raises:
        HTTPException: 403 error if password reset is not enabled.
                       401 error if the secret key is invalid.

    Returns:
        dict: A message indicating successful password reset.
    """
    secret_key = request.secret_key
    if not RESET_PASSWORD:
        raise HTTPException(
            status_code=403, detail="Password reset not enabled")

    if secret_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid secret key")

    # Reset admin password to 'admin'
    new_hashed_password = await generate_password_hash("admin")
    async with aiosqlite.connect(DATABASE_PATH) as db_connection:
        await db_connection.execute(
            'UPDATE admins SET hashed_password = ? WHERE username = ?',
            (new_hashed_password, "admin"))
        await db_connection.commit()

    return {"message": "Password reset successfully"}


@app.get("/reset-password-enabled")
async def is_reset_password_enabled():
    """
    Checks if the password reset functionality is enabled.

    This endpoint provides a simple way to check if the application's password reset feature
    is enabled or disabled. It can be used by frontend applications to conditionally display
    password reset options.

    Returns:
        dict: A dictionary with a boolean value indicating if the password reset is enabled.
    """
    return {"resetPasswordEnabled": RESET_PASSWORD}


if __name__ == "__main__":
    uvicorn.run(
        app=app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        log_config=logging_config,
        ssl_keyfile="/app/certs/free2fa_admin_api.key",
        ssl_certfile="/app/certs/free2fa_admin_api.crt"
    )
