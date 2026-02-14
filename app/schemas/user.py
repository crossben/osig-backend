"""
OSIG Backend - User Schemas

Pydantic schemas for user-related requests and responses.
"""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from app.models.user import UserPlan


# Base User Schema
class UserBase(BaseModel):
    """Base user schema with common fields."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = None


# User Registration
class UserCreate(UserBase):
    """Schema for user registration."""
    password: str = Field(..., min_length=8, max_length=100)


# User Login
class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


# User Response
class UserResponse(UserBase):
    """Schema for user response (without password)."""
    id: str
    plan: UserPlan
    avatar_url: Optional[str] = None
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# User Update
class UserUpdate(BaseModel):
    """Schema for updating user profile."""
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None


# Password Change
class PasswordChange(BaseModel):
    """Schema for changing password."""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


# Token Response
class Token(BaseModel):
    """Schema for authentication token response."""
    access_token: str
    token_type: str = "bearer"


# Auth Response (includes user and token)
class AuthResponse(BaseModel):
    """Schema for authentication response with user and token."""
    user: UserResponse
    access_token: str
    token_type: str = "bearer"
