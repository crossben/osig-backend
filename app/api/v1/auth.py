"""
OSIG Backend - Authentication API Endpoints

Handles user registration, login, and profile management.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_user
from app.schemas.user import UserCreate, UserLogin, UserResponse, AuthResponse
from app.services.auth_service import auth_service
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
    
    - **email**: Valid email address
    - **username**: Unique username (3-50 characters)
    - **password**: Strong password (min 8 characters)
    - **full_name**: Optional full name
    
    Returns user object and JWT access token.
    """
    # Create user
    user = auth_service.create_user(db, user_data)
    
    # Generate token
    access_token = auth_service.create_user_token(user)
    
    return AuthResponse(
        user=UserResponse.model_validate(user),
        access_token=access_token,
        token_type="bearer"
    )


@router.post("/login", response_model=AuthResponse)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Login with email and password.
    
    - **email**: Registered email address
    - **password**: User password
    
    Returns user object and JWT access token.
    """
    # Authenticate user
    user = auth_service.authenticate_user(db, credentials)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account"
        )
    
    # Generate token
    access_token = auth_service.create_user_token(user)
    
    return AuthResponse(
        user=UserResponse.model_validate(user),
        access_token=access_token,
        token_type="bearer"
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """
    Get current authenticated user profile.
    
    Requires valid JWT token in Authorization header.
    """
    return UserResponse.model_validate(current_user)
