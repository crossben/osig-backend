"""
OSIG Backend - Authentication Service

Business logic for user authentication and management.
"""
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.user import User, UserPlan
from app.schemas.user import UserCreate, UserLogin
from app.core.security import verify_password, get_password_hash, create_access_token


class AuthService:
    """Service for authentication operations."""
    
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Get user by email."""
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[User]:
        """Get user by username."""
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def create_user(db: Session, user_data: UserCreate) -> User:
        """
        Create a new user.
        
        Args:
            db: Database session
            user_data: User registration data
            
        Returns:
            Created user object
            
        Raises:
            HTTPException: If email or username already exists
        """
        # Check if email exists
        if AuthService.get_user_by_email(db, user_data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Check if username exists
        if AuthService.get_user_by_username(db, user_data.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        
        # Create user
        db_user = User(
            email=user_data.email,
            username=user_data.username,
            full_name=user_data.full_name,
            hashed_password=get_password_hash(user_data.password),
            plan=UserPlan.FREE,  # Default to free plan
            is_active=True,
            is_superuser=False,
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        return db_user
    
    @staticmethod
    def authenticate_user(db: Session, credentials: UserLogin) -> Optional[User]:
        """
        Authenticate user with email and password.
        
        Args:
            db: Database session
            credentials: Login credentials
            
        Returns:
            User object if authentication successful, None otherwise
        """
        user = AuthService.get_user_by_email(db, credentials.email)
        
        if not user:
            return None
        
        if not verify_password(credentials.password, user.hashed_password):
            return None
        
        return user
    
    @staticmethod
    def create_user_token(user: User) -> str:
        """
        Create JWT access token for user.
        
        Args:
            user: User object
            
        Returns:
            JWT access token
        """
        # "sv" ties the token to the user's current session version (revocation)
        return create_access_token(data={"sub": str(user.id), "sv": user.session_version or 0})


# Service instance
auth_service = AuthService()
