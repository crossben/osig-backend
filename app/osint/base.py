"""
Base OSINT Module

This module provides the base class and data structures for all OSINT modules.
All OSINT implementations must inherit from BaseOSINTModule to ensure consistency.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import logging

# Set up logging for OSINT modules
logger = logging.getLogger(__name__)


class OSINTResult(BaseModel):
    """
    Standardized result format for all OSINT modules.
    
    This ensures all modules return data in a consistent format that can be
    easily stored in the database and displayed to users.
    """
    # Source information
    source: str = Field(..., description="Name of the OSINT tool/service (e.g., 'Holehe', 'Sherlock')")
    source_url: Optional[str] = Field(None, description="URL to the finding if available")
    
    # Result data
    data_type: str = Field(..., description="Type of data found (e.g., 'social_profile', 'email_account')")
    data: Dict[str, Any] = Field(..., description="The actual finding data in flexible JSON format")
    
    # Metadata
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score (0.0 - 1.0)")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When this result was found")
    
    class Config:
        json_schema_extra = {
            "example": {
                "source": "Holehe",
                "source_url": "https://github.com/megadose/holehe",
                "data_type": "email_account",
                "data": {
                    "platform": "GitHub",
                    "exists": True,
                    "url": "https://github.com"
                },
                "confidence": 0.95,
                "timestamp": "2024-02-14T20:00:00Z"
            }
        }


class BaseOSINTModule(ABC):
    """
    Abstract base class for all OSINT modules.
    
    Every OSINT module (Email, Username, Domain, Phone) must inherit from this class
    and implement the run() method. This ensures all modules have a consistent interface.
    
    Usage:
        class EmailIntelModule(BaseOSINTModule):
            def run(self, target: str) -> List[OSINTResult]:
                # Implementation here
                pass
    """
    
    def __init__(self, name: str, display_name: str):
        """
        Initialize the OSINT module.
        
        Args:
            name: Internal identifier for the module (e.g., 'email_intel')
            display_name: User-friendly name (e.g., 'Email Intelligence')
        """
        self.name = name
        self.display_name = display_name
        self.logger = logging.getLogger(f"osint.{name}")
    
    @abstractmethod
    def run(self, target: str) -> List[OSINTResult]:
        """
        Execute the OSINT module and return findings.
        
        This method MUST be implemented by all subclasses.
        
        Args:
            target: The target to investigate (email, username, domain, or phone)
            
        Returns:
            List of OSINTResult objects containing all findings
            
        Raises:
            Exception: If the module execution fails
        """
        pass
    
    def log_start(self, target: str):
        """Log the start of module execution."""
        self.logger.info(f"Starting {self.display_name} for target: {target}")
    
    def log_success(self, result_count: int):
        """Log successful completion."""
        self.logger.info(f"{self.display_name} completed. Found {result_count} results.")
    
    def log_error(self, error: Exception):
        """Log errors during execution."""
        self.logger.error(f"{self.display_name} failed: {str(error)}", exc_info=True)
    
    def validate_target(self, target: str, expected_type: str) -> bool:
        """
        Validate that the target matches expected format.
        
        Args:
            target: The target string to validate
            expected_type: Type of target ('email', 'username', 'domain', 'phone')
            
        Returns:
            True if valid, False otherwise
        """
        if not target or not target.strip():
            return False
        
        # Basic validation based on type
        if expected_type == "email":
            return "@" in target and "." in target.split("@")[-1]
        elif expected_type == "username":
            return len(target) >= 3 and target.replace("_", "").replace("-", "").isalnum()
        elif expected_type == "domain":
            return "." in target and " " not in target
        elif expected_type == "phone":
            # Basic check for digits and common phone characters
            return any(c.isdigit() for c in target)
        
        return True
