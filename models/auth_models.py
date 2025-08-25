"""
Authentication Models
Pydantic models for request/response handling
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class LoginRequest(BaseModel):
    """Login request model"""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")

class FeatureRequest(BaseModel):
    """Feature access request model"""
    feature: str = Field(..., description="Requested feature name")
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional context for policy evaluation"
    )

class AuthResponse(BaseModel):
    """Authentication response model"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    authorized: bool = Field(..., description="Authorization status")
    user_id: Optional[str] = Field(None, description="User ID")
    username: Optional[str] = Field(None, description="Username")
    persona: Optional[str] = Field(None, description="User persona/role")
    allowed_features: List[str] = Field(
        default_factory=list,
        description="List of features user can access"
    )
    requested_feature: Optional[str] = Field(
        None,
        description="Feature that was requested for authorization"
    )
