"""
Authentication Models with dynamic group-based authorization
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class AccessType(str, Enum):
    FULL = "full"
    PARTIAL = "partial"

class AuthenticateRequest(BaseModel):
    """Authentication request with dynamic groups"""
    feature: str = Field(..., description="Main feature name")
    sub_feature: Optional[str] = Field(None, description="Sub-feature name")
    groups: List[str] = Field(..., description="List of group UUIDs for authorization")
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional context for policy evaluation"
    )

class SubFeature(BaseModel):
    """Sub-feature model"""
    name: str = Field(..., description="Sub-feature name")
    display_name: str = Field(..., description="Display name")
    allowed: bool = Field(..., description="Access allowed")

class FeatureAccess(BaseModel):
    """Enhanced feature access model"""
    allowed: bool = Field(..., description="Has some level of access to this feature group")
    full_feature_access: bool = Field(..., description="Has full access to main feature")
    display_name: str = Field(..., description="Feature display name")
    sub_features: List[SubFeature] = Field(default_factory=list, description="Allowed sub-features")
    access_type: AccessType = Field(..., description="Type of access: full or partial")

class AuthResponse(BaseModel):
    """Authentication response model"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    authorized: bool = Field(..., description="Authorization status")
    user_id: Optional[str] = Field(None, description="User ID")
    username: Optional[str] = Field(None, description="Username")
    persona: Optional[str] = Field(None, description="User persona/role")
    groups: Optional[List[str]] = Field(None, description="Groups from request")
    allowed_features: Dict[str, FeatureAccess] = Field(
        default_factory=dict,
        description="Hierarchical feature access"
    )
    allowed_features_flat: List[str] = Field(
        default_factory=list,
        description="Flat list of allowed features"
    )
    requested_feature: Optional[str] = Field(None, description="Requested feature")
    requested_sub_feature: Optional[str] = Field(None, description="Requested sub-feature")
    access_summary: Optional[Dict[str, int]] = Field(
        None,
        description="Summary of access levels"
    )
