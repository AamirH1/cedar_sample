"""
FastAPI Authentication Service with Cedar Policy Integration
A microservice for handling authentication and authorization using Cedar policies.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import logging
from pathlib import Path

from auth.jwt_handler import create_access_token, decode_jwt
from auth.auth_bearer import JWTBearer
from auth.cedar_service import CedarService
from models.auth_models import LoginRequest, AuthResponse, FeatureRequest
from utils.logger import setup_logger

# Initialize FastAPI app
app = FastAPI(
    title="Cedar Authentication Service",
    description="Authentication and authorization service using Cedar policies",
    version="1.0.0"
)

# Setup logging
logger = setup_logger()

# Initialize Cedar service
cedar_service = CedarService()

# JWT Bearer security
security = HTTPBearer()
jwt_bearer = JWTBearer()

@app.on_event("startup")
async def startup_event():
    """Initialize service on startup"""
    logger.info("Starting Cedar Authentication Service")
    await cedar_service.initialize()
    logger.info("Cedar service initialized successfully")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "cedar-auth"}

@app.post("/login", response_model=AuthResponse)
async def login(login_data: LoginRequest):
    """
    Authenticate user and return JWT token
    
    Args:
        login_data: Username and password credentials
        
    Returns:
        AuthResponse with JWT token and user info
    """
    try:
        # Authenticate user
        user_info = await cedar_service.authenticate_user(
            login_data.username, 
            login_data.password
        )
        
        if not user_info:
            logger.warning(f"Failed login attempt for user: {login_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Create JWT token
        token_data = {
            "sub": user_info["username"],
            "persona": user_info["persona"],
            "user_id": user_info["user_id"]
        }
        access_token = create_access_token(data=token_data)
        
        # Get allowed features for user
        allowed_features = await cedar_service.get_user_allowed_features(
            user_info["username"], 
            user_info["persona"]
        )
        
        logger.info(f"Successful login for user: {login_data.username}")
        
        return AuthResponse(
            access_token=access_token,
            token_type="bearer",
            authorized=True,
            user_id=user_info["user_id"],
            username=user_info["username"],
            persona=user_info["persona"],
            allowed_features=allowed_features
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/authenticate", response_model=AuthResponse)
async def authenticate(
    feature_request: FeatureRequest,
    token: str = Depends(jwt_bearer)
):
    """
    Authenticate user access to specific features using Cedar policies
    
    Args:
        feature_request: Requested feature and optional context
        token: JWT token from Authorization header
        
    Returns:
        AuthResponse indicating authorization status
    """
    try:
        # Decode JWT token
        payload = decode_jwt(token)
        if not payload:
            logger.warning("Invalid JWT token provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        username = payload.get("sub")
        persona = payload.get("persona")
        user_id = payload.get("user_id")
        
        # Evaluate Cedar policy
        is_authorized = await cedar_service.evaluate_policy(
            username=username,
            persona=persona,
            feature=feature_request.feature,
            context=feature_request.context or {}
        )
        
        # Get allowed features if authorized
        allowed_features = []
        if is_authorized:
            allowed_features = await cedar_service.get_user_allowed_features(
                username, persona
            )
        
        # Log authorization decision
        logger.info(
            f"Authorization decision for user {username}, "
            f"feature {feature_request.feature}: {is_authorized}"
        )
        
        return AuthResponse(
            access_token=token,
            token_type="bearer",
            authorized=is_authorized,
            user_id=user_id,
            username=username,
            persona=persona,
            allowed_features=allowed_features if is_authorized else [],
            requested_feature=feature_request.feature
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
