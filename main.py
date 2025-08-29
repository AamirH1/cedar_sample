"""
FastAPI Authentication Service with Dynamic Group-based Authorization
Removes all hardcoded user/group dependencies
"""

from fastapi import FastAPI, HTTPException, Depends, status
from typing import Dict, Any
import logging
from contextlib import asynccontextmanager

from auth.jwt_handler import decode_jwt
from auth.auth_bearer import JWTBearer
from auth.cedar_service import CedarService
from models.auth_models import AuthenticateRequest, AuthResponse, FeatureAccess, AccessType
from utils.logger import setup_logger

# Initialize services
logger = setup_logger()
cedar_service = CedarService()
jwt_bearer = JWTBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown events"""
    # Startup
    logger.info("Starting Dynamic Cedar Authentication Service")
    await cedar_service.initialize()
    logger.info("Cedar service initialized successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Cedar service")

app = FastAPI(
    title="Dynamic Cedar Authentication Service",
    description="Authentication service using dynamic group-based authorization",
    version="4.0.0",
    lifespan=lifespan
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "cedar-auth-dynamic", "version": "4.0.0"}

@app.post("/authenticate", response_model=AuthResponse)
async def authenticate(
    auth_request: AuthenticateRequest,
    token: str = Depends(jwt_bearer)
):
    """
    Authenticate user access using dynamic groups from request payload
    """
    try:
        # Validate JWT token structure and expiry only
        payload = decode_jwt(token)
        if not payload:
            logger.warning("Invalid JWT token provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        username = payload.get("sub")
        user_id = payload.get("user_id")
        persona = payload.get("persona")
        
        # Use groups from request payload ONLY (ignore any token claims)
        request_groups = auth_request.groups
        
        logger.info(f"Processing auth request for user {username} with groups {request_groups}")
        
        # Evaluate Cedar policy using dynamic groups
        is_authorized = await cedar_service.evaluate_policy_dynamic(
            username=username,
            feature=auth_request.feature,
            groups=request_groups,
            context=auth_request.context or {},
            sub_feature=auth_request.sub_feature
        )
        
        # Handle focused responses for sub-feature requests
        allowed_features_response = {}
        allowed_features_flat = []
        access_summary = None
        
        if auth_request.sub_feature:
            # SPECIFIC SUB-FEATURE REQUEST - Return only requested sub-feature info
            requested_feature = auth_request.feature
            requested_sub_feature = auth_request.sub_feature
            
            feature_info = cedar_service.feature_hierarchy.get(requested_feature, {})
            sub_feature_info = None
            for sf in feature_info.get("sub_features", []):
                if sf["name"] == requested_sub_feature:
                    sub_feature_info = sf
                    break
            
            if sub_feature_info:
                allowed_features_response[requested_feature] = FeatureAccess(
                    allowed=is_authorized,
                    full_feature_access=False,
                    display_name=feature_info.get("display_name", requested_feature),
                    access_type=AccessType.PARTIAL,
                    sub_features=[{
                        "name": requested_sub_feature,
                        "display_name": sub_feature_info.get("display_name", requested_sub_feature),
                        "allowed": is_authorized
                    }]
                )
                
                if is_authorized:
                    allowed_features_flat = [requested_feature, f"{requested_feature}.{requested_sub_feature}"]
                    access_summary = {"full_access": 0, "partial_access": 1, "total_features": 1}
                else:
                    allowed_features_flat = []
                    access_summary = {"full_access": 0, "partial_access": 0, "total_features": 0}
        
        elif is_authorized:
            # MAIN FEATURE REQUEST - AUTHORIZED: Return all user's features
            allowed_features_dict = await cedar_service.get_user_features_dynamic(username, request_groups)
            access_summary = {"full_access": 0, "partial_access": 0, "total_features": 0}
            
            for feature_name, feature_data in allowed_features_dict.items():
                allowed_features_response[feature_name] = FeatureAccess(**feature_data)
                allowed_features_flat.append(feature_name)
                
                if feature_data["access_type"] == "full":
                    access_summary["full_access"] += 1
                else:
                    access_summary["partial_access"] += 1
                access_summary["total_features"] += 1
                
                for sub_feature in feature_data.get("sub_features", []):
                    if sub_feature["allowed"]:
                        allowed_features_flat.append(f"{feature_name}.{sub_feature['name']}")
        
        else:
            # MAIN FEATURE REQUEST - NOT AUTHORIZED
            requested_feature = auth_request.feature
            all_user_features = await cedar_service.get_user_features_dynamic(username, request_groups)
            
            # Only include requested feature if user has partial access to it
            if requested_feature in all_user_features:
                feature_data = all_user_features[requested_feature]
                allowed_features_response[requested_feature] = FeatureAccess(**feature_data)
                allowed_features_flat.append(requested_feature)
                
                for sub_feature in feature_data.get("sub_features", []):
                    if sub_feature["allowed"]:
                        allowed_features_flat.append(f"{requested_feature}.{sub_feature['name']}")
                
                access_summary = {
                    "full_access": 1 if feature_data["access_type"] == "full" else 0,
                    "partial_access": 1 if feature_data["access_type"] == "partial" else 0,
                    "total_features": 1
                }
            else:
                # No access to requested feature at all
                allowed_features_response = {}
                allowed_features_flat = []
                access_summary = {"full_access": 0, "partial_access": 0, "total_features": 0}
        
        # Log authorization decision
        resource_desc = f"{auth_request.feature}"
        if auth_request.sub_feature:
            resource_desc += f".{auth_request.sub_feature}"
        
        logger.info(
            f"Authorization decision for user {username}, "
            f"resource {resource_desc}, groups {request_groups}: {is_authorized}"
        )
        
        return AuthResponse(
            access_token=token,
            token_type="bearer",
            authorized=is_authorized,
            user_id=user_id,
            username=username,
            persona=persona,
            groups=request_groups,
            allowed_features=allowed_features_response,
            allowed_features_flat=allowed_features_flat,
            requested_feature=auth_request.feature,
            requested_sub_feature=auth_request.sub_feature,
            access_summary=access_summary
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
