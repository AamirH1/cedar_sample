"""
FastAPI Authentication Service with Cedar Policy Integration
Supports hierarchical feature access control with intelligent access grouping
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer
from typing import Dict, Any
import logging
from contextlib import asynccontextmanager

from auth.jwt_handler import create_access_token, decode_jwt
from auth.auth_bearer import JWTBearer
from auth.cedar_service import CedarService
from models.auth_models import LoginRequest, AuthResponse, FeatureRequest, FeatureAccess, AccessType
from utils.logger import setup_logger

# Initialize services
logger = setup_logger()
cedar_service = CedarService()
jwt_bearer = JWTBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown events"""
    # Startup
    logger.info("Starting Cedar Authentication Service with Hierarchical Features")
    await cedar_service.initialize()
    logger.info("Cedar service initialized successfully")
    
    yield
    
    # Shutdown (if needed)
    logger.info("Shutting down Cedar service")

app = FastAPI(
    title="Cedar Authentication Service with Hierarchical Features",
    description="Authentication and authorization service using Cedar policies with intelligent access grouping",
    version="2.1.0",
    lifespan=lifespan
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "cedar-auth-hierarchical", "version": "2.1.0"}

@app.post("/login", response_model=AuthResponse)
async def login(login_data: LoginRequest):
    """
    Authenticate user and return JWT token with hierarchical permissions
    """
    try:
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
        
        # Get hierarchical allowed features
        allowed_features_dict = await cedar_service.get_user_allowed_features(
            user_info["username"]
        )
        
        # Convert to response format and create flat list of permissions
        allowed_features_response = {}
        allowed_features_flat = []
        access_summary = {"full_access": 0, "partial_access": 0, "total_features": 0}
        
        for feature_name, feature_data in allowed_features_dict.items():
            allowed_features_response[feature_name] = FeatureAccess(**feature_data)
            allowed_features_flat.append(feature_name)  # Feature group is always added
            
            # Count access types for summary
            if feature_data["access_type"] == "full":
                access_summary["full_access"] += 1
            else:
                access_summary["partial_access"] += 1
            access_summary["total_features"] += 1
            
            # Add sub-features to flat list
            for sub_feature in feature_data.get("sub_features", []):
                if sub_feature["allowed"]:
                    allowed_features_flat.append(f"{feature_name}.{sub_feature['name']}")
        
        logger.info(
            f"Successful login for user: {login_data.username} - "
            f"Access: {access_summary['full_access']} full, {access_summary['partial_access']} partial"
        )
        
        return AuthResponse(
            access_token=access_token,
            token_type="bearer",
            authorized=True,
            user_id=user_info["user_id"],
            username=user_info["username"],
            persona=user_info["persona"],
            allowed_features=allowed_features_response,
            allowed_features_flat=allowed_features_flat,
            access_summary=access_summary
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# @app.post("/authenticate", response_model=AuthResponse)
# async def authenticate(
#     feature_request: FeatureRequest,
#     token: str = Depends(jwt_bearer)
# ):
#     """
#     Authenticate user access to specific features/sub-features using Cedar policies
#     """
#     try:
#         payload = decode_jwt(token)
#         if not payload:
#             logger.warning("Invalid JWT token provided")
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid token"
#             )
        
#         username = payload.get("sub")
#         persona = payload.get("persona")
#         user_id = payload.get("user_id")
        
#         # Evaluate Cedar policy for feature/sub-feature
#         is_authorized = await cedar_service.evaluate_policy(
#             username=username,
#             feature=feature_request.feature,
#             context=feature_request.context or {},
#             sub_feature=feature_request.sub_feature
#         )
        
#         # FIXED: Only get features relevant to the requested feature
#         allowed_features_response = {}
#         allowed_features_flat = []
#         access_summary = None
        
#         if is_authorized:
#             # If authorized, get all user's allowed features for context
#             allowed_features_dict = await cedar_service.get_user_allowed_features(username)
#             access_summary = {"full_access": 0, "partial_access": 0, "total_features": 0}
            
#             for feature_name, feature_data in allowed_features_dict.items():
#                 allowed_features_response[feature_name] = FeatureAccess(**feature_data)
#                 allowed_features_flat.append(feature_name)
                
#                 # Count access types
#                 if feature_data["access_type"] == "full":
#                     access_summary["full_access"] += 1
#                 else:
#                     access_summary["partial_access"] += 1
#                 access_summary["total_features"] += 1
                
#                 # Add sub-features to flat list
#                 for sub_feature in feature_data.get("sub_features", []):
#                     if sub_feature["allowed"]:
#                         allowed_features_flat.append(f"{feature_name}.{sub_feature['name']}")
        
#         else:
#             # If NOT authorized, only show info about the requested feature if user has partial access to it
#             requested_feature = feature_request.feature
#             all_user_features = await cedar_service.get_user_allowed_features(username)
            
#             # Only include the requested feature if user has some access to it
#             if requested_feature in all_user_features:
#                 feature_data = all_user_features[requested_feature]
#                 allowed_features_response[requested_feature] = FeatureAccess(**feature_data)
#                 allowed_features_flat.append(requested_feature)
                
#                 # Add sub-features to flat list
#                 for sub_feature in feature_data.get("sub_features", []):
#                     if sub_feature["allowed"]:
#                         allowed_features_flat.append(f"{requested_feature}.{sub_feature['name']}")
                
#                 access_summary = {
#                     "full_access": 1 if feature_data["access_type"] == "full" else 0,
#                     "partial_access": 1 if feature_data["access_type"] == "partial" else 0,
#                     "total_features": 1
#                 }
            
#             # If user has NO access to requested feature, return empty
#             else:
#                 allowed_features_response = {}
#                 allowed_features_flat = []
#                 access_summary = {"full_access": 0, "partial_access": 0, "total_features": 0}
        
#         # Log authorization decision
#         resource_desc = f"{feature_request.feature}"
#         if feature_request.sub_feature:
#             resource_desc += f".{feature_request.sub_feature}"
        
#         logger.info(
#             f"Authorization decision for user {username}, "
#             f"resource {resource_desc}: {is_authorized}"
#         )
        
#         return AuthResponse(
#             access_token=token,
#             token_type="bearer",
#             authorized=is_authorized,
#             user_id=user_id,
#             username=username,
#             persona=persona,
#             allowed_features=allowed_features_response,
#             allowed_features_flat=allowed_features_flat,
#             requested_feature=feature_request.feature,
#             requested_sub_feature=feature_request.sub_feature,
#             access_summary=access_summary
#         )
        
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Authentication error: {str(e)}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Authentication service error"
#         )

@app.post("/authenticate", response_model=AuthResponse)
async def authenticate(
    feature_request: FeatureRequest,
    token: str = Depends(jwt_bearer)
):
    """
    Authenticate user access to specific features/sub-features using Cedar policies
    """
    try:
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
        
        # Evaluate Cedar policy for feature/sub-feature
        is_authorized = await cedar_service.evaluate_policy(
            username=username,
            feature=feature_request.feature,
            context=feature_request.context or {},
            sub_feature=feature_request.sub_feature
        )
        
        # FIXED: Handle responses based on request type and authorization
        allowed_features_response = {}
        allowed_features_flat = []
        access_summary = None
        
        if feature_request.sub_feature:
            # SPECIFIC SUB-FEATURE REQUEST
            requested_feature = feature_request.feature
            requested_sub_feature = feature_request.sub_feature
            
            # Get feature hierarchy info for display purposes
            feature_info = cedar_service.feature_hierarchy.get(requested_feature, {})
            sub_feature_info = None
            for sf in feature_info.get("sub_features", []):
                if sf["name"] == requested_sub_feature:
                    sub_feature_info = sf
                    break
            
            if sub_feature_info:
                # Create focused response with ONLY the requested sub-feature
                allowed_features_response[requested_feature] = FeatureAccess(
                    allowed=is_authorized,  # True only if sub-feature is authorized
                    full_feature_access=False,  # Never full access for sub-feature request
                    display_name=feature_info.get("display_name", requested_feature),
                    access_type="partial",  # Always partial for sub-feature
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
            allowed_features_dict = await cedar_service.get_user_allowed_features(username)
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
            requested_feature = feature_request.feature
            all_user_features = await cedar_service.get_user_allowed_features(username)
            
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
        resource_desc = f"{feature_request.feature}"
        if feature_request.sub_feature:
            resource_desc += f".{feature_request.sub_feature}"
        
        logger.info(
            f"Authorization decision for user {username}, "
            f"resource {resource_desc}: {is_authorized}"
        )
        
        return AuthResponse(
            access_token=token,
            token_type="bearer",
            authorized=is_authorized,
            user_id=user_id,
            username=username,
            persona=persona,
            allowed_features=allowed_features_response,
            allowed_features_flat=allowed_features_flat,
            requested_feature=feature_request.feature,
            requested_sub_feature=feature_request.sub_feature,
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


@app.get("/features/{username}")
async def get_user_features(username: str, token: str = Depends(jwt_bearer)):
    """Get hierarchical feature access for a user with access level details"""
    try:
        payload = decode_jwt(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Only allow users to see their own features (or admins to see any)
        requesting_user = payload.get("sub")
        requesting_persona = payload.get("persona")
        
        if requesting_user != username and requesting_persona not in ["admin", "developer"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view other user's features"
            )
        
        # Get user's persona from users.json
        user_data = cedar_service.users.get(username)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        allowed_features = await cedar_service.get_user_allowed_features(username)
        flat_features = await cedar_service.get_user_allowed_features_flat(username)
        
        # Create summary
        summary = {"full_access": 0, "partial_access": 0, "total_features": len(allowed_features)}
        for feature_data in allowed_features.values():
            if feature_data["access_type"] == "full":
                summary["full_access"] += 1
            else:
                summary["partial_access"] += 1
        
        return {
            "username": username,
            "persona": user_data["persona"],
            "features": allowed_features,
            "flat_features": flat_features,
            "summary": summary
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get features error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Service error"
        )

@app.post("/check-access")
async def check_specific_access(
    feature_request: FeatureRequest,
    token: str = Depends(jwt_bearer)
):
    """Quick endpoint to check specific feature/sub-feature access without full feature list"""
    try:
        payload = decode_jwt(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        username = payload.get("sub")
        
        has_access = await cedar_service.check_specific_access(
            username, 
            feature_request.feature, 
            feature_request.sub_feature
        )
        
        return {
            "username": username,
            "feature": feature_request.feature,
            "sub_feature": feature_request.sub_feature,
            "has_access": has_access
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Access check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Service error"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
