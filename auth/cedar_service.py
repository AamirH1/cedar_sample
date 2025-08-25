"""
Cedar Policy Service - BEST APPROACH VERSION
Handles Cedar policy evaluation and user authentication with hierarchical features
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from cedarpy import is_authorized, AuthzResult
from auth.jwt_handler import verify_password

logger = logging.getLogger(__name__)

class CedarService:
    """
    Service for handling Cedar policy evaluation and user management
    """
    
    def __init__(self):
        self.users: Dict = {}
        self.entities: List = []
        self.policies: str = ""
        self.config_path = Path(__file__).parent.parent / "config"
        self.feature_hierarchy = self._build_feature_hierarchy()
    
    def _build_feature_hierarchy(self) -> Dict[str, Dict]:
        """Build the feature hierarchy structure"""
        return {
            "feature1": {
                "type": "feature",
                "display_name": "feature1", # Placeholder name: start with capital letter and spaces if needed
                "sub_features": []
            },
            "feature2": {
                "type": "feature",
                "display_name": "feature2", # Placeholder name: start with capital letter and spaces
                "sub_features": [
                    {"name": "subfeature1", "display_name": "subfeature1"}, # Placeholder name: start with capital letter and spaces
                    {"name": "subfeature4", "display_name": "subfeature4"}, # Placeholder name: start with capital letter and spaces
                    {"name": "subfeature2", "display_name": "subfeature2"},
                    {"name": "subfeature3", "display_name": "subfeature3"}
                ]
            }
        }
    
    async def initialize(self):
        """Initialize Cedar service with configuration files"""
        try:
            # Load users
            with open(self.config_path / "users.json", "r") as f:
                self.users = json.load(f)
            
            # Load entities
            with open(self.config_path / "entities.json", "r") as f:
                self.entities = json.load(f)
            
            # Load policies
            with open(self.config_path / "policies.cedar", "r") as f:
                self.policies = f.read()
            
            logger.info("Cedar service configuration loaded successfully")
            logger.info(f"Loaded {len(self.users)} users, {len(self.entities)} entities")
            
        except Exception as e:
            logger.error(f"Failed to initialize Cedar service: {str(e)}")
            raise
    
    async def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user credentials
        """
        user = self.users.get(username)
        if not user:
            logger.warning(f"User {username} not found")
            return None
        
        if verify_password(password, user["password_hash"]):
            return {
                "user_id": user["user_id"],
                "username": username,
                "persona": user["persona"]
            }
        
        logger.warning(f"Password verification failed for user {username}")
        return None
    
    async def evaluate_policy(
        self, 
        username: str,
        feature: str, 
        context: Dict[str, Any],
        sub_feature: Optional[str] = None
    ) -> bool:
        """
        Evaluate Cedar policy for user access to a feature or sub-feature
        """
        try:
            eval_context = context.copy()

            # Determine resource type and ID
            if sub_feature:
                resource_type = "SubFeature"
                resource_id = sub_feature
            else:
                resource_type = "Feature"
                resource_id = feature
            
            request = {
                "principal": f'User::"{username}"',
                "action": 'Action::"access"',
                "resource": f'{resource_type}::"{resource_id}"',
                "context": eval_context
            }
            
            logger.debug(f"Cedar request: {request}")
            
            # Evaluate with Cedar
            authz_result: AuthzResult = is_authorized(request, self.policies, self.entities)
            
            logger.debug(f"Cedar evaluation: user={username}, resource={resource_type}::{resource_id}, authorized={authz_result.allowed}")
            
            return authz_result.allowed
            
        except Exception as e:
            logger.error(f"Cedar policy evaluation error: {str(e)}")
            logger.error(f"Request was: {locals()}")
            return False
    
    async def get_user_allowed_features(self, username: str) -> Dict[str, Any]:
        """
        Get hierarchical list of features and sub-features user is allowed to access.
        
        Logic:
        - allowed: True if user has ANY access to the feature (main feature OR any sub-features)
        - full_feature_access: True only if user has access to the main feature itself
        - sub_features: List of allowed sub-features
        
        This approach is most intuitive for UI/UX - if user can access any part of a feature group,
        the feature shows as "allowed" with details about what specifically they can access.
        """
        allowed_structure = {}
        
        logger.info(f"Getting allowed features for user {username}")
        
        for feature_name, feature_info in self.feature_hierarchy.items():
            logger.debug(f"Checking feature: {feature_name}")
            
            # Check main feature access
            feature_allowed = await self.evaluate_policy(
                username, feature_name, {}
            )
            
            logger.debug(f"Main feature {feature_name} allowed: {feature_allowed}")
            
            # Check all sub-features
            allowed_sub_features = []
            for sub_feature in feature_info.get("sub_features", []):
                sub_feature_name = sub_feature["name"]
                sub_feature_allowed = await self.evaluate_policy(
                    username, feature_name, {}, sub_feature_name
                )
                
                logger.debug(f"Sub-feature {feature_name}.{sub_feature_name} allowed: {sub_feature_allowed}")
                
                if sub_feature_allowed:
                    allowed_sub_features.append({
                        "name": sub_feature_name,
                        "display_name": sub_feature["display_name"],
                        "allowed": True
                    })
            
            # BEST APPROACH: Include feature if user has ANY access
            has_any_access = feature_allowed or len(allowed_sub_features) > 0
            
            if has_any_access:
                allowed_structure[feature_name] = {
                    "allowed": True,  # True if ANY access (main feature or sub-features)
                    "full_feature_access": feature_allowed,  # True only if main feature access
                    "display_name": feature_info["display_name"],
                    "sub_features": allowed_sub_features,
                    "access_type": "full" if feature_allowed else "partial"  # Helper field for UI
                }
                
                logger.info(f"Feature {feature_name}: allowed=True, full_access={feature_allowed}, sub_features_count={len(allowed_sub_features)}")
        
        logger.info(f"User {username} has access to {len(allowed_structure)} feature groups")
        return allowed_structure
    
    async def get_user_allowed_features_flat(self, username: str) -> List[str]:
        """
        Get flat list of all allowed features and sub-features for quick permission checks
        """
        allowed_features = []
        hierarchy = await self.get_user_allowed_features(username)
        
        for feature_name, feature_data in hierarchy.items():
            # Always include the feature name if user has any access
            allowed_features.append(feature_name)
            
            # Add sub-features with dot notation
            for sub_feature in feature_data.get("sub_features", []):
                if sub_feature["allowed"]:
                    allowed_features.append(f"{feature_name}.{sub_feature['name']}")
        
        return allowed_features
    
    async def check_specific_access(self, username: str, feature: str, sub_feature: Optional[str] = None) -> bool:
        """
        Quick method to check if user has access to a specific feature or sub-feature
        """
        return await self.evaluate_policy(username, feature, {}, sub_feature)
