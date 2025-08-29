"""
Dynamic Cedar Policy Service
Handles authorization based purely on groups from request payload
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from cedarpy import is_authorized, AuthzResult

logger = logging.getLogger(__name__)

class CedarService:
    """
    Service for handling Cedar policy evaluation with dynamic group-based authorization
    """
    
    def __init__(self):
        self.policies: str = ""
        self.config_path = Path(__file__).parent.parent / "config"
        self.feature_hierarchy = self._build_feature_hierarchy()
    
    def _build_feature_hierarchy(self) -> Dict[str, Dict]:
        """Build the feature hierarchy structure"""
        return {
            "feature1": {
                "type": "feature",
                "display_name": "feature1",
                "sub_features": []
            },
            "feature2": {
                "type": "feature",
                "display_name": "feature2",
                "sub_features": [
                    {"name": "subfeature1", "display_name": "subfeature1"},
                    {"name": "subfeature2", "display_name": "subfeature2"},
                    {"name": "subfeature3", "display_name": "subfeature3"},
                    {"name": "subfeature4", "display_name": "subfeature4"}
                ]
            }
        }
    
    async def initialize(self):
        """Initialize Cedar service with minimal configuration"""
        try:
            # Load policies only
            with open(self.config_path / "policies.cedar", "r") as f:
                self.policies = f.read()
            
            logger.info("Cedar service configuration loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Cedar service: {str(e)}")
            raise
    
    def _create_minimal_entities(self, username: str) -> List[Dict]:
        """Create minimal entities for Cedar evaluation (no hardcoded users)"""
        return [
            {
                "uid": {"__entity": {"type": "User", "id": username}},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"__entity": {"type": "Feature", "id": "feature1"}},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"__entity": {"type": "Feature", "id": "feature2"}},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"__entity": {"type": "SubFeature", "id": "subfeature1"}},
                "attrs": {},
                "parents": [{"__entity": {"type": "Feature", "id": "feature2"}}]
            },
            {
                "uid": {"__entity": {"type": "SubFeature", "id": "subfeature2"}},
                "attrs": {},
                "parents": [{"__entity": {"type": "Feature", "id": "feature2"}}]
            },
            {
                "uid": {"__entity": {"type": "SubFeature", "id": "subfeature3"}},
                "attrs": {},
                "parents": [{"__entity": {"type": "Feature", "id": "feature2"}}]
            },
            {
                "uid": {"__entity": {"type": "SubFeature", "id": "subfeature4"}},
                "attrs": {},
                "parents": [{"__entity": {"type": "Feature", "id": "feature2"}}]
            }
        ]
    
    async def evaluate_policy_dynamic(
        self, 
        username: str,
        feature: str, 
        groups: List[str],
        context: Dict[str, Any],
        sub_feature: Optional[str] = None
    ) -> bool:
        """
        Evaluate Cedar policy using groups from request payload only
        """
        try:
            # Build evaluation context with groups
            eval_context = context.copy()
            eval_context["groups"] = groups  # Pass groups to Cedar context
            
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
            
            logger.debug(f"Cedar request with dynamic groups: {request}")
            
            # Create minimal entities dynamically
            entities = self._create_minimal_entities(username)
            
            # Evaluate with Cedar
            authz_result: AuthzResult = is_authorized(request, self.policies, entities)
            
            logger.debug(
                f"Cedar evaluation: user={username}, resource={resource_type}::{resource_id}, "
                f"groups={groups}, authorized={authz_result.allowed}"
            )
            
            return authz_result.allowed
            
        except Exception as e:
            logger.error(f"Cedar policy evaluation error: {str(e)}")
            logger.error(f"Request was: {locals()}")
            return False
    
    async def get_user_features_dynamic(self, username: str, groups: List[str]) -> Dict[str, Any]:
        """
        Get hierarchical features based purely on dynamic group membership
        """
        allowed_structure = {}
        
        logger.info(f"Getting allowed features for user {username} with dynamic groups {groups}")
        
        for feature_name, feature_info in self.feature_hierarchy.items():
            logger.debug(f"Checking feature: {feature_name}")
            
            # Check main feature access
            feature_allowed = await self.evaluate_policy_dynamic(
                username, feature_name, groups, {}
            )
            
            logger.debug(f"Main feature {feature_name} allowed: {feature_allowed}")
            
            # Check all sub-features
            allowed_sub_features = []
            for sub_feature in feature_info.get("sub_features", []):
                sub_feature_name = sub_feature["name"]
                sub_feature_allowed = await self.evaluate_policy_dynamic(
                    username, feature_name, groups, {}, sub_feature_name
                )
                
                logger.debug(f"Sub-feature {feature_name}.{sub_feature_name} allowed: {sub_feature_allowed}")
                
                if sub_feature_allowed:
                    allowed_sub_features.append({
                        "name": sub_feature_name,
                        "display_name": sub_feature["display_name"],
                        "allowed": True
                    })
            
            # Include feature if user has ANY access
            has_any_access = feature_allowed or len(allowed_sub_features) > 0
            
            if has_any_access:
                allowed_structure[feature_name] = {
                    "allowed": True,
                    "full_feature_access": feature_allowed,
                    "display_name": feature_info["display_name"],
                    "sub_features": allowed_sub_features,
                    "access_type": "full" if feature_allowed else "partial"
                }
        
        logger.info(f"User {username} has access to {len(allowed_structure)} feature groups")
        return allowed_structure
    
    async def get_user_features_flat_dynamic(self, username: str, groups: List[str]) -> List[str]:
        """
        Get flat list of features based on dynamic groups
        """
        allowed_features = []
        hierarchy = await self.get_user_features_dynamic(username, groups)
        
        for feature_name, feature_data in hierarchy.items():
            allowed_features.append(feature_name)
            
            for sub_feature in feature_data.get("sub_features", []):
                if sub_feature["allowed"]:
                    allowed_features.append(f"{feature_name}.{sub_feature['name']}")
        
        return allowed_features
