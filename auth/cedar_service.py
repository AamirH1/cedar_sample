"""
Cedar Policy Service
Handles Cedar policy evaluation and user authentication
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
            
        except Exception as e:
            logger.error(f"Failed to initialize Cedar service: {str(e)}")
            raise
    
    async def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user credentials
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            User information if authenticated, None otherwise
        """
        user = self.users.get(username)
        if not user:
            return None
        
        if verify_password(password, user["password_hash"]):
            return {
                "user_id": user["user_id"],
                "username": username,
                "persona": user["persona"]
            }
        
        return None
    
    async def evaluate_policy(
        self, 
        username: str, 
        persona: str, 
        feature: str, 
        context: Dict[str, Any]
    ) -> bool:
        """
        Evaluate Cedar policy for user access to feature
        
        Args:
            username: User's username
            persona: User's persona/role
            feature: Requested feature
            context: Additional context for policy evaluation
            
        Returns:
            True if access is authorized, False otherwise
        """
        try:
            # Create authorization request
            request = {
                "principal": f'User::"{username}"',
                "action": f'Action::"{feature}"',
                "resource": f'Feature::"{feature}"',
                "context": context
            }
            
            # Evaluate with Cedar
            authz_result: AuthzResult = is_authorized(
                request, 
                self.policies, 
                self.entities
            )
            
            logger.info(
                f"Cedar evaluation: user={username}, feature={feature}, "
                f"authorized={authz_result.allowed}"
            )
            
            return authz_result.allowed
            
        except Exception as e:
            logger.error(f"Cedar policy evaluation error: {str(e)}")
            return False
    
    async def get_user_allowed_features(self, username: str, persona: str) -> List[str]:
        """
        Get list of features user is allowed to access
        
        Args:
            username: User's username
            persona: User's persona/role
            
        Returns:
            List of allowed feature names
        """
        features = [
            "dashboard_access",
            "user_management",
            "report_generation",
            "data_export",
            "system_configuration"
        ]
        
        allowed_features = []
        
        for feature in features:
            is_allowed = await self.evaluate_policy(
                username, persona, feature, {}
            )
            if is_allowed:
                allowed_features.append(feature)
        
        return allowed_features
