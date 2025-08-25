"""
JWT Bearer Authentication
FastAPI dependency for JWT token validation
"""

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .jwt_handler import decode_jwt

class JWTBearer(HTTPBearer):
    """
    JWT Bearer token validator for FastAPI dependencies
    """
    
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> str:
        """
        Validate JWT token from Authorization header
        
        Args:
            request: FastAPI request object
            
        Returns:
            Valid JWT token string
            
        Raises:
            HTTPException: If token is invalid or missing
        """
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid authentication scheme."
                )
            
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid token or expired token."
                )
            
            return credentials.credentials
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization code."
            )

    def verify_jwt(self, jwt_token: str) -> bool:
        """
        Verify JWT token validity
        
        Args:
            jwt_token: JWT token string
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            payload = decode_jwt(jwt_token)
            return payload is not None
        except Exception:
            return False
