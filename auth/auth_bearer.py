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
        """
        try:
            payload = decode_jwt(jwt_token)
            return payload is not None
        except Exception:
            return False
