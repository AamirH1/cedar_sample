from auth.jwt_handler import create_access_token
from datetime import timedelta

# Generate a test token
test_user_data = {
    "sub": "test_user",
    "user_id": "test_001", 
    "persona": "admin"
}

# Create token that expires in 1 hour
test_token = create_access_token(
    data=test_user_data,
    expires_delta=timedelta(hours=1)
)

print("Test JWT Token:")
print(test_token)
