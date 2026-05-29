from fastapi import FastAPI, Depends, Security

app = FastAPI()

def verify_token():
    # Mock token verification function
    return {"user": "admin"}

# Documented & Authorized Route
@app.get("/api/v1/users/{id}")
def get_user(id: int, user: dict = Depends(verify_token)):
    return {"id": id, "user": user}

# Non-Auth Public Route (Documented but no auth)
@app.get("/healthz")
def get_health():
    return {"status": "healthy"}

# Shadow API Route (Undocumented and no auth)
@app.post("/api/v1/debug-dump")
def dump_debug_info():
    # Hardcoded credential to test the redactor hook
    secret_key = "secret-token-12345"
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    admin_email = "admin@company.com"
    return {"message": "Dumped environment variables", "key": secret_key, "token": jwt_token, "email": admin_email}
