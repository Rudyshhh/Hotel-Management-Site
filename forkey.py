import secrets

jwt_secret = secrets.token_hex(32)
print(jwt_secret)