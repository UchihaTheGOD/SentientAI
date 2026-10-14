# app/services/auth_service.py - Argon2id
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=['argon2'], deprecated='auto', argon2__type='ID', argon2__memory_cost=19456, argon2__time_cost=2, argon2__parallelism=1)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
