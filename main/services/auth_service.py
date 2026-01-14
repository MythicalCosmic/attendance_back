import jwt
import hashlib
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.core.cache import cache
from django.db import transaction
from django.db.models import Prefetch
from ..models import User, Session, Permission


class AuthService:
    JWT_SECRET = getattr(settings, 'JWT_SECRET_KEY', settings.SECRET_KEY)
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRY_DAYS = 365

    USER_CACHE_TTL = 60 * 15 
    PERMISSION_CACHE_TTL = 60 * 30  
    SESSION_CACHE_TTL = 60 * 60  
    
    @classmethod
    @transaction.atomic
    def login(cls, email: str, password: str, ip_address: str, user_agent: str = 'Unknown') -> dict:
        try:
            user = (
                User.objects
                .filter(email=email, is_deleted=False)
                .prefetch_related(
                    Prefetch(
                        'roles__permissions',
                        queryset=Permission.objects.only('codename')
                    )
                )
                .only('id', 'email', 'password', 'is_active', 'first_name', 'last_name', 'middle_name')
                .first()
            )
            print(user.password, password)
            
            if not user:
                return cls._error_response('Invalid credentials')
            
            if not user.is_active:
                return cls._error_response('Account is inactive')
            
            if not check_password(password, user.password):
                return cls._error_response('Invalid credentials')
            
            Session.objects.filter(user=user).delete()
            cls._clear_user_cache(user.id)
            
            token = cls._generate_token(user)
            token_hash = cls._hash_token(token)
            
            Session.objects.create(
                user=user,
                token_hash=token_hash,
                ip_address=ip_address,
                user_agent=user_agent[:200],  
                expires_at=datetime.now() + timedelta(days=cls.JWT_EXPIRY_DAYS)
            )
            
            User.objects.filter(id=user.id).update(
                last_login_at=datetime.now(),
                last_login_ip=ip_address
            )

            permissions = cls._get_user_permissions(user)
            cls._cache_user_session(user.id, token_hash, permissions)
            
            return {
                'success': True,
                'token': token,
                'user': cls._serialize_user(user, permissions),
                'message': 'Login successful'
            }
            
        except Exception as e:
            return cls._error_response(f'Login failed: {str(e)}')
    
    @classmethod
    def logout(cls, token: str) -> dict:
        try:
            token_hash = cls._hash_token(token)
            
            user_id = cls._get_user_id_from_cache(token_hash)
            
            if user_id:
                Session.objects.filter(user_id=user_id).delete()
                cls._clear_user_cache(user_id)
                return {'success': True, 'message': 'Logged out successfully'}
            
            payload = cls._decode_token(token)
            if payload:
                Session.objects.filter(user_id=payload['user_id']).delete()
                cls._clear_user_cache(payload['user_id'])
                return {'success': True, 'message': 'Logged out successfully'}
            
            return {'success': True, 'message': 'Already logged out'}
            
        except Exception as e:
            return cls._error_response(f'Logout failed: {str(e)}')
    
    @classmethod
    @transaction.atomic
    def refresh_token(cls, old_token: str, ip_address: str, user_agent: str = 'Unknown') -> dict:
        try:
            user, permissions = cls.validate_token(old_token)
            
            if not user:
                return cls._error_response('Invalid token')
            
            if not user.is_active:
                return cls._error_response('Account is inactive')

            old_token_hash = cls._hash_token(old_token)
            Session.objects.filter(token_hash=old_token_hash).delete()
            cls._invalidate_session_cache(old_token_hash)

            new_token = cls._generate_token(user)
            new_token_hash = cls._hash_token(new_token)
            
            Session.objects.create(
                user=user,
                token_hash=new_token_hash,
                ip_address=ip_address,
                user_agent=user_agent[:200],
                expires_at=datetime.now() + timedelta(days=cls.JWT_EXPIRY_DAYS)
            )
            
            cls._cache_user_session(user.id, new_token_hash, permissions)
            
            return {
                'success': True,
                'token': new_token,
                'message': 'Token refreshed'
            }
            
        except Exception as e:
            return cls._error_response(f'Refresh failed: {str(e)}')
    
    @classmethod
    def validate_token(cls, token: str) -> tuple:
        if not token:
            return None, None
        
        try:
            token_hash = cls._hash_token(token)
            cached = cls._get_cached_session(token_hash)
            if cached:
                return cached['user'], cached['permissions']
            payload = cls._decode_token(token)
            if not payload:
                return None, None
        
            session = (
                Session.objects
                .filter(token_hash=token_hash, expires_at__gt=datetime.now())
                .select_related('user')
                .first()
            )
            
            if not session or not session.user.is_active or session.user.is_deleted:
                return None, None
            permissions = cls._load_permissions_from_db(session.user.id)
            cls._cache_user_session(session.user.id, token_hash, permissions)
            
            return session.user, permissions
            
        except Exception:
            return None, None
    
    @classmethod
    def has_permission(cls, token: str, permission_codename: str) -> bool:
        _, permissions = cls.validate_token(token)
        return permission_codename in (permissions or [])
    
    @classmethod
    def has_any_permission(cls, token: str, permission_codenames: list) -> bool:
        _, permissions = cls.validate_token(token)
        if not permissions:
            return False
        return bool(set(permission_codenames) & set(permissions))
    
    @classmethod
    def has_all_permissions(cls, token: str, permission_codenames: list) -> bool:
        _, permissions = cls.validate_token(token)
        if not permissions:
            return False
        return set(permission_codenames).issubset(set(permissions))
    
    @classmethod
    def _generate_token(cls, user: User) -> str:
        payload = {
            'user_id': user.id,
            'email': user.email,
            'exp': datetime.utcnow() + timedelta(days=cls.JWT_EXPIRY_DAYS),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, cls.JWT_SECRET, algorithm=cls.JWT_ALGORITHM)
    
    @classmethod
    def _decode_token(cls, token: str) -> dict | None:
        try:
            return jwt.decode(token, cls.JWT_SECRET, algorithms=[cls.JWT_ALGORITHM])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None
    
    @classmethod
    def _hash_token(cls, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()[:50]
    
    @classmethod
    def _cache_key_session(cls, token_hash: str) -> str:
        return f"auth:session:{token_hash}"
    
    @classmethod
    def _cache_key_permissions(cls, user_id: int) -> str:
        return f"auth:permissions:{user_id}"
    
    @classmethod
    def _cache_user_session(cls, user_id: int, token_hash: str, permissions: list):
        cache_key = cls._cache_key_session(token_hash)
        cache.set(cache_key, {
            'user_id': user_id,
            'permissions': permissions
        }, cls.SESSION_CACHE_TTL)
    
    @classmethod
    def _get_cached_session(cls, token_hash: str) -> dict | None:
        cache_key = cls._cache_key_session(token_hash)
        data = cache.get(cache_key)
        
        if not data:
            return None

        user = cls._get_cached_user(data['user_id'])
        if not user:
            return None
        
        return {
            'user': user,
            'permissions': data['permissions']
        }
    
    @classmethod
    def _get_cached_user(cls, user_id: int) -> User | None:
        cache_key = f"auth:user:{user_id}"
        user = cache.get(cache_key)
        
        if not user:
            user = (
                User.objects
                .filter(id=user_id, is_deleted=False, is_active=True)
                .only('id', 'email', 'first_name', 'last_name', 'middle_name', 'is_active')
                .first()
            )
            if user:
                cache.set(cache_key, user, cls.USER_CACHE_TTL)
        
        return user
    
    @classmethod
    def _get_user_id_from_cache(cls, token_hash: str) -> int | None:
        cache_key = cls._cache_key_session(token_hash)
        data = cache.get(cache_key)
        return data['user_id'] if data else None
    
    @classmethod
    def _invalidate_session_cache(cls, token_hash: str):
        cache.delete(cls._cache_key_session(token_hash))
    
    @classmethod
    def _clear_user_cache(cls, user_id: int):
        cache.delete(f"auth:user:{user_id}")
        cache.delete(cls._cache_key_permissions(user_id))
    
    @classmethod
    def _get_user_permissions(cls, user: User) -> list:
        permissions = set()
        for role in user.roles.all():
            for perm in role.permissions.all():
                permissions.add(perm.codename)
        return list(permissions)
    
    @classmethod
    def _load_permissions_from_db(cls, user_id: int) -> list:
        cache_key = cls._cache_key_permissions(user_id)
        permissions = cache.get(cache_key)
        
        if permissions is None:
            permissions = list(
                Permission.objects
                .filter(roles__users__id=user_id)
                .values_list('codename', flat=True)
                .distinct()
            )
            cache.set(cache_key, permissions, cls.PERMISSION_CACHE_TTL)
        
        return permissions
    
    @classmethod
    def _serialize_user(cls, user: User, permissions: list) -> dict:
        return {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'middle_name': user.middle_name,
            'full_name': user.full_name,
            'permissions': permissions
        }
    
    @classmethod
    def _error_response(cls, message: str) -> dict:
        return {
            'success': False,
            'token': None,
            'user': None,
            'message': message
        }