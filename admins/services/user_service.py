# admin_panel/services/user_service.py

from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.db import transaction, connection
from django.db.models import Prefetch, Q, Count
from datetime import datetime
from main.models import User, Role, UserRole, UserGroupAccess, Group


class UserService:
    
    CACHE_TTL = 60 * 5

    @classmethod
    def get_by_id(cls, user_id: int) -> dict:
        try:
            cache_key = f"user:detail:{user_id}"
            cached = cache.get(cache_key)
            if cached:
                return {'success': True, 'user': cached, 'message': 'User retrieved'}
            
            user = (
                User.objects
                .filter(id=user_id, is_deleted=False)
                .select_related()  
                .prefetch_related(
                    Prefetch(
                        'roles',
                        queryset=Role.objects.only('id', 'name')
                    ),
                    Prefetch(
                        'group_accesses',
                        queryset=UserGroupAccess.objects.select_related('group').only(
                            'id', 'user_id', 'group_id', 'group__id', 'group__name'
                        )
                    )
                )
                .only(
                    'id', 'email', 'first_name', 'last_name', 'middle_name',
                    'is_active', 'last_login_at', 'created_at', 'updated_at'
                )
                .first()
            )
            
            if not user:
                return {'success': False, 'user': None, 'message': 'User not found'}
            
            serialized = cls._serialize_user_detail(user)
            cache.set(cache_key, serialized, cls.CACHE_TTL)
            
            return {
                'success': True,
                'user': serialized,
                'message': 'User retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to get user: {str(e)}'}
    
    @classmethod
    def get_list(
        cls,
        page: int = 1,
        per_page: int = 20,
        search: str = None,
        role_id: int = None,
        is_active: bool = None,
        order_by: str = '-created_at'
    ) -> dict:
        try:
            queryset = (
                User.objects
                .filter(is_deleted=False)
                .only(
                    'id', 'email', 'first_name', 'last_name',
                    'is_active', 'created_at'
                )
            )
            if search:
                search = search.strip()
                if len(search) >= 2: 
                    queryset = queryset.filter(
                        Q(email__icontains=search) |
                        Q(first_name__icontains=search) |
                        Q(last_name__icontains=search)
                    )
            
            if role_id:
                queryset = queryset.filter(roles__id=role_id)
            
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active)
            allowed_ordering = {
                'created_at': 'created_at',
                '-created_at': '-created_at',
                'email': 'email',
                '-email': '-email',
                'first_name': 'first_name',
                '-first_name': '-first_name',
                'last_name': 'last_name',
                '-last_name': '-last_name'
            }
            order_field = allowed_ordering.get(order_by, '-created_at')
            queryset = queryset.order_by(order_field)
            total = queryset.count()
            offset = (page - 1) * per_page
            user_ids = list(queryset.values_list('id', flat=True)[offset:offset + per_page])

            if user_ids:
                users = (
                    User.objects
                    .filter(id__in=user_ids)
                    .prefetch_related(
                        Prefetch(
                            'roles',
                            queryset=Role.objects.only('id', 'name')
                        )
                    )
                    .only(
                        'id', 'email', 'first_name', 'last_name',
                        'is_active', 'created_at'
                    )
                )
                user_dict = {u.id: u for u in users}
                users = [user_dict[uid] for uid in user_ids if uid in user_dict]
            else:
                users = []
            
            return {
                'success': True,
                'users': [cls._serialize_user_list(u) for u in users],
                'meta': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': (total + per_page - 1) // per_page if total > 0 else 0
                },
                'message': 'Users retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'users': [], 'meta': None, 'message': f'Failed to get users: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def create(
        cls,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        middle_name: str = None,
        role_ids: list = None,
        group_ids: list = None,
        is_active: bool = True
    ) -> dict:
        try:
            email = str(email).lower().strip()
            
            if User.objects.filter(email=email, is_deleted=False).exists():
                return {'success': False, 'user': None, 'message': 'Email already exists'}
            user = User.objects.create(
                email=email,
                password=make_password(str(password)),
                first_name=str(first_name).strip(),
                last_name=str(last_name).strip(),
                middle_name=str(middle_name).strip() if middle_name else None,
                is_active=bool(is_active)
            )
            if role_ids:
                role_ids = [int(rid) for rid in role_ids if rid]
                if role_ids:
                    roles = Role.objects.filter(id__in=role_ids)
                    UserRole.objects.bulk_create([
                        UserRole(user=user, role=role) for role in roles
                    ], ignore_conflicts=True)

            if group_ids:
                group_ids = [int(gid) for gid in group_ids if gid]
                if group_ids:
                    groups = Group.objects.filter(id__in=group_ids, is_active=True)
                    UserGroupAccess.objects.bulk_create([
                        UserGroupAccess(user=user, group=group) for group in groups
                    ], ignore_conflicts=True)
            
            return cls.get_by_id(user.id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to create user: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update(
        cls,
        user_id: int,
        email: str = None,
        first_name: str = None,
        last_name: str = None,
        middle_name: str = None,
        is_active: bool = None
    ) -> dict:
        try:
            user = (
                User.objects
                .select_for_update(nowait=True)
                .filter(id=user_id, is_deleted=False)
                .first()
            )
            
            if not user:
                return {'success': False, 'user': None, 'message': 'User not found'}
            changed = False
            
            if email is not None:
                email = str(email).lower().strip()
                if email != user.email:
                    if User.objects.filter(email=email, is_deleted=False).exclude(id=user_id).exists():
                        return {'success': False, 'user': None, 'message': 'Email already exists'}
                    user.email = email
                    changed = True
            
            if first_name is not None:
                user.first_name = str(first_name).strip()
                changed = True
            
            if last_name is not None:
                user.last_name = str(last_name).strip()
                changed = True
            
            if middle_name is not None:
                user.middle_name = str(middle_name).strip() if middle_name else None
                changed = True
            
            if is_active is not None:
                user.is_active = bool(is_active)
                changed = True
                if not is_active:
                    cls._clear_user_auth_cache(user_id)
            
            if changed:
                user.save(update_fields=[
                    'email', 'first_name', 'last_name', 'middle_name', 
                    'is_active', 'updated_at'
                ])
                cls._invalidate_user_cache(user_id)
            
            return cls.get_by_id(user_id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to update user: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_password(cls, user_id: int, new_password: str) -> dict:
        try:
            updated = (
                User.objects
                .filter(id=user_id, is_deleted=False)
                .update(
                    password=make_password(str(new_password)),
                    updated_at=datetime.now()
                )
            )
            
            if not updated:
                return {'success': False, 'message': 'User not found'}
            
            cls._clear_user_auth_cache(user_id)
            
            return {'success': True, 'message': 'Password updated'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to update password: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_roles(cls, user_id: int, role_ids: list) -> dict:
        try:
            if not User.objects.filter(id=user_id, is_deleted=False).exists():
                return {'success': False, 'user': None, 'message': 'User not found'}
            UserRole.objects.filter(user_id=user_id).delete()
            if role_ids:
                role_ids = list(set(int(rid) for rid in role_ids if rid)) 
                roles = Role.objects.filter(id__in=role_ids).only('id')
                UserRole.objects.bulk_create([
                    UserRole(user_id=user_id, role_id=role.id) for role in roles
                ], ignore_conflicts=True)
            
            cls._clear_user_auth_cache(user_id)
            cls._invalidate_user_cache(user_id)

            return cls.get_by_id(user_id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to update roles: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_group_access(cls, user_id: int, group_ids: list) -> dict:
        try:
            if not User.objects.filter(id=user_id, is_deleted=False).exists():
                return {'success': False, 'user': None, 'message': 'User not found'}
            old_group_ids = list(
                UserGroupAccess.objects
                .filter(user_id=user_id)
                .values_list('group_id', flat=True)
            )
            UserGroupAccess.objects.filter(user_id=user_id).delete()

            new_group_ids = []
            if group_ids:
                group_ids = list(set(int(gid) for gid in group_ids if gid))  
                groups = Group.objects.filter(id__in=group_ids).only('id')
                UserGroupAccess.objects.bulk_create([
                    UserGroupAccess(user_id=user_id, group_id=group.id) for group in groups
                ], ignore_conflicts=True)
                new_group_ids = [g.id for g in groups]
        
            all_group_ids = set(old_group_ids) | set(new_group_ids)
            for gid in all_group_ids:
                cache.delete(f"auth:group_access:{user_id}:{gid}")
            
            cls._invalidate_user_cache(user_id)
            
            return cls.get_by_id(user_id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to update group access: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def delete(cls, user_id: int) -> dict:
        try:
            updated = (
                User.objects
                .filter(id=user_id, is_deleted=False)
                .update(
                    is_deleted=True,
                    is_active=False,
                    deleted_at=datetime.now(),
                    updated_at=datetime.now()
                )
            )
            
            if not updated:
                return {'success': False, 'message': 'User not found'}
            
            from main.models import Session
            Session.objects.filter(user_id=user_id).delete()
        
            cls._clear_user_auth_cache(user_id)
            cls._invalidate_user_cache(user_id)
            
            return {'success': True, 'message': 'User deleted'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete user: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def restore(cls, user_id: int) -> dict:
        try:
            user = User.objects.filter(id=user_id, is_deleted=True).only('email').first()
            
            if not user:
                return {'success': False, 'user': None, 'message': 'Deleted user not found'}
            if User.objects.filter(email=user.email, is_deleted=False).exclude(id=user_id).exists():
                return {'success': False, 'user': None, 'message': 'Email is now used by another user'}
            
            User.objects.filter(id=user_id).update(
                is_deleted=False,
                is_active=True,
                deleted_at=None,
                updated_at=datetime.now()
            )
            
            return cls.get_by_id(user_id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to restore user: {str(e)}'}

    @classmethod
    def _serialize_user_list(cls, user: User) -> dict:
        return {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'full_name': user.full_name,
            'is_active': user.is_active,
            'roles': [{'id': r.id, 'name': r.name} for r in user.roles.all()],
            'created_at': user.created_at.isoformat() if user.created_at else None
        }
    
    @classmethod
    def _serialize_user_detail(cls, user: User) -> dict:
        return {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'middle_name': user.middle_name,
            'full_name': user.full_name,
            'is_active': user.is_active,
            'roles': [{'id': r.id, 'name': r.name} for r in user.roles.all()],
            'group_access': [
                {'id': ga.group.id, 'name': ga.group.name}
                for ga in user.group_accesses.all()
                if ga.group
            ],
            'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'updated_at': user.updated_at.isoformat() if user.updated_at else None
        }
    
    @classmethod
    def _clear_user_auth_cache(cls, user_id: int):
        cache.delete(f"auth:user:{user_id}")
        cache.delete(f"auth:permissions:{user_id}")
    
    @classmethod
    def _invalidate_user_cache(cls, user_id: int):
        cache.delete(f"user:detail:{user_id}")