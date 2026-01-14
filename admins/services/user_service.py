from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.db import transaction
from django.db.models import Prefetch, Q
from datetime import datetime
from main.models import User, Role, UserRole, UserGroupAccess, Permission


class UserService:
    @classmethod
    def get_by_id(cls, user_id: int) -> dict:
        try:
            user = (
                User.objects
                .filter(id=user_id, is_deleted=False)
                .prefetch_related(
                    Prefetch(
                        'roles',
                        queryset=Role.objects.only('id', 'name')
                    ),
                    'group_accesses__group'
                )
                .first()
            )
            
            if not user:
                return {'success': False, 'user': None, 'message': 'User not found'}
            
            return {
                'success': True,
                'user': cls._serialize_user_detail(user),
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
                .prefetch_related(
                    Prefetch(
                        'roles',
                        queryset=Role.objects.only('id', 'name')
                    )
                )
            )
            if search:
                queryset = queryset.filter(
                    Q(email__icontains=search) |
                    Q(first_name__icontains=search) |
                    Q(last_name__icontains=search)
                )
            
            if role_id:
                queryset = queryset.filter(roles__id=role_id)
            
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active)

            allowed_ordering = ['created_at', '-created_at', 'email', '-email', 
                               'first_name', '-first_name', 'last_name', '-last_name']
            if order_by in allowed_ordering:
                queryset = queryset.order_by(order_by)
            else:
                queryset = queryset.order_by('-created_at')

            total = queryset.count()

            offset = (page - 1) * per_page
            users = queryset[offset:offset + per_page]
            
            return {
                'success': True,
                'users': [cls._serialize_user_list(u) for u in users],
                'meta': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': (total + per_page - 1) // per_page
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
            email = email.lower().strip()

            if User.objects.filter(email=email, is_deleted=False).exists():
                return {'success': False, 'user': None, 'message': 'Email already exists'}

            user = User.objects.create(
                email=email,
                password=make_password(password),
                first_name=first_name.strip(),
                last_name=last_name.strip(),
                middle_name=middle_name.strip() if middle_name else None,
                is_active=is_active
            )

            if role_ids:
                roles = Role.objects.filter(id__in=role_ids)
                for role in roles:
                    UserRole.objects.create(user=user, role=role)
            
            if group_ids:
                from main.models import Group
                groups = Group.objects.filter(id__in=group_ids, is_active=True)
                for group in groups:
                    UserGroupAccess.objects.create(user=user, group=group)
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
            user = User.objects.filter(id=user_id, is_deleted=False).first()
            
            if not user:
                return {'success': False, 'user': None, 'message': 'User not found'}
            if email:
                email = email.lower().strip()
                if email != user.email:
                    if User.objects.filter(email=email, is_deleted=False).exclude(id=user_id).exists():
                        return {'success': False, 'user': None, 'message': 'Email already exists'}
                    user.email = email
            
            if first_name is not None:
                user.first_name = first_name.strip()
            
            if last_name is not None:
                user.last_name = last_name.strip()
            
            if middle_name is not None:
                user.middle_name = middle_name.strip() if middle_name else None
            
            if is_active is not None:
                user.is_active = is_active
                if not is_active:
                    cls._clear_user_auth_cache(user_id)
            
            user.save()
            
            cls._clear_user_auth_cache(user_id)
            return cls.get_by_id(user_id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to update user: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_password(cls, user_id: int, new_password: str) -> dict:
        try:
            updated = User.objects.filter(id=user_id, is_deleted=False).update(
                password=make_password(new_password),
                updated_at=datetime.now()
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
            user = User.objects.filter(id=user_id, is_deleted=False).first()
            
            if not user:
                return {'success': False, 'user': None, 'message': 'User not found'}

            UserRole.objects.filter(user=user).delete()

            if role_ids:
                roles = Role.objects.filter(id__in=role_ids)
                for role in roles:
                    UserRole.objects.create(user=user, role=role)
            
            cls._clear_user_auth_cache(user_id)
            
            return cls.get_by_id(user_id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to update roles: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_group_access(cls, user_id: int, group_ids: list) -> dict:
        try:
            user = User.objects.filter(id=user_id, is_deleted=False).first()
            
            if not user:
                return {'success': False, 'user': None, 'message': 'User not found'}
            
            UserGroupAccess.objects.filter(user=user).delete()

            if group_ids:
                from main.models import Group
                groups = Group.objects.filter(id__in=group_ids)
                for group in groups:
                    UserGroupAccess.objects.create(user=user, group=group)

            cache.delete_pattern(f"auth:group_access:{user_id}:*")
            
            return cls.get_by_id(user_id)
            
        except Exception as e:
            return {'success': False, 'user': None, 'message': f'Failed to update group access: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def delete(cls, user_id: int) -> dict:
        try:
            user = User.objects.filter(id=user_id, is_deleted=False).first()
            
            if not user:
                return {'success': False, 'message': 'User not found'}
            
            user.is_deleted = True
            user.is_active = False
            user.deleted_at = datetime.now()
            user.save()
            from main.models import Session
            Session.objects.filter(user=user).delete()
            cls._clear_user_auth_cache(user_id)
            
            return {'success': True, 'message': 'User deleted'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete user: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def restore(cls, user_id: int) -> dict:
        try:
            user = User.objects.filter(id=user_id, is_deleted=True).first()
            
            if not user:
                return {'success': False, 'user': None, 'message': 'Deleted user not found'}
            if User.objects.filter(email=user.email, is_deleted=False).exclude(id=user_id).exists():
                return {'success': False, 'user': None, 'message': 'Email is now used by another user'}
            
            user.is_deleted = False
            user.is_active = True
            user.deleted_at = None
            user.save()
            
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