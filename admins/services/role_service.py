from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, Prefetch
from main.models import Role, Permission, RolePermission, UserRole


class RoleService:
    @classmethod
    def get_by_id(cls, role_id: int) -> dict:
        try:
            role = (
                Role.objects
                .filter(id=role_id)
                .prefetch_related(
                    Prefetch(
                        'permissions',
                        queryset=Permission.objects.only('id', 'codename', 'name')
                    )
                )
                .annotate(user_count=Count('users', distinct=True))
                .first()
            )
            
            if not role:
                return {'success': False, 'role': None, 'message': 'Role not found'}
            
            return {
                'success': True,
                'role': cls._serialize_role_detail(role),
                'message': 'Role retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'role': None, 'message': f'Failed to get role: {str(e)}'}
    
    @classmethod
    def get_list(
        cls,
        page: int = 1,
        per_page: int = 20,
        search: str = None,
        order_by: str = 'name'
    ) -> dict:
        try:
            queryset = (
                Role.objects
                .prefetch_related(
                    Prefetch(
                        'permissions',
                        queryset=Permission.objects.only('id', 'codename', 'name')
                    )
                )
                .annotate(
                    user_count=Count('users', distinct=True),
                    permission_count=Count('permissions', distinct=True)
                )
            )
            
            if search:
                queryset = queryset.filter(name__icontains=search)
            
            allowed_ordering = ['name', '-name', 'created_at', '-created_at']
            if order_by in allowed_ordering:
                queryset = queryset.order_by(order_by)
            else:
                queryset = queryset.order_by('name')
            
            total = queryset.count()
 
            offset = (page - 1) * per_page
            roles = queryset[offset:offset + per_page]
            
            return {
                'success': True,
                'roles': [cls._serialize_role_list(r) for r in roles],
                'meta': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': (total + per_page - 1) // per_page
                },
                'message': 'Roles retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'roles': [], 'meta': None, 'message': f'Failed to get roles: {str(e)}'}
    
    @classmethod
    def get_all_permissions(cls) -> dict:
        try:
            permissions = Permission.objects.all().order_by('codename')
            
            grouped = {}
            for perm in permissions:
                module = perm.codename.split('.')[0]
                if module not in grouped:
                    grouped[module] = []
                grouped[module].append({
                    'id': perm.id,
                    'codename': perm.codename,
                    'name': perm.name,
                    'description': perm.description
                })
            
            return {
                'success': True,
                'permissions': grouped,
                'message': 'Permissions retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'permissions': {}, 'message': f'Failed to get permissions: {str(e)}'}

    @classmethod
    @transaction.atomic
    def create(
        cls,
        name: str,
        description: str = None,
        permission_ids: list = None
    ) -> dict:
        try:
            name = name.strip()
            
            if Role.objects.filter(name__iexact=name).exists():
                return {'success': False, 'role': None, 'message': 'Role name already exists'}
            role = Role.objects.create(
                name=name,
                description=description.strip() if description else None
            )
            
            if permission_ids:
                permissions = Permission.objects.filter(id__in=permission_ids)
                for permission in permissions:
                    RolePermission.objects.create(role=role, permission=permission)
            
            return cls.get_by_id(role.id)
            
        except Exception as e:
            return {'success': False, 'role': None, 'message': f'Failed to create role: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update(
        cls,
        role_id: int,
        name: str = None,
        description: str = None
    ) -> dict:
        try:
            role = Role.objects.filter(id=role_id).first()
            
            if not role:
                return {'success': False, 'role': None, 'message': 'Role not found'}
            if name:
                name = name.strip()
                if name.lower() != role.name.lower():
                    if Role.objects.filter(name__iexact=name).exclude(id=role_id).exists():
                        return {'success': False, 'role': None, 'message': 'Role name already exists'}
                    role.name = name
            
            if description is not None:
                role.description = description.strip() if description else None
            
            role.save()
        
            cls._clear_role_users_cache(role_id)
            
            return cls.get_by_id(role_id)
            
        except Exception as e:
            return {'success': False, 'role': None, 'message': f'Failed to update role: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_permissions(cls, role_id: int, permission_ids: list) -> dict:
        try:
            role = Role.objects.filter(id=role_id).first()
            
            if not role:
                return {'success': False, 'role': None, 'message': 'Role not found'}
            
            if role.name == 'Super Admin' and not permission_ids:
                return {'success': False, 'role': None, 'message': 'Cannot remove all permissions from Super Admin'}

            RolePermission.objects.filter(role=role).delete()

            if permission_ids:
                permissions = Permission.objects.filter(id__in=permission_ids)
                for permission in permissions:
                    RolePermission.objects.create(role=role, permission=permission)
            
            cls._clear_role_users_cache(role_id)
            
            return cls.get_by_id(role_id)
            
        except Exception as e:
            return {'success': False, 'role': None, 'message': f'Failed to update permissions: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def add_permissions(cls, role_id: int, permission_ids: list) -> dict:
        try:
            role = Role.objects.filter(id=role_id).first()
            
            if not role:
                return {'success': False, 'role': None, 'message': 'Role not found'}
            
            if not permission_ids:
                return cls.get_by_id(role_id)
            existing_ids = set(
                RolePermission.objects
                .filter(role=role)
                .values_list('permission_id', flat=True)
            )
            permissions = Permission.objects.filter(id__in=permission_ids).exclude(id__in=existing_ids)
            for permission in permissions:
                RolePermission.objects.create(role=role, permission=permission)

            cls._clear_role_users_cache(role_id)
            
            return cls.get_by_id(role_id)
            
        except Exception as e:
            return {'success': False, 'role': None, 'message': f'Failed to add permissions: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def remove_permissions(cls, role_id: int, permission_ids: list) -> dict:
        try:
            role = Role.objects.filter(id=role_id).first()
            
            if not role:
                return {'success': False, 'role': None, 'message': 'Role not found'}
            
            if not permission_ids:
                return cls.get_by_id(role_id)

            RolePermission.objects.filter(role=role, permission_id__in=permission_ids).delete()

            cls._clear_role_users_cache(role_id)
            
            return cls.get_by_id(role_id)
            
        except Exception as e:
            return {'success': False, 'role': None, 'message': f'Failed to remove permissions: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def delete(cls, role_id: int) -> dict:
        try:
            role = Role.objects.filter(id=role_id).first()
            
            if not role:
                return {'success': False, 'message': 'Role not found'}
            
            protected_roles = ['Super Admin', 'Admin', 'Teacher', 'Viewer']
            if role.name in protected_roles:
                return {'success': False, 'message': f'Cannot delete system role: {role.name}'}
            
            user_count = UserRole.objects.filter(role=role).count()
            if user_count > 0:
                return {
                    'success': False,
                    'message': f'Cannot delete role: {user_count} users are assigned to this role'
                }
        
            cls._clear_role_users_cache(role_id)
            
            role.delete()
            
            return {'success': True, 'message': 'Role deleted'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete role: {str(e)}'}
    
    @classmethod
    def _serialize_role_list(cls, role: Role) -> dict:
        return {
            'id': role.id,
            'name': role.name,
            'description': role.description,
            'user_count': getattr(role, 'user_count', 0),
            'permission_count': getattr(role, 'permission_count', 0),
            'created_at': role.created_at.isoformat() if role.created_at else None
        }
    
    @classmethod
    def _serialize_role_detail(cls, role: Role) -> dict:
        permissions_grouped = {}
        permissions_list = []
        
        for perm in role.permissions.all():
            module = perm.codename.split('.')[0]
            if module not in permissions_grouped:
                permissions_grouped[module] = []
            
            perm_data = {
                'id': perm.id,
                'codename': perm.codename,
                'name': perm.name
            }
            permissions_grouped[module].append(perm_data)
            permissions_list.append(perm_data)
        
        return {
            'id': role.id,
            'name': role.name,
            'description': role.description,
            'user_count': getattr(role, 'user_count', 0),
            'permissions': permissions_list,
            'permissions_grouped': permissions_grouped,
            'created_at': role.created_at.isoformat() if role.created_at else None,
            'updated_at': role.updated_at.isoformat() if role.updated_at else None
        }
    
    @classmethod
    def _clear_role_users_cache(cls, role_id: int):
        user_ids = (
            UserRole.objects
            .filter(role_id=role_id)
            .values_list('user_id', flat=True)
        )
        
        for user_id in user_ids:
            cache.delete(f"auth:user:{user_id}")
            cache.delete(f"auth:permissions:{user_id}")