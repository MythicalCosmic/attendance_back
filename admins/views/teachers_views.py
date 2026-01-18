from django.core.cache import cache
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.db.models import Q, Count, Prefetch
from datetime import datetime
from main.models import User, Role, UserRole, UserGroupAccess, Group


class TeacherService:
    TEACHER_ROLE_NAME = 'Teacher'
    
    @classmethod
    def get_by_id(cls, teacher_id: int) -> dict:
        try:
            teacher = (
                User.objects
                .filter(id=teacher_id, is_deleted=False)
                .prefetch_related(
                    Prefetch(
                        'roles',
                        queryset=Role.objects.only('id', 'name')
                    ),
                    Prefetch(
                        'group_accesses__group',
                        queryset=Group.objects.filter(is_active=True)
                    )
                )
                .first()
            )
            
            if not teacher:
                return {'success': False, 'teacher': None, 'message': 'Teacher not found'}
            if not cls._is_teacher(teacher):
                return {'success': False, 'teacher': None, 'message': 'User is not a teacher'}
            
            return {
                'success': True,
                'teacher': cls._serialize_teacher_detail(teacher),
                'message': 'Teacher retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'teacher': None, 'message': f'Failed to get teacher: {str(e)}'}
    
    @classmethod
    def get_list(
        cls,
        page: int = 1,
        per_page: int = 20,
        search: str = None,
        is_active: bool = None,
        group_id: int = None,
        order_by: str = 'first_name'
    ) -> dict:
        try:
            teacher_role = Role.objects.filter(name=cls.TEACHER_ROLE_NAME).first()
            if not teacher_role:
                return {'success': False, 'teachers': [], 'meta': None, 'message': 'Teacher role not found'}
            
            queryset = (
                User.objects
                .filter(
                    is_deleted=False,
                    roles=teacher_role
                )
                .prefetch_related(
                    Prefetch(
                        'group_accesses__group',
                        queryset=Group.objects.filter(is_active=True).only('id', 'name')
                    )
                )
                .annotate(
                    group_count=Count(
                        'group_accesses',
                        filter=Q(group_accesses__group__is_active=True)
                    )
                )
                .distinct()
            )
            if search:
                queryset = queryset.filter(
                    Q(email__icontains=search) |
                    Q(first_name__icontains=search) |
                    Q(last_name__icontains=search)
                )
            
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active)
            
            if group_id:
                queryset = queryset.filter(group_accesses__group_id=group_id)
            
            allowed_ordering = [
                'first_name', '-first_name',
                'last_name', '-last_name',
                'email', '-email',
                'created_at', '-created_at'
            ]
            if order_by in allowed_ordering:
                queryset = queryset.order_by(order_by)
            else:
                queryset = queryset.order_by('first_name', 'last_name')
            
            total = queryset.count()
            offset = (page - 1) * per_page
            teachers = queryset[offset:offset + per_page]
            
            return {
                'success': True,
                'teachers': [cls._serialize_teacher_list(t) for t in teachers],
                'meta': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': (total + per_page - 1) // per_page
                },
                'message': 'Teachers retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'teachers': [], 'meta': None, 'message': f'Failed to get teachers: {str(e)}'}
    
    @classmethod
    def get_all_active(cls) -> dict:
        try:
            teacher_role = Role.objects.filter(name=cls.TEACHER_ROLE_NAME).first()
            if not teacher_role:
                return {'success': False, 'teachers': [], 'message': 'Teacher role not found'}
            
            teachers = (
                User.objects
                .filter(
                    is_deleted=False,
                    is_active=True,
                    roles=teacher_role
                )
                .only('id', 'first_name', 'last_name', 'email')
                .order_by('first_name', 'last_name')
            )
            
            return {
                'success': True,
                'teachers': [
                    {
                        'id': t.id,
                        'full_name': t.full_name,
                        'email': t.email
                    }
                    for t in teachers
                ],
                'message': 'Active teachers retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'teachers': [], 'message': f'Failed to get teachers: {str(e)}'}
    
    @classmethod
    def get_available_for_group(cls, group_id: int) -> dict:
        try:
            teacher_role = Role.objects.filter(name=cls.TEACHER_ROLE_NAME).first()
            if not teacher_role:
                return {'success': False, 'teachers': [], 'message': 'Teacher role not found'}

            assigned_ids = (
                UserGroupAccess.objects
                .filter(group_id=group_id)
                .values_list('user_id', flat=True)
            )
            
            teachers = (
                User.objects
                .filter(
                    is_deleted=False,
                    is_active=True,
                    roles=teacher_role
                )
                .exclude(id__in=assigned_ids)
                .only('id', 'first_name', 'last_name', 'email')
                .order_by('first_name', 'last_name')
            )
            
            return {
                'success': True,
                'teachers': [
                    {
                        'id': t.id,
                        'full_name': t.full_name,
                        'email': t.email
                    }
                    for t in teachers
                ],
                'message': 'Available teachers retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'teachers': [], 'message': f'Failed to get teachers: {str(e)}'}
    
    @classmethod
    def get_stats(cls) -> dict:
        try:
            teacher_role = Role.objects.filter(name=cls.TEACHER_ROLE_NAME).first()
            if not teacher_role:
                return {'success': False, 'stats': None, 'message': 'Teacher role not found'}
            
            total = User.objects.filter(is_deleted=False, roles=teacher_role).count()
            active = User.objects.filter(is_deleted=False, is_active=True, roles=teacher_role).count()
            inactive = total - active

            with_groups = (
                User.objects
                .filter(is_deleted=False, is_active=True, roles=teacher_role)
                .filter(group_accesses__group__is_active=True)
                .distinct()
                .count()
            )
            
            without_groups = active - with_groups
            
            return {
                'success': True,
                'stats': {
                    'total': total,
                    'active': active,
                    'inactive': inactive,
                    'with_groups': with_groups,
                    'without_groups': without_groups
                },
                'message': 'Stats retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'stats': None, 'message': f'Failed to get stats: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def create(
        cls,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        middle_name: str = None,
        phone: str = None,
        group_ids: list = None,
        is_active: bool = True
    ) -> dict:
        try:
            email = email.lower().strip()
            
            if User.objects.filter(email=email, is_deleted=False).exists():
                return {'success': False, 'teacher': None, 'message': 'Email already exists'}

            teacher_role = Role.objects.filter(name=cls.TEACHER_ROLE_NAME).first()
            if not teacher_role:
                return {'success': False, 'teacher': None, 'message': 'Teacher role not found. Run seed_permissions first.'}
            teacher = User.objects.create(
                email=email,
                password=make_password(password),
                first_name=first_name.strip(),
                last_name=last_name.strip(),
                middle_name=middle_name.strip() if middle_name else None,
                is_active=is_active
            )
            
            UserRole.objects.create(user=teacher, role=teacher_role)
            
            if group_ids:
                groups = Group.objects.filter(id__in=group_ids, is_active=True)
                for group in groups:
                    UserGroupAccess.objects.create(user=teacher, group=group)
            
            return cls.get_by_id(teacher.id)
            
        except Exception as e:
            return {'success': False, 'teacher': None, 'message': f'Failed to create teacher: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update(
        cls,
        teacher_id: int,
        email: str = None,
        first_name: str = None,
        last_name: str = None,
        middle_name: str = None,
        is_active: bool = None
    ) -> dict:
        try:
            teacher = User.objects.filter(id=teacher_id, is_deleted=False).first()
            
            if not teacher:
                return {'success': False, 'teacher': None, 'message': 'Teacher not found'}
            
            if not cls._is_teacher(teacher):
                return {'success': False, 'teacher': None, 'message': 'User is not a teacher'}
            
            if email:
                email = email.lower().strip()
                if email != teacher.email:
                    if User.objects.filter(email=email, is_deleted=False).exclude(id=teacher_id).exists():
                        return {'success': False, 'teacher': None, 'message': 'Email already exists'}
                    teacher.email = email
            
            if first_name is not None:
                teacher.first_name = first_name.strip()
            
            if last_name is not None:
                teacher.last_name = last_name.strip()
            
            if middle_name is not None:
                teacher.middle_name = middle_name.strip() if middle_name else None
            
            if is_active is not None:
                teacher.is_active = is_active
                if not is_active:
                    cls._clear_teacher_cache(teacher_id)
            
            teacher.save()
            
            return cls.get_by_id(teacher_id)
            
        except Exception as e:
            return {'success': False, 'teacher': None, 'message': f'Failed to update teacher: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_password(cls, teacher_id: int, new_password: str) -> dict:
        try:
            teacher = User.objects.filter(id=teacher_id, is_deleted=False).first()
            
            if not teacher:
                return {'success': False, 'message': 'Teacher not found'}
            
            if not cls._is_teacher(teacher):
                return {'success': False, 'message': 'User is not a teacher'}
            
            teacher.password = make_password(new_password)
            teacher.save(update_fields=['password', 'updated_at'])
            cls._clear_teacher_cache(teacher_id)
            
            return {'success': True, 'message': 'Password updated'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to update password: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_groups(cls, teacher_id: int, group_ids: list) -> dict:
        try:
            teacher = User.objects.filter(id=teacher_id, is_deleted=False).first()
            
            if not teacher:
                return {'success': False, 'teacher': None, 'message': 'Teacher not found'}
            
            if not cls._is_teacher(teacher):
                return {'success': False, 'teacher': None, 'message': 'User is not a teacher'}
            
            old_group_ids = list(
                UserGroupAccess.objects
                .filter(user=teacher)
                .values_list('group_id', flat=True)
            )
            
            UserGroupAccess.objects.filter(user=teacher).delete()
            
            if group_ids:
                groups = Group.objects.filter(id__in=group_ids)
                for group in groups:
                    UserGroupAccess.objects.create(user=teacher, group=group)
            
            all_group_ids = set(old_group_ids) | set(group_ids or [])
            for group_id in all_group_ids:
                cache.delete(f"auth:group_access:{teacher_id}:{group_id}")
            
            return cls.get_by_id(teacher_id)
            
        except Exception as e:
            return {'success': False, 'teacher': None, 'message': f'Failed to update groups: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def add_to_group(cls, teacher_id: int, group_id: int) -> dict:
        try:
            teacher = User.objects.filter(id=teacher_id, is_deleted=False).first()
            
            if not teacher:
                return {'success': False, 'teacher': None, 'message': 'Teacher not found'}
            
            if not cls._is_teacher(teacher):
                return {'success': False, 'teacher': None, 'message': 'User is not a teacher'}
            
            group = Group.objects.filter(id=group_id).first()
            if not group:
                return {'success': False, 'teacher': None, 'message': 'Group not found'}
            if UserGroupAccess.objects.filter(user=teacher, group=group).exists():
                return {'success': False, 'teacher': None, 'message': 'Teacher already assigned to this group'}
            
            UserGroupAccess.objects.create(user=teacher, group=group)
            cache.delete(f"auth:group_access:{teacher_id}:{group_id}")
            
            return cls.get_by_id(teacher_id)
            
        except Exception as e:
            return {'success': False, 'teacher': None, 'message': f'Failed to add to group: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def remove_from_group(cls, teacher_id: int, group_id: int) -> dict:
        try:
            teacher = User.objects.filter(id=teacher_id, is_deleted=False).first()
            
            if not teacher:
                return {'success': False, 'teacher': None, 'message': 'Teacher not found'}
            
            if not cls._is_teacher(teacher):
                return {'success': False, 'teacher': None, 'message': 'User is not a teacher'}
            
            deleted, _ = UserGroupAccess.objects.filter(user=teacher, group_id=group_id).delete()
            
            if not deleted:
                return {'success': False, 'teacher': None, 'message': 'Teacher not assigned to this group'}
            
            cache.delete(f"auth:group_access:{teacher_id}:{group_id}")
            
            return cls.get_by_id(teacher_id)
            
        except Exception as e:
            return {'success': False, 'teacher': None, 'message': f'Failed to remove from group: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def delete(cls, teacher_id: int) -> dict:
        try:
            teacher = User.objects.filter(id=teacher_id, is_deleted=False).first()
            
            if not teacher:
                return {'success': False, 'message': 'Teacher not found'}
            
            if not cls._is_teacher(teacher):
                return {'success': False, 'message': 'User is not a teacher'}
            
            teacher.is_deleted = True
            teacher.is_active = False
            teacher.deleted_at = datetime.now()
            teacher.save()
            
            from main.models import Session
            Session.objects.filter(user=teacher).delete()

            cls._clear_teacher_cache(teacher_id)
            
            return {'success': True, 'message': 'Teacher deleted'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete teacher: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def restore(cls, teacher_id: int) -> dict:
        try:
            teacher = User.objects.filter(id=teacher_id, is_deleted=True).first()
            
            if not teacher:
                return {'success': False, 'teacher': None, 'message': 'Deleted teacher not found'}
            if User.objects.filter(email=teacher.email, is_deleted=False).exclude(id=teacher_id).exists():
                return {'success': False, 'teacher': None, 'message': 'Email is now used by another user'}
            
            teacher.is_deleted = False
            teacher.is_active = True
            teacher.deleted_at = None
            teacher.save()
            
            return cls.get_by_id(teacher_id)
            
        except Exception as e:
            return {'success': False, 'teacher': None, 'message': f'Failed to restore teacher: {str(e)}'}
    
    @classmethod
    def _is_teacher(cls, user: User) -> bool:
        if hasattr(user, '_prefetched_objects_cache') and 'roles' in user._prefetched_objects_cache:
            return any(r.name == cls.TEACHER_ROLE_NAME for r in user.roles.all())
        return user.roles.filter(name=cls.TEACHER_ROLE_NAME).exists()
    
    @classmethod
    def _serialize_teacher_list(cls, teacher: User) -> dict:
        groups = []
        if hasattr(teacher, 'group_accesses'):
            for access in teacher.group_accesses.all():
                if access.group and access.group.is_active:
                    groups.append({
                        'id': access.group.id,
                        'name': access.group.name
                    })
        
        return {
            'id': teacher.id,
            'email': teacher.email,
            'first_name': teacher.first_name,
            'last_name': teacher.last_name,
            'full_name': teacher.full_name,
            'is_active': teacher.is_active,
            'group_count': getattr(teacher, 'group_count', len(groups)),
            'groups': groups,
            'created_at': teacher.created_at.isoformat() if teacher.created_at else None
        }
    
    @classmethod
    def _serialize_teacher_detail(cls, teacher: User) -> dict:
        groups = []
        if hasattr(teacher, 'group_accesses'):
            for access in teacher.group_accesses.all():
                if access.group:
                    groups.append({
                        'id': access.group.id,
                        'name': access.group.name,
                        'is_active': access.group.is_active
                    })
        
        roles = [{'id': r.id, 'name': r.name} for r in teacher.roles.all()]
        
        return {
            'id': teacher.id,
            'email': teacher.email,
            'first_name': teacher.first_name,
            'last_name': teacher.last_name,
            'middle_name': teacher.middle_name,
            'full_name': teacher.full_name,
            'is_active': teacher.is_active,
            'roles': roles,
            'groups': groups,
            'group_count': len(groups),
            'last_login_at': teacher.last_login_at.isoformat() if teacher.last_login_at else None,
            'created_at': teacher.created_at.isoformat() if teacher.created_at else None,
            'updated_at': teacher.updated_at.isoformat() if teacher.updated_at else None
        }
    
    @classmethod
    def _clear_teacher_cache(cls, teacher_id: int):
        cache.delete(f"auth:user:{teacher_id}")
        cache.delete(f"auth:permissions:{teacher_id}")