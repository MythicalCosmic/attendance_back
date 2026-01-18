from django.core.cache import cache
from django.db import transaction
from django.db.models import Q, Count, Prefetch
from datetime import datetime, date
from main.models import Group, Student, UserGroupAccess, User


class GroupService:
    @classmethod
    def get_by_id(cls, group_id: int) -> dict:
        try:
            group = (
                Group.objects
                .filter(id=group_id)
                .annotate(
                    student_count=Count('students', filter=Q(students__is_deleted=False)),
                    active_student_count=Count(
                        'students',
                        filter=Q(students__is_deleted=False, students__is_active=True)
                    )
                )
                .prefetch_related(
                    Prefetch(
                        'user_accesses__user',
                        queryset=User.objects.filter(is_deleted=False).only(
                            'id', 'first_name', 'last_name', 'email'
                        )
                    )
                )
                .first()
            )
            
            if not group:
                return {'success': False, 'group': None, 'message': 'Group not found'}
            
            return {
                'success': True,
                'group': cls._serialize_group_detail(group),
                'message': 'Group retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to get group: {str(e)}'}
    
    @classmethod
    def get_list(
        cls,
        page: int = 1,
        per_page: int = 20,
        search: str = None,
        is_active: bool = None,
        is_finished: bool = None,
        is_cancelled: bool = None,
        order_by: str = '-created_at'
    ) -> dict:
        try:
            queryset = (
                Group.objects
                .annotate(
                    student_count=Count('students', filter=Q(students__is_deleted=False)),
                    active_student_count=Count(
                        'students',
                        filter=Q(students__is_deleted=False, students__is_active=True)
                    )
                )
            )
            
            if search:
                queryset = queryset.filter(
                    Q(name__icontains=search) |
                    Q(description__icontains=search)
                )
            
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active)
            
            if is_finished is not None:
                queryset = queryset.filter(is_finished=is_finished)
            
            if is_cancelled is not None:
                queryset = queryset.filter(is_cancelled=is_cancelled)
            
            # Ordering
            allowed_ordering = [
                'name', '-name',
                'created_at', '-created_at',
                'start_date', '-start_date',
                'end_date', '-end_date'
            ]
            if order_by in allowed_ordering:
                queryset = queryset.order_by(order_by)
            else:
                queryset = queryset.order_by('-created_at')

            total = queryset.count()

            offset = (page - 1) * per_page
            groups = queryset[offset:offset + per_page]
            
            return {
                'success': True,
                'groups': [cls._serialize_group_list(g) for g in groups],
                'meta': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': (total + per_page - 1) // per_page
                },
                'message': 'Groups retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'groups': [], 'meta': None, 'message': f'Failed to get groups: {str(e)}'}
    
    @classmethod
    def get_active_groups(cls) -> dict:
        try:
            groups = (
                Group.objects
                .filter(is_active=True, is_finished=False, is_cancelled=False)
                .annotate(
                    student_count=Count('students', filter=Q(students__is_deleted=False, students__is_active=True))
                )
                .order_by('name')
            )
            
            return {
                'success': True,
                'groups': [
                    {
                        'id': g.id,
                        'name': g.name,
                        'student_count': g.student_count
                    }
                    for g in groups
                ],
                'message': 'Active groups retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'groups': [], 'message': f'Failed to get groups: {str(e)}'}
    
    @classmethod
    def get_user_groups(cls, user_id: int) -> dict:
        try:
            group_ids = (
                UserGroupAccess.objects
                .filter(user_id=user_id)
                .values_list('group_id', flat=True)
            )
            
            groups = (
                Group.objects
                .filter(id__in=group_ids, is_active=True)
                .annotate(
                    student_count=Count('students', filter=Q(students__is_deleted=False, students__is_active=True))
                )
                .order_by('name')
            )
            
            return {
                'success': True,
                'groups': [cls._serialize_group_list(g) for g in groups],
                'message': 'User groups retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'groups': [], 'message': f'Failed to get user groups: {str(e)}'}
    
    @classmethod
    def get_stats(cls) -> dict:
        try:
            total = Group.objects.count()
            active = Group.objects.filter(is_active=True, is_finished=False, is_cancelled=False).count()
            finished = Group.objects.filter(is_finished=True).count()
            cancelled = Group.objects.filter(is_cancelled=True).count()
            
            total_students = Student.objects.filter(is_deleted=False).count()
            active_students = Student.objects.filter(is_deleted=False, is_active=True).count()
            
            return {
                'success': True,
                'stats': {
                    'groups': {
                        'total': total,
                        'active': active,
                        'finished': finished,
                        'cancelled': cancelled
                    },
                    'students': {
                        'total': total_students,
                        'active': active_students
                    }
                },
                'message': 'Stats retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'stats': None, 'message': f'Failed to get stats: {str(e)}'}

    @classmethod
    @transaction.atomic
    def create(
        cls,
        name: str,
        description: str = None,
        start_date: date = None,
        end_date: date = None,
        assigned_user_ids: list = None
    ) -> dict:
        try:
            name = name.strip()

            if start_date and end_date and start_date > end_date:
                return {'success': False, 'group': None, 'message': 'Start date cannot be after end date'}
            
            group = Group.objects.create(
                name=name,
                description=description.strip() if description else None,
                start_date=start_date,
                end_date=end_date,
                is_active=True
            )

            if assigned_user_ids:
                users = User.objects.filter(id__in=assigned_user_ids, is_deleted=False, is_active=True)
                for user in users:
                    UserGroupAccess.objects.create(user=user, group=group)
            
            return cls.get_by_id(group.id)
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to create group: {str(e)}'}

    @classmethod
    @transaction.atomic
    def update(
        cls,
        group_id: int,
        name: str = None,
        description: str = None,
        start_date: date = None,
        end_date: date = None
    ) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            
            if not group:
                return {'success': False, 'group': None, 'message': 'Group not found'}
            
            if name is not None:
                group.name = name.strip()
            
            if description is not None:
                group.description = description.strip() if description else None
            
            if start_date is not None:
                group.start_date = start_date
            
            if end_date is not None:
                group.end_date = end_date

            if group.start_date and group.end_date and group.start_date > group.end_date:
                return {'success': False, 'group': None, 'message': 'Start date cannot be after end date'}
            
            group.save()
            
            return cls.get_by_id(group_id)
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to update group: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_status(
        cls,
        group_id: int,
        is_active: bool = None,
        is_finished: bool = None,
        is_cancelled: bool = None
    ) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            
            if not group:
                return {'success': False, 'group': None, 'message': 'Group not found'}
            
            if is_active is not None:
                group.is_active = is_active
            
            if is_finished is not None:
                group.is_finished = is_finished
                if is_finished:
                    group.is_active = False
            
            if is_cancelled is not None:
                group.is_cancelled = is_cancelled
                if is_cancelled:
                    group.is_active = False
            
            group.save()
            
            return cls.get_by_id(group_id)
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to update group status: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def finish_group(cls, group_id: int) -> dict:
        return cls.update_status(group_id, is_active=False, is_finished=True)
    
    @classmethod
    @transaction.atomic
    def cancel_group(cls, group_id: int) -> dict:
        return cls.update_status(group_id, is_active=False, is_cancelled=True)
    
    @classmethod
    @transaction.atomic
    def reactivate_group(cls, group_id: int) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            
            if not group:
                return {'success': False, 'group': None, 'message': 'Group not found'}
            
            group.is_active = True
            group.is_finished = False
            group.is_cancelled = False
            group.save()
            
            return cls.get_by_id(group_id)
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to reactivate group: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update_assigned_users(cls, group_id: int, user_ids: list) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            
            if not group:
                return {'success': False, 'group': None, 'message': 'Group not found'}
            
            old_user_ids = list(
                UserGroupAccess.objects
                .filter(group=group)
                .values_list('user_id', flat=True)
            )
            UserGroupAccess.objects.filter(group=group).delete()

            if user_ids:
                users = User.objects.filter(id__in=user_ids, is_deleted=False, is_active=True)
                for user in users:
                    UserGroupAccess.objects.create(user=user, group=group)
            
            all_user_ids = set(old_user_ids) | set(user_ids or [])
            for user_id in all_user_ids:
                cache.delete(f"auth:group_access:{user_id}:{group_id}")
            
            return cls.get_by_id(group_id)
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to update assigned users: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def add_assigned_users(cls, group_id: int, user_ids: list) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            
            if not group:
                return {'success': False, 'group': None, 'message': 'Group not found'}
            
            if not user_ids:
                return cls.get_by_id(group_id)

            existing_ids = set(
                UserGroupAccess.objects
                .filter(group=group)
                .values_list('user_id', flat=True)
            )
            
            users = User.objects.filter(
                id__in=user_ids,
                is_deleted=False,
                is_active=True
            ).exclude(id__in=existing_ids)
            
            for user in users:
                UserGroupAccess.objects.create(user=user, group=group)
                cache.delete(f"auth:group_access:{user.id}:{group_id}")
            
            return cls.get_by_id(group_id)
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to add users: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def remove_assigned_users(cls, group_id: int, user_ids: list) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            
            if not group:
                return {'success': False, 'group': None, 'message': 'Group not found'}
            
            if not user_ids:
                return cls.get_by_id(group_id)
            
            UserGroupAccess.objects.filter(group=group, user_id__in=user_ids).delete()
            
            # Clear cache
            for user_id in user_ids:
                cache.delete(f"auth:group_access:{user_id}:{group_id}")
            
            return cls.get_by_id(group_id)
            
        except Exception as e:
            return {'success': False, 'group': None, 'message': f'Failed to remove users: {str(e)}'}

    @classmethod
    @transaction.atomic
    def delete(cls, group_id: int, force: bool = False) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            
            if not group:
                return {'success': False, 'message': 'Group not found'}
            
            student_count = Student.objects.filter(group=group, is_deleted=False).count()
            
            if student_count > 0 and not force:
                return {
                    'success': False,
                    'message': f'Cannot delete group with {student_count} students. Use force=True or remove students first.'
                }
            user_ids = UserGroupAccess.objects.filter(group=group).values_list('user_id', flat=True)
            for user_id in user_ids:
                cache.delete(f"auth:group_access:{user_id}:{group_id}")
        
            if force and student_count > 0:
                Student.objects.filter(group=group, is_deleted=False).update(
                    is_deleted=True,
                    is_active=False,
                    deleted_at=datetime.now()
                )
            
            UserGroupAccess.objects.filter(group=group).delete()
            
            group.delete()
            
            return {
                'success': True,
                'message': f'Group deleted' + (f' along with {student_count} students' if force and student_count > 0 else '')
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete group: {str(e)}'}

    @classmethod
    def _serialize_group_list(cls, group: Group) -> dict:
        return {
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'is_active': group.is_active,
            'is_finished': group.is_finished,
            'is_cancelled': group.is_cancelled,
            'status': cls._get_status_label(group),
            'student_count': getattr(group, 'student_count', 0),
            'active_student_count': getattr(group, 'active_student_count', 0),
            'start_date': group.start_date.isoformat() if group.start_date else None,
            'end_date': group.end_date.isoformat() if group.end_date else None,
            'created_at': group.created_at.isoformat() if group.created_at else None
        }
    
    @classmethod
    def _serialize_group_detail(cls, group: Group) -> dict:
        assigned_users = []
        if hasattr(group, 'user_accesses'):
            for access in group.user_accesses.all():
                if access.user:
                    assigned_users.append({
                        'id': access.user.id,
                        'email': access.user.email,
                        'full_name': access.user.full_name
                    })
        
        return {
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'is_active': group.is_active,
            'is_finished': group.is_finished,
            'is_cancelled': group.is_cancelled,
            'status': cls._get_status_label(group),
            'student_count': getattr(group, 'student_count', 0),
            'active_student_count': getattr(group, 'active_student_count', 0),
            'start_date': group.start_date.isoformat() if group.start_date else None,
            'end_date': group.end_date.isoformat() if group.end_date else None,
            'assigned_users': assigned_users,
            'created_at': group.created_at.isoformat() if group.created_at else None,
            'updated_at': group.updated_at.isoformat() if group.updated_at else None
        }
    
    @classmethod
    def _get_status_label(cls, group: Group) -> str:
        if group.is_cancelled:
            return 'cancelled'
        if group.is_finished:
            return 'finished'
        if group.is_active:
            return 'active'
        return 'inactive'