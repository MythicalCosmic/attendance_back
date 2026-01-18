from django.core.cache import cache
from django.db import transaction
from django.db.models import Q, Count
from datetime import datetime
from main.models import Student, Group


class StudentService:
    @classmethod
    def get_by_id(cls, student_id: int) -> dict:
        try:
            student = (
                Student.objects
                .filter(id=student_id, is_deleted=False)
                .select_related('group')
                .first()
            )
            
            if not student:
                return {'success': False, 'student': None, 'message': 'Student not found'}
            
            return {
                'success': True,
                'student': cls._serialize_student_detail(student),
                'message': 'Student retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'student': None, 'message': f'Failed to get student: {str(e)}'}
    
    @classmethod
    def get_list(
        cls,
        page: int = 1,
        per_page: int = 20,
        search: str = None,
        group_id: int = None,
        is_active: bool = None,
        order_by: str = 'first_name'
    ) -> dict:
        try:
            queryset = (
                Student.objects
                .filter(is_deleted=False)
                .select_related('group')
            )

            if search:
                queryset = queryset.filter(
                    Q(first_name__icontains=search) |
                    Q(last_name__icontains=search) |
                    Q(identifier__icontains=search) |
                    Q(phone__icontains=search)
                )
            
            if group_id:
                queryset = queryset.filter(group_id=group_id)
            
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active)

            allowed_ordering = [
                'first_name', '-first_name',
                'last_name', '-last_name',
                'created_at', '-created_at',
                'group__name', '-group__name'
            ]
            if order_by in allowed_ordering:
                queryset = queryset.order_by(order_by)
            else:
                queryset = queryset.order_by('first_name', 'last_name')
            
            total = queryset.count()

            offset = (page - 1) * per_page
            students = queryset[offset:offset + per_page]
            
            return {
                'success': True,
                'students': [cls._serialize_student_list(s) for s in students],
                'meta': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'total_pages': (total + per_page - 1) // per_page
                },
                'message': 'Students retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'students': [], 'meta': None, 'message': f'Failed to get students: {str(e)}'}
    
    @classmethod
    def get_by_group(cls, group_id: int, is_active: bool = True) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            if not group:
                return {'success': False, 'students': [], 'message': 'Group not found'}
            
            queryset = (
                Student.objects
                .filter(group_id=group_id, is_deleted=False)
                .order_by('first_name', 'last_name')
            )
            
            if is_active is not None:
                queryset = queryset.filter(is_active=is_active)
            
            students = list(queryset)
            
            return {
                'success': True,
                'students': [cls._serialize_student_list(s) for s in students],
                'group': {
                    'id': group.id,
                    'name': group.name
                },
                'message': 'Students retrieved'
            }
            
        except Exception as e:
            return {'success': False, 'students': [], 'message': f'Failed to get students: {str(e)}'}

    @classmethod
    @transaction.atomic
    def create(
        cls,
        group_id: int,
        first_name: str,
        last_name: str,
        middle_name: str = None,
        identifier: str = None,
        phone: str = None,
        is_active: bool = True
    ) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            if not group:
                return {'success': False, 'student': None, 'message': 'Group not found'}
            
            if not group.is_active:
                return {'success': False, 'student': None, 'message': 'Cannot add student to inactive group'}
            
            if group.is_finished:
                return {'success': False, 'student': None, 'message': 'Cannot add student to finished group'}
            
            if identifier:
                identifier = identifier.strip()
                if Student.objects.filter(identifier=identifier, is_deleted=False).exists():
                    return {'success': False, 'student': None, 'message': 'Student identifier already exists'}
            
            student = Student.objects.create(
                group=group,
                first_name=first_name.strip(),
                last_name=last_name.strip(),
                middle_name=middle_name.strip() if middle_name else None,
                identifier=identifier,
                phone=phone.strip() if phone else None,
                is_active=is_active
            )
            
            return cls.get_by_id(student.id)
            
        except Exception as e:
            return {'success': False, 'student': None, 'message': f'Failed to create student: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def bulk_create(cls, group_id: int, students_data: list) -> dict:
        try:
            group = Group.objects.filter(id=group_id).first()
            if not group:
                return {'success': False, 'students': [], 'message': 'Group not found'}
            
            if not group.is_active or group.is_finished:
                return {'success': False, 'students': [], 'message': 'Cannot add students to inactive/finished group'}
            
            created_students = []
            errors = []
            
            for idx, data in enumerate(students_data):
                if not data.get('first_name') or not data.get('last_name'):
                    errors.append(f"Row {idx + 1}: first_name and last_name are required")
                    continue

                identifier = data.get('identifier')
                if identifier:
                    identifier = identifier.strip()
                    if Student.objects.filter(identifier=identifier, is_deleted=False).exists():
                        errors.append(f"Row {idx + 1}: identifier '{identifier}' already exists")
                        continue
                
                student = Student.objects.create(
                    group=group,
                    first_name=data['first_name'].strip(),
                    last_name=data['last_name'].strip(),
                    middle_name=data.get('middle_name', '').strip() or None,
                    identifier=identifier,
                    phone=data.get('phone', '').strip() or None,
                    is_active=data.get('is_active', True)
                )
                created_students.append(cls._serialize_student_list(student))
            
            return {
                'success': True,
                'students': created_students,
                'created_count': len(created_students),
                'errors': errors,
                'message': f'Created {len(created_students)} students' + (f' with {len(errors)} errors' if errors else '')
            }
            
        except Exception as e:
            return {'success': False, 'students': [], 'message': f'Failed to create students: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def update(
        cls,
        student_id: int,
        first_name: str = None,
        last_name: str = None,
        middle_name: str = None,
        identifier: str = None,
        phone: str = None,
        is_active: bool = None
    ) -> dict:
        try:
            student = Student.objects.filter(id=student_id, is_deleted=False).first()
            
            if not student:
                return {'success': False, 'student': None, 'message': 'Student not found'}
            
            if first_name is not None:
                student.first_name = first_name.strip()
            
            if last_name is not None:
                student.last_name = last_name.strip()
            
            if middle_name is not None:
                student.middle_name = middle_name.strip() if middle_name else None
            
            if identifier is not None:
                if identifier:
                    identifier = identifier.strip()
                    if Student.objects.filter(identifier=identifier, is_deleted=False).exclude(id=student_id).exists():
                        return {'success': False, 'student': None, 'message': 'Student identifier already exists'}
                    student.identifier = identifier
                else:
                    student.identifier = None
            
            if phone is not None:
                student.phone = phone.strip() if phone else None
            
            if is_active is not None:
                student.is_active = is_active
            
            student.save()
            
            return cls.get_by_id(student_id)
            
        except Exception as e:
            return {'success': False, 'student': None, 'message': f'Failed to update student: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def transfer_to_group(cls, student_id: int, new_group_id: int) -> dict:
        try:
            student = Student.objects.filter(id=student_id, is_deleted=False).first()
            
            if not student:
                return {'success': False, 'student': None, 'message': 'Student not found'}
            
            new_group = Group.objects.filter(id=new_group_id).first()
            if not new_group:
                return {'success': False, 'student': None, 'message': 'Target group not found'}
            
            if not new_group.is_active:
                return {'success': False, 'student': None, 'message': 'Cannot transfer to inactive group'}
            
            if new_group.is_finished:
                return {'success': False, 'student': None, 'message': 'Cannot transfer to finished group'}
            
            if student.group_id == new_group_id:
                return {'success': False, 'student': None, 'message': 'Student is already in this group'}
            
            student.group = new_group
            student.save()
            
            return cls.get_by_id(student_id)
            
        except Exception as e:
            return {'success': False, 'student': None, 'message': f'Failed to transfer student: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def bulk_transfer(cls, student_ids: list, new_group_id: int) -> dict:
        try:
            new_group = Group.objects.filter(id=new_group_id).first()
            if not new_group:
                return {'success': False, 'message': 'Target group not found'}
            
            if not new_group.is_active or new_group.is_finished:
                return {'success': False, 'message': 'Cannot transfer to inactive/finished group'}
            
            updated = Student.objects.filter(
                id__in=student_ids,
                is_deleted=False
            ).exclude(group_id=new_group_id).update(
                group=new_group,
                updated_at=datetime.now()
            )
            
            return {
                'success': True,
                'transferred_count': updated,
                'message': f'Transferred {updated} students'
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to transfer students: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def delete(cls, student_id: int) -> dict:
        try:
            student = Student.objects.filter(id=student_id, is_deleted=False).first()
            
            if not student:
                return {'success': False, 'message': 'Student not found'}
            
            student.is_deleted = True
            student.is_active = False
            student.deleted_at = datetime.now()
            student.save()
            
            return {'success': True, 'message': 'Student deleted'}
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete student: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def bulk_delete(cls, student_ids: list) -> dict:
        try:
            updated = Student.objects.filter(
                id__in=student_ids,
                is_deleted=False
            ).update(
                is_deleted=True,
                is_active=False,
                deleted_at=datetime.now()
            )
            
            return {
                'success': True,
                'deleted_count': updated,
                'message': f'Deleted {updated} students'
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Failed to delete students: {str(e)}'}
    
    @classmethod
    @transaction.atomic
    def restore(cls, student_id: int) -> dict:
        try:
            student = Student.objects.filter(id=student_id, is_deleted=True).select_related('group').first()
            
            if not student:
                return {'success': False, 'student': None, 'message': 'Deleted student not found'}
            if not student.group or not student.group.is_active:
                return {'success': False, 'student': None, 'message': 'Cannot restore: group is inactive or deleted'}
            
            student.is_deleted = False
            student.is_active = True
            student.deleted_at = None
            student.save()
            
            return cls.get_by_id(student_id)
            
        except Exception as e:
            return {'success': False, 'student': None, 'message': f'Failed to restore student: {str(e)}'}

    @classmethod
    def _serialize_student_list(cls, student: Student) -> dict:
        return {
            'id': student.id,
            'first_name': student.first_name,
            'last_name': student.last_name,
            'full_name': student.full_name,
            'identifier': student.identifier,
            'phone': student.phone,
            'is_active': student.is_active,
            'group': {
                'id': student.group_id,
                'name': student.group.name if student.group else None
            } if student.group_id else None,
            'created_at': student.created_at.isoformat() if student.created_at else None
        }
    
    @classmethod
    def _serialize_student_detail(cls, student: Student) -> dict:
        return {
            'id': student.id,
            'first_name': student.first_name,
            'last_name': student.last_name,
            'middle_name': student.middle_name,
            'full_name': student.full_name,
            'identifier': student.identifier,
            'phone': student.phone,
            'is_active': student.is_active,
            'group': {
                'id': student.group.id,
                'name': student.group.name,
                'is_active': student.group.is_active
            } if student.group else None,
            'created_at': student.created_at.isoformat() if student.created_at else None,
            'updated_at': student.updated_at.isoformat() if student.updated_at else None
        }