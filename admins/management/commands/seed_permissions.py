from django.core.management.base import BaseCommand
from django.db import transaction
from main.models import Permission, Role, RolePermission


class Command(BaseCommand):
    help = 'Seed permissions and default roles for the attendance system'

    PERMISSIONS = [
        ('user.view', 'View Users', 'Can view user list and details'),
        ('user.create', 'Create Users', 'Can create new users'),
        ('user.edit', 'Edit Users', 'Can edit user details'),
        ('user.delete', 'Delete Users', 'Can delete users'),

        ('role.view', 'View Roles', 'Can view roles and their permissions'),
        ('role.create', 'Create Roles', 'Can create new roles'),
        ('role.edit', 'Edit Roles', 'Can edit roles and assign permissions'),
        ('role.delete', 'Delete Roles', 'Can delete roles'),
        
        ('group.view', 'View Groups', 'Can view group list and details'),
        ('group.create', 'Create Groups', 'Can create new groups'),
        ('group.edit', 'Edit Groups', 'Can edit group details'),
        ('group.delete', 'Delete Groups', 'Can delete groups'),
        ('group.access_all', 'Access All Groups', 'Can access all groups without restrictions'),
        
        ('student.view', 'View Students', 'Can view student list and details'),
        ('student.create', 'Create Students', 'Can add new students'),
        ('student.edit', 'Edit Students', 'Can edit student details'),
        ('student.delete', 'Delete Students', 'Can remove students'),

        ('attendance.view', 'View Attendance', 'Can view attendance records'),
        ('attendance.mark', 'Mark Attendance', 'Can mark daily attendance'),
        ('attendance.edit', 'Edit Attendance', 'Can edit past attendance records'),
        ('attendance.delete', 'Delete Attendance', 'Can delete attendance records'),
        ('attendance.export', 'Export Attendance', 'Can export attendance to Excel'),

        ('report.view', 'View Reports', 'Can view attendance reports'),
        ('report.export', 'Export Reports', 'Can export reports'),
    ]

    DEFAULT_ROLES = {
        'Super Admin': {
            'description': 'Full system access with all permissions',
            'permissions': '__all__' 
        },
        'Admin': {
            'description': 'Administrative access without role management',
            'permissions': [
                'user.view', 'user.create', 'user.edit', 'user.delete',
                'role.view',
                'group.view', 'group.create', 'group.edit', 'group.delete', 'group.access_all',
                'student.view', 'student.create', 'student.edit', 'student.delete',
                'attendance.view', 'attendance.mark', 'attendance.edit', 'attendance.delete', 'attendance.export',
                'report.view', 'report.export',
            ]
        },
        'Teacher': {
            'description': 'Can manage attendance for assigned groups',
            'permissions': [
                'group.view',
                'student.view',
                'attendance.view', 'attendance.mark', 'attendance.export',
                'report.view',
            ]
        },
        'Viewer': {
            'description': 'Read-only access to attendance data',
            'permissions': [
                'group.view',
                'student.view',
                'attendance.view',
                'report.view',
            ]
        },
    }

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing permissions and roles before seeding',
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write('Clearing existing data...')
            RolePermission.objects.all().delete()
            Role.objects.all().delete()
            Permission.objects.all().delete()
            self.stdout.write(self.style.WARNING('Cleared all permissions and roles'))

        # Seed permissions
        self.stdout.write('Seeding permissions...')
        permissions_created = 0
        permissions_updated = 0
        
        all_permissions = {}
        
        for codename, name, description in self.PERMISSIONS:
            permission, created = Permission.objects.update_or_create(
                codename=codename,
                defaults={
                    'name': name,
                    'description': description
                }
            )
            all_permissions[codename] = permission
            
            if created:
                permissions_created += 1
                self.stdout.write(f'  + Created: {codename}')
            else:
                permissions_updated += 1
                self.stdout.write(f'  ~ Updated: {codename}')

        self.stdout.write(
            self.style.SUCCESS(
                f'Permissions: {permissions_created} created, {permissions_updated} updated'
            )
        )
        self.stdout.write('\nSeeding roles...')
        roles_created = 0
        roles_updated = 0

        for role_name, role_data in self.DEFAULT_ROLES.items():
            role, created = Role.objects.update_or_create(
                name=role_name,
                defaults={'description': role_data['description']}
            )

            RolePermission.objects.filter(role=role).delete()
            if role_data['permissions'] == '__all__':
                permissions_to_assign = all_permissions.values()
            else:
                permissions_to_assign = [
                    all_permissions[p] for p in role_data['permissions']
                    if p in all_permissions
                ]

            for permission in permissions_to_assign:
                RolePermission.objects.create(role=role, permission=permission)

            perm_count = len(list(permissions_to_assign))
            
            if created:
                roles_created += 1
                self.stdout.write(f'  + Created: {role_name} ({perm_count} permissions)')
            else:
                roles_updated += 1
                self.stdout.write(f'  ~ Updated: {role_name} ({perm_count} permissions)')

        self.stdout.write(
            self.style.SUCCESS(
                f'Roles: {roles_created} created, {roles_updated} updated'
            )
        )

        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(self.style.SUCCESS('Seeding completed!'))
        self.stdout.write(f'Total permissions: {Permission.objects.count()}')
        self.stdout.write(f'Total roles: {Role.objects.count()}')
        
        self.stdout.write('\nRole summary:')
        for role in Role.objects.prefetch_related('permissions').all():
            perm_count = role.permissions.count()
            self.stdout.write(f'  - {role.name}: {perm_count} permissions')