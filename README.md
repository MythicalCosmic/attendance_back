# Attendance API

> Fast, modular attendance management backend with service-layer architecture

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-5.x-092E20?logo=django&logoColor=white)
![DRF](https://img.shields.io/badge/DRF-3.x-ff1709?logo=django&logoColor=white)
![Status](https://img.shields.io/badge/Status-In_Development-yellow)

A high-performance attendance management API built for educational institutions and organizations. Features a clean modular architecture with shared base components, dedicated admin controls, and optimized endpoints for speed.

> ⚠️ **Note:** This project is under active development. Core features are functional, additional features coming soon.

---

## ✨ Features

### 📋 Attendance Management
- Record student/employee attendance
- Check-in and check-out tracking
- Attendance history and reports
- Bulk attendance operations

### 👥 User Management
- Student/employee profiles
- Role-based access (Admin, Teacher, Student)
- Authentication and authorization

### 🔐 Admin Panel
- User management and moderation
- Attendance monitoring
- Reports and analytics
- System configuration

### ⚡ Performance First
- Optimized database queries
- Minimal response times
- Efficient serialization
- Clean service-layer architecture

---

## 🏗️ Architecture

The project follows a **modular architecture** with a shared base module containing common utilities.

```
┌────────────────────────────────────────────────────────┐
│                   ATTENDANCE API                       │
├────────────────────────────────────────────────────────┤
│                                                        │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│   │   Admins    │  │ Attendance  │  │    Users    │   │
│   │   Module    │  │   Module    │  │   Module    │   │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│          │                │                │          │
│          └────────────────┼────────────────┘          │
│                           │                           │
│                    ┌──────▼──────┐                    │
│                    │    BASE     │                    │
│                    │   MODULE    │                    │
│                    ├─────────────┤                    │
│                    │ • Helpers   │                    │
│                    │ • Middleware│                    │
│                    │ • Services  │                    │
│                    │ • Utils     │                    │
│                    └──────┬──────┘                    │
│                           │                           │
│                    ┌──────▼──────┐                    │
│                    │  Database   │                    │
│                    └─────────────┘                    │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Framework** | Django 5.x |
| **API** | Django REST Framework |
| **Database** | SQLite (dev) / PostgreSQL (prod) |
| **Auth** | JWT / Token-based |

---

## 📁 Project Structure

```
attendance_back/
│
├── base/                       # Shared core module
│   ├── helpers/               # Common helper functions
│   ├── middleware/            # Custom middleware
│   ├── services/              # Shared services
│   ├── utils/                 # Utility functions
│   ├── models.py              # Base/abstract models
│   ├── serializers.py         # Base serializers
│   ├── permissions.py         # Custom permissions
│   └── exceptions.py          # Custom exceptions
│
├── attendence/                 # Attendance module
│   ├── migrations/            # DB migrations
│   ├── services/              # Attendance logic
│   ├── views/                 # API views
│   ├── models.py              # Attendance models
│   ├── serializers.py         # DRF serializers
│   └── urls.py                # URL routing
│
├── admins/                     # Admin module
│   ├── migrations/            # DB migrations
│   ├── services/              # Admin business logic
│   ├── views/                 # Admin API views
│   ├── models.py              # Admin models
│   ├── serializers.py         # Admin serializers
│   └── urls.py                # Admin URLs
│
├── main/                       # Django project config
│   ├── settings.py            # Project settings
│   ├── urls.py                # Root URL config
│   ├── asgi.py                # ASGI config
│   └── wsgi.py                # WSGI config
│
├── manage.py                   # Django CLI
├── requirements.txt            # Dependencies
└── .gitignore                  # Git ignore
```

---

## 📦 Installation

### Prerequisites

- Python 3.11+
- Git

### Setup

```bash
# Clone repository
git clone https://github.com/MythicalCosmic/attendance_back.git
cd attendance_back

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start server
python manage.py runserver
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file:

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (PostgreSQL for production)
DATABASE_URL=postgres://user:pass@localhost:5432/attendance

# JWT Settings
JWT_SECRET_KEY=your-jwt-secret
JWT_EXPIRATION_HOURS=24
```

---

## 🔌 API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login/` | User login |
| `POST` | `/api/auth/logout/` | User logout |
| `GET` | `/api/auth/me/` | Current user |

### Attendance

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/attendance/` | List attendance records |
| `POST` | `/api/attendance/` | Create attendance record |
| `POST` | `/api/attendance/check-in/` | Check in |
| `POST` | `/api/attendance/check-out/` | Check out |
| `GET` | `/api/attendance/{id}/` | Get record details |
| `GET` | `/api/attendance/report/` | Attendance report |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/users/` | List all users |
| `POST` | `/api/admin/users/` | Create user |
| `GET` | `/api/admin/users/{id}/` | User details |
| `PATCH` | `/api/admin/users/{id}/` | Update user |
| `DELETE` | `/api/admin/users/{id}/` | Delete user |
| `GET` | `/api/admin/attendance/` | All attendance records |
| `GET` | `/api/admin/reports/` | Admin reports |

---

## 🧱 Base Module

The `base/` module provides shared components used across all modules:

### Helpers
Common utility functions for data processing, validation, etc.

### Middleware
- Authentication middleware
- Request logging
- Error handling

### Services
Shared business logic and external integrations.

### Permissions
Custom DRF permission classes for role-based access.

```python
# Example usage in other modules
from base.helpers import format_date, validate_input
from base.permissions import IsAdmin, IsTeacher
from base.services import NotificationService
```

---

## 🚀 Deployment

### Production with Gunicorn

```bash
pip install gunicorn
gunicorn main.wsgi:application --bind 0.0.0.0:8000 --workers 4
```

### With Nginx

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /static/ {
        alias /path/to/staticfiles/;
    }
}
```

---

## 🛡️ Security

- Token-based authentication
- Role-based access control
- Input validation
- CORS headers configured
- SQL injection protection (ORM)

---

## 📋 Roadmap

- [x] Core attendance tracking
- [x] Admin user management
- [x] Base module architecture
- [x] Authentication system
- [ ] Bulk attendance import
- [ ] Advanced reporting
- [ ] Email notifications
- [ ] Mobile app API optimization
- [ ] Export to CSV/Excel

---

## 🐛 Troubleshooting

### Migration Errors

```bash
# Reset migrations
python manage.py migrate --run-syncdb

# Fresh start
rm db.sqlite3
python manage.py migrate
```

### CORS Issues

Ensure CORS headers are configured in settings:

```python
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://yourdomain.com",
]
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/NewFeature`)
3. Commit changes (`git commit -m 'Add NewFeature'`)
4. Push to branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

**Fast, clean, and modular — attendance tracking done right.**
