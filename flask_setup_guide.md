# 🚌 Bus Pass Verification System - Flask Backend

A secure, role-based Flask application for managing and verifying student bus passes with QR code scanning capabilities.

## 🔐 Security Features

- **Secure Authentication**: PBKDF2 password hashing with 100,000 iterations
- **Session Management**: Database-backed sessions with expiration
- **Rate Limiting**: Protection against brute force attacks
- **Account Lockout**: Automatic lockout after 5 failed login attempts
- **Audit Logging**: Comprehensive activity tracking
- **Input Validation**: Server-side and client-side validation
- **CSRF Protection**: Built-in Flask security features
- **XSS Protection**: Content Security Policy headers
- **SQL Injection Prevention**: Parameterized queries

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## 🚀 Installation

### 1. Clone or Download the Application

Create a new directory and save the following files:

```
bus_pass_system/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   ├── base.html         # Base template
│   ├── login.html        # Login page
│   └── dashboard.html    # Main dashboard
├── uploads/              # File upload directory (auto-created)
└── logs/                 # Log files directory (auto-created)
```

### 2. Set up Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv bus_pass_venv

# Activate virtual environment
# On Windows:
bus_pass_venv\Scripts\activate
# On macOS/Linux:
source bus_pass_venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Create Directory Structure

```bash
# Create templates directory
mkdir templates

# Create uploads directory (auto-created by app)
mkdir uploads

# Create logs directory (auto-created by app)
mkdir logs
```

### 5. Save Template Files

Save the HTML templates in the `templates/` directory:
- `base.html`
- `login.html` 
- `dashboard.html`

## 🏃‍♂️ Running the Application

### Development Mode

```bash
python app.py
```

The application will start on `http://localhost:5000`

### Production Mode

For production deployment, use a WSGI server like Gunicorn:

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 🔑 Default Login Credentials

### Admin Access
- **Username**: `admin`
- **Password**: `Admin@123!`

### Staff Access  
- **Username**: `staff`
- **Password**: `staff123`

> ⚠️ **Important**: Change these default credentials immediately in production!

## 👥 User Roles & Permissions

### Admin Role
- ✅ Upload student data (CSV/Excel)
- ✅ Add individual students
- ✅ Search students
- ✅ QR code scanning
- ✅ Manage and export data
- ✅ View audit logs
- ✅ Full system access

### Staff Role
- ✅ Search students
- ✅ QR code scanning
- ❌ Data upload/modification
- ❌ System administration

## 📊 Database Schema

The application uses SQLite with the following tables:

### Students Table
```sql
CREATE TABLE students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT UNIQUE NOT NULL,
    student_name TEXT NOT NULL,
    course TEXT NOT NULL,
    stoppage TEXT NOT NULL,
    bus_no TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'staff')),
    is_active INTEGER DEFAULT 1,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Audit Log Table
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## 📁 File Upload Format

### CSV Format
```csv
student_id,student_name,course,stoppage,bus_no
STU001,John Doe,Computer Science,Main Gate,BUS01
STU002,Jane Smith,Mathematics,Library,BUS02
```

### Excel Format
Same columns as CSV, first row should contain headers.

### Validation Rules
- **student_id**: 3-20 characters, alphanumeric, underscore, dash only
- **student_name**: 2-100 characters, letters, spaces, dots only
- **course**: Required, any text
- **stoppage**: Required, any text  
- **bus_no**: 1-10 characters, uppercase letters, numbers, dashes only

## 🔧 Configuration

### Environment Variables (Optional)

```bash
export FLASK_SECRET_KEY="your-super-secret-key-here"
export FLASK_ENV="production"
export UPLOAD_FOLDER="/path/to/uploads"
export MAX_CONTENT_LENGTH="16777216"  # 16MB in bytes
```

### Security Settings

Edit `app.py` to customize security settings:

```python
# Session timeout (default: 2 hours)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# File size limit (default: 16MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Rate limiting (default: 5 login attempts per 15 minutes)
@rate_limit(max_requests=5, window=900)
```

## 🚀 Production Deployment

### 1. Security Checklist

- [ ] Change default admin credentials
- [ ] Set secure `SECRET_KEY`
- [ ] Enable HTTPS
- [ ] Configure firewall
- [ ] Set up proper logging
- [ ] Regular database backups
- [ ] Update dependencies regularly

### 2. Nginx Configuration Example

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # File upload limit
    client_max_body_size 20M;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Static files (if any)
    location /static {
        alias /path/to/your/static/files;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### 3. Systemd Service (Linux)

Create `/etc/systemd/system/bus-pass-system.service`:

```ini
[Unit]
Description=Bus Pass Verification System
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/bus_pass_system
Environment=PATH=/path/to/bus_pass_system/venv/bin
ExecStart=/path/to/bus_pass_system/venv/bin/gunicorn --workers 4 --bind unix:bus_pass_system.sock -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable bus-pass-system
sudo systemctl start bus-pass-system
```

### 4. Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p uploads logs templates

# Set permissions
RUN chmod +x app.py

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000')"

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]
```

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  bus-pass-system:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./uploads:/app/uploads
      - ./logs:/app/logs
      - ./bus_pass.db:/app/bus_pass.db
    environment:
      - FLASK_ENV=production
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - bus-pass-system
    restart: unless-stopped
```

## 🔍 API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### Students Management
- `GET /api/students` - Get all students
- `POST /api/students` - Add new student (Admin only)
- `POST /api/students/search` - Search student by ID
- `POST /api/students/upload` - Bulk upload students (Admin only)
- `GET /api/students/export/<format>` - Export students data (Admin only)

### System Administration
- `GET /api/audit-logs` - Get audit logs (Admin only)

## 📱 QR Code Integration

The system supports QR code scanning for quick student verification:

1. **Generate QR Codes**: Create QR codes containing student IDs
2. **Scan with Camera**: Use the built-in scanner or mobile camera
3. **Instant Verification**: Real-time student information display

### QR Code Generation Example

```python
import qrcode

def generate_student_qr(student_id):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(student_id)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(f"qr_codes/{student_id}.png")
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Database Connection Error
```
sqlite3.OperationalError: database is locked
```
**Solution**: Ensure no other process is accessing the database, restart the application.

#### 2. File Upload Fails
```
413 Request Entity Too Large
```
**Solution**: Check `MAX_CONTENT_LENGTH` setting and nginx configuration.

#### 3. Camera Access Denied
**Solution**: 
- Ensure HTTPS is enabled (required for camera access)
- Check browser permissions
- Test on localhost for development

#### 4. Session Expires Quickly
**Solution**: Check `PERMANENT_SESSION_LIFETIME` configuration.

### Debug Mode

Enable debug mode for development:

```python
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Logging

Check application logs:

```bash
# Application logs
tail -f app.log

# System logs (if using systemd)
sudo journalctl -u bus-pass-system -f
```

## 📊 Monitoring & Maintenance

### Database Backup

```bash
# Create backup
cp bus_pass.db bus_pass_backup_$(date +%Y%m%d_%H%M%S).db

# Automated backup script
#!/bin/bash
BACKUP_DIR="/path/to/backups"
DATE=$(date +%Y%m%d_%H%M%S)
cp bus_pass.db "$BACKUP_DIR/bus_pass_backup_$DATE.db"
find "$BACKUP_DIR" -name "bus_pass_backup_*.db" -mtime +30 -delete
```

### Performance Monitoring

```python
# Add to app.py for basic monitoring
@app.after_request
def after_request(response):
    app.logger.info(f"{request.method} {request.path} - {response.status_code}")
    return response
```

### Security Monitoring

- Monitor failed login attempts
- Check audit logs regularly  
- Update dependencies monthly
- Review user accounts quarterly

## 🔄 Updates & Migration

### Updating the Application

1. **Backup database and files**
2. **Update code files**
3. **Install new dependencies**
4. **Restart application**

```bash
# Backup
cp bus_pass.db bus_pass_backup.db

# Update dependencies
pip install -r requirements.txt --upgrade

# Restart service
sudo systemctl restart bus-pass-system
```

### Database Migration

For schema changes, create migration scripts:

```python
# migration_001_add_column.py
import sqlite3

def migrate():
    conn = sqlite3.connect('bus_pass.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('ALTER TABLE students ADD COLUMN phone TEXT')
        conn.commit()
        print("Migration completed successfully")
    except Exception as e:
        print(f"Migration failed: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    migrate()
```

## 📞 Support

For issues and feature requests:

1. Check the troubleshooting section
2. Review application logs
3. Test with default credentials
4. Verify system requirements

## 📄 License

This application is provided as-is for educational and development purposes.

## 🚀 Future Enhancements

- [ ] Multi-tenant support
- [ ] REST API documentation (Swagger)
- [ ] Email notifications
- [ ] Advanced reporting
- [ ] Mobile app integration
- [ ] Bulk QR code generation
- [ ] Student photo integration
- [ ] GPS-based attendance
- [ ] SMS notifications
- [ ] Advanced analytics dashboard