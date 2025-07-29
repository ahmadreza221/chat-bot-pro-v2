# Chat Bot Pro V2 - System Architecture

## Overview

Chat Bot Pro V2 is a production-grade microservice platform built with modern technologies and security best practices.

## Technology Stack

### Backend Services
- **Rust (Axum)**: High-performance API server with async/await
- **PostgreSQL**: Primary database with ACID compliance
- **Redis**: Caching, sessions, and job queues
- **Python FastAPI**: AI/Analytics microservice

### Frontend
- **React 18**: TypeScript-based SPA
- **Vite**: Fast build tool and dev server
- **React Router**: Client-side routing with RBAC guards

### Infrastructure
- **Docker Compose**: Multi-container orchestration
- **Nginx**: Reverse proxy with SSL termination
- **Certbot**: Automatic Let's Encrypt certificate management
- **Prometheus + Grafana**: Monitoring and observability

## System Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Nginx         │    │   Certbot       │
│   (React SPA)   │◄──►│   (Reverse      │◄──►│   (SSL Certs)   │
│   Port 3000     │    │    Proxy)       │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Backend       │    │   AI Worker     │    │   PostgreSQL    │
│   (Rust/Axum)   │◄──►│   (Python)      │◄──►│   (Database)    │
│   Port 8080     │    │   Port 8000     │    │   Port 5432     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   Redis         │    │   Prometheus    │
                       │   (Cache/Queue) │    │   (Metrics)     │
                       │   Port 6379     │    │   Port 9090     │
                       └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │   Grafana       │
                                              │   (Dashboard)   │
                                              │   Port 3001     │
                                              └─────────────────┘
```

## Authentication Flow

### 1. Registration Process
```
User → Frontend → Backend → Database
  ↓
1. User submits registration form
2. Backend validates input
3. Password hashed with Argon2
4. User record created (unverified)
5. Email verification token generated
6. Email stub logged (production: real email sent)
7. Response: User ID returned
```

### 2. Email Verification
```
User → Frontend → Backend → Database
  ↓
1. User clicks email verification link
2. Token validated against database
3. User marked as verified
4. Token marked as used
5. User can now login
```

### 3. Login Process
```
User → Frontend → Backend → Database
  ↓
1. User submits credentials
2. Backend validates email/password
3. If 2FA enabled: OTP required
4. Session created with 30-day expiry
5. JWT token generated (RS256)
6. Device fingerprint captured
7. Response: JWT token
```

### 4. 2FA Setup
```
User → Frontend → Backend → Database
  ↓
1. User requests 2FA setup
2. TOTP secret generated (Base32)
3. Secret stored in database
4. QR code URI generated
5. User scans with authenticator app
6. User verifies with 6-digit code
7. 2FA enabled for account
```

## Security Features

### Authentication & Authorization
- **JWT Tokens**: RS256 signed with rotating keys
- **Session Management**: Database-backed with expiry
- **RBAC**: Role-based access control
- **2FA**: TOTP-based multi-factor authentication
- **Rate Limiting**: IP-based with burst protection

### Data Protection
- **Password Hashing**: Argon2 with salt
- **HTTPS**: TLS 1.3 with Let's Encrypt
- **Input Validation**: Comprehensive sanitization
- **SQL Injection Protection**: Parameterized queries
- **XSS Protection**: Content Security Policy

### Infrastructure Security
- **Container Isolation**: Docker network segmentation
- **Secret Management**: Environment variables
- **Audit Logging**: All auth events logged
- **Device Tracking**: Fingerprint and IP logging

## Database Schema

### Core Tables
```sql
-- Users and Authentication
users (id, email, password_hash, is_verified, totp_secret, totp_enabled, ...)
roles (id, name, description)
user_roles (user_id, role_id)
sessions (id, user_id, ip_address, user_agent, expires_at)
device_fingerprints (id, user_id, fingerprint, first_seen_at, last_seen_at)

-- Email and Password Reset
email_verification_tokens (id, user_id, token, expires_at, used)
password_reset_tokens (id, user_id, token, expires_at, used)

-- Referrals
invitations (id, code, inviter_id, invitee_id, created_at, accepted_at)
```

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - Session logout
- `POST /auth/logout-all` - All sessions logout

### 2FA
- `POST /auth/2fa/setup` - Setup 2FA
- `POST /auth/2fa/verify` - Verify 2FA

### Password Management
- `POST /auth/password-reset/request` - Request reset
- `POST /auth/password-reset/confirm` - Confirm reset

### Email Verification
- `POST /auth/email/verify/request` - Request verification
- `POST /auth/email/verify/confirm` - Confirm verification

### Admin
- `GET /admin/ping` - Admin health check
- `POST /admin/users/:id/sessions/revoke` - Revoke user sessions

### Security
- `GET /auth/keys/jwks.json` - Public key set
- `POST /auth/keys/rotate` - Rotate signing keys

## Deployment Architecture

### Production Environment
```
Internet → Cloud Load Balancer → Nginx → Application Stack
                                    ↓
                              SSL Termination
                              Rate Limiting
                              Static File Serving
```

### Monitoring Stack
- **Prometheus**: Metrics collection
- **Grafana**: Visualization and alerting
- **Custom Metrics**: Auth success/failure rates
- **Health Checks**: All services monitored

## Development Workflow

### Local Development
```bash
# Start all services
docker-compose up -d

# Run tests
docker-compose exec backend cargo test
docker-compose exec frontend npm test

# View logs
docker-compose logs -f [service]
```

### CI/CD Pipeline
1. **Code Push** → GitHub
2. **Automated Tests** → Backend + Frontend
3. **Security Scan** → Dependency vulnerabilities
4. **Build Images** → Docker containers
5. **Deploy** → Production server

## Security Checklist

- [x] HTTPS enforced with valid certificates
- [x] Password hashing with Argon2
- [x] JWT token rotation
- [x] Rate limiting on auth endpoints
- [x] Input validation and sanitization
- [x] SQL injection protection
- [x] XSS protection headers
- [x] CSRF protection
- [x] Secure session management
- [x] 2FA implementation
- [x] Audit logging
- [x] Device fingerprinting
- [x] RBAC implementation
- [x] Admin session revocation
- [x] Email verification flow
- [x] Password reset flow

## Performance Considerations

- **Database Connection Pooling**: Optimized for concurrent requests
- **Redis Caching**: Session and frequently accessed data
- **Async Processing**: Non-blocking I/O operations
- **Container Resource Limits**: Memory and CPU constraints
- **CDN Ready**: Static assets optimized for delivery

## Scalability Features

- **Horizontal Scaling**: Stateless backend services
- **Database Sharding**: Ready for multi-instance setup
- **Load Balancing**: Nginx upstream configuration
- **Microservice Architecture**: Independent service scaling
- **Message Queues**: Redis-based job processing