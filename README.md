# SecureAuthPOC API

## Overview
SecureAuthPOC is a production-ready, security-focused authentication API built with .NET 8. It demonstrates industry-standard security practices for user authentication, including JWT-based authentication, rate limiting, password encryption, and compliance with major regulations (GDPR, CCPA, PCI DSS). The API provides secure user registration, login, token management, and comprehensive security features to protect against common web application vulnerabilities.

## Technologies Used
- **.NET 8** - Modern, high-performance framework
- **ASP.NET Core** - Web API framework
- **JWT (JSON Web Tokens)** - Secure authentication tokens
- **BCrypt.Net-Next** - Password hashing with adaptive work factor
- **Swagger/OpenAPI** - API documentation
- **Docker** - Containerization
- **In-Memory Database** - Lightweight data storage for POC
- **Token Bucket Algorithm** - Rate limiting implementation

## Prerequisites
Before running this project, ensure you have the following installed:

### Required Software
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)
- [Git](https://git-scm.com/) (optional)
- [Docker](https://www.docker.com/products/docker-desktop) (for containerization)
- [Postman](https://www.postman.com/) or [curl](https://curl.se/) (for API testing)

### Required Knowledge
- Basic understanding of REST APIs
- Familiarity with JWT authentication
- Knowledge of security best practices
- Understanding of Docker basics (for containerized deployment)

## Running Locally on Kestrel Server

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-organization/SecureAuthPOC.git
cd SecureAuthPOC
```

### Step 2: Restore Dependencies
```bash
dotnet restore
```

### Step 3: Build the Solution
```bash
dotnet build
```

### Step 4: Configure Application Settings
Update `appsettings.json` with your configuration:
```json
{
  "Jwt": {
    "SecretKey": "YourSuperSecureSecretKeyWithAtLeast32CharactersLong!",
    "Issuer": "SecureAuthPOC",
    "Audience": "SecureAuthPOC-Client",
    "AccessTokenExpiryMinutes": 15,
    "RefreshTokenExpiryDays": 7
  },
  "RateLimiting": {
    "RequestsPerMinute": 5,
    "BurstLimit": 10,
    "BlockDurationMinutes": 15,
    "Enabled": true,
    "ExcludePaths": [ "/health", "/swagger" ]
  }
}
```

### Step 5: Run the Application
```bash
# Development environment
dotnet run --environment=Development

# Production environment
dotnet run --environment=Production

# With specific ports
dotnet run --urls "https://localhost:5001;http://localhost:5000"
```

### Step 6: Verify Installation
```bash
curl -X GET https://localhost:5001/health
```

## Running with Docker

### Option 1: Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-organization/SecureAuthPOC.git
cd SecureAuthPOC

# Build and run with Docker Compose
docker-compose up --build
```

### Option 2: Using Docker CLI

```bash
# Build the Docker image
docker build -t secureauthpoc .

# Run the container
docker run -d -p 8080:80 -p 8081:443 \
  -e Jwt__SecretKey="YourSuperSecureSecretKeyHere" \
  -e ASPNETCORE_ENVIRONMENT=Production \
  --name secureauth-api \
  secureauthpoc
```

### Option 3: Using Docker Compose with Environment Variables
Create a `.env` file:
```env
JWT_SECRET_KEY=YourSuperSecureSecretKeyWithAtLeast32CharactersLong!
ASPNETCORE_ENVIRONMENT=Production
```

Then run:
```bash
docker-compose --env-file .env up --build
```

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Authentication Required |
|--------|----------|-------------|-------------------------|
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | User login | No |
| POST | `/api/auth/refresh` | Refresh access token | No |
| POST | `/api/auth/logout` | User logout | Yes |
| GET | `/api/auth/password-strength` | Check password strength | No |
| POST | `/api/auth/generate-password` | Generate secure password | No |

### System Endpoints

| Method | Endpoint | Description | Rate Limited |
|--------|----------|-------------|--------------|
| GET | `/health` | Health check endpoint | No |
| GET | `/` or `/swagger` | API documentation (Swagger UI) | No |
| GET | `/test-rate-limit` | Test rate limiting | Yes |

### Request Examples

**Register User:**
```bash
curl -X POST https://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "secureuser",
    "password": "SecurePass123!@#",
    "confirmPassword": "SecurePass123!@#",
    "acceptTerms": true,
    "marketingOptIn": false
  }'
```

**Login User:**
```bash
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!@#"
  }'
```

## Key Features Implemented

### 1. Authentication & Authorization
- **JWT-based authentication** with short-lived access tokens (15 minutes)
- **Refresh token rotation** for secure session management
- **Account lockout** after 5 failed login attempts
- **Two-factor authentication** ready (TOTP implementation available)

### 2. Password Security
- **BCrypt password hashing** with unique salts per user
- **Password strength validation** (12+ characters, mixed case, numbers, special characters)
- **Secure password generator** for users
- **Timing attack prevention** in password verification

### 3. Rate Limiting & Protection
- **Token bucket algorithm** implementation (5 requests per minute default)
- **IP-based blocking** after repeated violations
- **Configurable limits** via appsettings.json
- **Path-based exclusions** for health checks and documentation

### 4. Security Headers & Policies
- **Content Security Policy (CSP)** to prevent XSS attacks
- **X-Frame-Options: DENY** to prevent clickjacking
- **X-Content-Type-Options: nosniff** to prevent MIME type sniffing
- **X-XSS-Protection** for legacy browser support
- **Strict-Transport-Security** for HTTPS enforcement

### 5. Input Validation & Sanitization
- **Model validation** with data annotations
- **Regular expression validation** for password complexity
- **Business logic validation** for critical operations
- **SQL injection prevention** through parameterized queries
- **XSS prevention** through output encoding

### 6. Audit Logging & Monitoring
- **Comprehensive audit logging** for all authentication events
- **Failed attempt tracking** with IP addresses and timestamps
- **Security event monitoring** for suspicious activities
- **GDPR-compliant logging** without storing sensitive data

### 7. Compliance Features
- **GDPR compliance** with user consent tracking
- **CCPA compliance** with opt-out mechanisms
- **PCI DSS considerations** for sensitive data handling
- **Data minimization** principles applied
- **Privacy by design** implementation

### 8. Error Handling
- **Generic error messages** to prevent information disclosure
- **Structured error responses** for API clients
- **Logging without sensitive data** exposure
- **Graceful degradation** under high load

### 9. Configuration & Deployment
- **Environment-specific configurations** (Development, Production)
- **Docker support** for containerized deployment
- **Health check endpoints** for monitoring
- **Swagger documentation** with security schemes

### 10. Performance & Scalability
- **In-memory database** for POC (easily upgradable to production DB)
- **Asynchronous processing** for I/O operations
- **Rate limiting scalability** with configurable parameters
- **Clean architecture** for maintainability

## Testing the API

### Health Check
```bash
curl -X GET https://localhost:5001/health
```

### Generate Secure Password
```bash
curl -X POST https://localhost:5001/api/auth/generate-password
```

### Test Rate Limiting
```bash
# This should return 429 after 5 requests
for i in {1..10}; do
  curl -X POST https://localhost:5001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}'
  echo ""
done
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `Jwt__SecretKey` | JWT signing key | - | Yes |
| `Jwt__Issuer` | JWT issuer | SecureAuthPOC | No |
| `Jwt__Audience` | JWT audience | SecureAuthPOC-Client | No |
| `ASPNETCORE_ENVIRONMENT` | Runtime environment | Production | No |
| `RateLimiting__Enabled` | Enable/disable rate limiting | true | No |

## Docker Compose Configuration

```yaml
version: '3.8'

services:
  secureauth-api:
    build: .
    ports:
      - "8080:80"
      - "8081:443"
    environment:
      - Jwt__SecretKey=${JWT_SECRET_KEY}
      - ASPNETCORE_ENVIRONMENT=${ASPNETCORE_ENVIRONMENT}
      - RateLimiting__Enabled=true
      - RateLimiting__RequestsPerMinute=5
    restart: unless-stopped
    networks:
      - secureauth-network

networks:
  secureauth-network:
    driver: bridge
```

## Project Structure

```
SecureAuthPOC/
├── Controllers/
│   └── AuthController.cs          # Authentication endpoints
├── Middleware/
│   ├── RateLimitingMiddleware.cs  # Rate limiting implementation
│   ├── SecurityHeadersMiddleware.cs # Security headers
│   └── JwtMiddleware.cs           # JWT validation
├── Models/
│   ├── User.cs                    # User entity
│   ├── AuthRequest.cs             # Authentication DTOs
│   └── AuthResponse.cs            # Response DTOs
├── Services/
│   ├── IAuthService.cs            # Authentication service interface
│   ├── AuthService.cs             # Authentication service implementation
│   ├── ITokenService.cs           # Token service interface
│   └── TokenService.cs            # Token service implementation
├── Data/
│   └── InMemoryDbContext.cs       # In-memory database context
├── Filters/
│   └── AuditLogFilter.cs          # Audit logging filter
├── Program.cs                     # Application entry point
├── appsettings.json               # Configuration
└── Dockerfile                     # Docker configuration
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, questions, or feature requests:
- Open an issue in the GitHub repository
- Contact the development team at dev@example.com
- Check the [Wiki](https://github.com/your-organization/SecureAuthPOC/wiki) for documentation

## Acknowledgments

- OWASP for security guidelines and best practices
- NIST for security standards and frameworks
- .NET community for excellent documentation and support
- Security researchers for identifying and reporting vulnerabilities

---

**Last Updated**: January 2024  
**Version**: 1.0.0  
**Status**: Production Ready
