# Auth Microservice

A minimal, production-ready authentication service built with Go and AWS Cognito. Designed for SaaS applications that need a reliable, secure, and easy-to-deploy authentication solution.

## Overview

This service provides a complete authentication system that:
- Uses AWS Cognito as the identity provider
- Stores tokens in secure httpOnly cookies
- Exposes a simple REST API for authentication operations
- Integrates seamlessly with Next.js frontends and Go business services
- Follows security best practices for web authentication

### Key Features

- **User Registration** - Create new user accounts with email verification
- **User Login** - Authenticate users and issue tokens
- **Token Refresh** - Refresh expired access tokens
- **User Logout** - Clear sessions and invalidate tokens
- **Current User** - Retrieve authenticated user information
- **Secure Cookies** - httpOnly, Secure, SameSite=Strict
- **CORS Support** - Configured for cross-origin requests with credentials
- **Production Ready** - Graceful shutdown, configurable timeouts, comprehensive error handling

## Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   Next.js   │─────▶│ Auth Service │─────▶│ AWS Cognito │
│  Frontend   │◀─────│   (Go)       │◀─────│             │
└─────────────┘      └──────────────┘      └─────────────┘
                            │
                            │ JWT Validation
                            ▼
                     ┌──────────────┐
                     │   Business   │
                     │   Services   │
                     │   (Go)       │
                     └──────────────┘
```

### Design Principles

1. **Frontend never talks to Cognito directly** - All auth flows go through this service
2. **httpOnly cookies** - Tokens are secure and inaccessible to JavaScript
3. **Minimal and focused** - Only handles authentication, nothing more
4. **No over-engineering** - Simple, straightforward code
5. **Production ready** - Battle-tested patterns and security practices

## Quick Start

### Prerequisites

- Go 1.25.3 or higher
- AWS Account with Cognito User Pool configured
- AWS credentials configured locally

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd auth-microservice
```

2. Install dependencies:
```bash
go mod download
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your Cognito credentials
```

4. Run the service:
```bash
go run cmd/api/main.go
```

The service will start on `http://localhost:8080`.

## Configuration

Configure the service using environment variables in the `.env` file:

```bash
# Server Configuration
PORT=8080
APP_ENV=local

# AWS Configuration
AWS_REGION=us-east-1
COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
COGNITO_CLIENT_ID=your-client-id
COGNITO_CLIENT_SECRET=your-client-secret

# Cookie Configuration
COOKIE_DOMAIN=
COOKIE_SECURE=false
FRONTEND_URL=http://localhost:3000
```

See [docs/SETUP.md](./docs/SETUP.md) for detailed configuration instructions.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Authenticate a user |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Log out user |
| GET | `/auth/me` | Get current user |

### Example: Register

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "name": "John Doe"
  }'
```

### Example: Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }' \
  -c cookies.txt
```

### Example: Get Current User

```bash
curl http://localhost:8080/auth/me -b cookies.txt
```

See [docs/API.md](./docs/API.md) for complete API documentation.

## Documentation

Comprehensive documentation is available in the `docs/` folder:

- **[API.md](./docs/API.md)** - Complete API endpoint documentation
- **[AUTHENTICATION_FLOW.md](./docs/AUTHENTICATION_FLOW.md)** - Authentication flow diagrams and integration guides
- **[SETUP.md](./docs/SETUP.md)** - Setup and deployment instructions
- **[ARCHITECTURE.md](./docs/ARCHITECTURE.md)** - Architecture, folder structure, and design decisions

## Project Structure

```
auth-microservice/
├── cmd/api/            # Application entry point
├── internal/
│   ├── config/         # Configuration management
│   ├── cognito/        # AWS Cognito client wrapper
│   ├── handlers/       # HTTP request handlers
│   ├── models/         # Request/response models
│   ├── server/         # Server setup and routing
│   └── utils/          # Utilities (cookies, responses)
├── docs/               # Documentation
├── .env                # Environment variables (not in git)
├── go.mod              # Go dependencies
├── Makefile            # Build commands
└── README.md           # This file
```

See [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) for detailed architecture documentation.

## Makefile Commands

```bash
# Build the application
make build

# Run the application
make run

# Run tests
make test

# Clean build artifacts
make clean

# Build and run (all)
make all

# Live reload (requires air)
make watch
```

## Development

### Running Locally

```bash
go run cmd/api/main.go
```

Or use the Makefile:

```bash
make run
```

### Building

```bash
go build -o bin/auth-service ./cmd/api
```

Or use the Makefile:

```bash
make build
```

### Testing

```bash
go test ./...
```

Or use the Makefile:

```bash
make test
```

## Deployment

### Docker

Build and run with Docker:

```bash
docker build -t auth-service .
docker run -p 8080:8080 --env-file .env auth-service
```

### Production Deployment

The service can be deployed to:
- AWS ECS (Elastic Container Service)
- AWS Lambda + API Gateway
- Kubernetes
- EC2 or any VPS

See [docs/SETUP.md](./docs/SETUP.md) for detailed deployment instructions.

## Security

This service follows security best practices:

- **httpOnly Cookies** - Prevents XSS attacks
- **Secure Flag** - Cookies only sent over HTTPS in production
- **SameSite=Strict** - Prevents CSRF attacks
- **CORS with Credentials** - Properly configured for cross-origin requests
- **Input Validation** - All inputs are validated
- **Error Handling** - Errors don't leak sensitive information
- **No Secrets in Code** - All secrets are in environment variables

### Production Checklist

Before deploying to production:

- [ ] Set `COOKIE_SECURE=true`
- [ ] Configure `COOKIE_DOMAIN` to your domain
- [ ] Update `FRONTEND_URL` to your frontend URL
- [ ] Use HTTPS everywhere
- [ ] Use IAM roles instead of access keys
- [ ] Enable CloudWatch logging
- [ ] Set up monitoring and alerts
- [ ] Configure rate limiting
- [ ] Review Cognito password policy
- [ ] Enable MFA in Cognito (optional)

## Integration Examples

### Next.js Server-Side

```typescript
export async function getServerSideProps(context) {
  const cookies = context.req.headers.cookie;

  const res = await fetch('http://auth-service:8080/auth/me', {
    headers: { cookie: cookies },
  });

  if (!res.ok) {
    return { redirect: { destination: '/login', permanent: false } };
  }

  const { user } = await res.json();
  return { props: { user } };
}
```

### Next.js Middleware

```typescript
export async function middleware(request: NextRequest) {
  const res = await fetch('http://auth-service:8080/auth/me', {
    headers: { cookie: request.headers.get('cookie') || '' },
  });

  if (!res.ok) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return NextResponse.next();
}
```

### Go Business Service

```go
// Validate JWT from cookie
accessToken, _ := r.Cookie("access_token")
token, err := jwt.Parse(accessToken.Value, keyFunc)
// Validate and extract user ID
userID := token.Claims.(jwt.MapClaims)["sub"].(string)
```

See [docs/AUTHENTICATION_FLOW.md](./docs/AUTHENTICATION_FLOW.md) for complete integration examples.

## AWS Cognito Setup

Quick setup steps:

1. Create a Cognito User Pool
2. Configure sign-in with email
3. Create an app client with client secret
4. Enable `ALLOW_USER_PASSWORD_AUTH` and `ALLOW_REFRESH_TOKEN_AUTH`
5. Copy User Pool ID, Client ID, and Client Secret to `.env`

See [docs/SETUP.md](./docs/SETUP.md) for detailed AWS Cognito setup instructions.

## Troubleshooting

### Common Issues

**Issue: "Failed to load config"**
- Ensure all required environment variables are set in `.env`

**Issue: "Login failed"**
- Check that the user's email is verified
- Verify the password is correct
- Ensure the user exists in Cognito

**Issue: "Cookies not being set"**
- Check CORS configuration
- Ensure `credentials: 'include'` in fetch requests
- Verify `Access-Control-Allow-Credentials: true` header

See [docs/SETUP.md](./docs/SETUP.md) for more troubleshooting tips.

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues or questions:
- Check the [documentation](./docs/)
- Open an issue on GitHub
- Review AWS Cognito documentation

## Acknowledgments

- Built with Go and the AWS SDK for Go v2
- Uses AWS Cognito for identity management
- Designed for SaaS applications using Next.js and Go microservices
