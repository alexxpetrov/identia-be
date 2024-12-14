# Identia: A Robust Authentication Backend Solution

Identia is a powerful authentication backend built using Go (Golang) designed to support both traditional and biometric authentication workflows. It provides an HTTP/2 server using gRPC, ensuring secure and efficient communication. Identia is tailored for modern applications requiring robust authentication strategies, including regular registration/login/logout mechanisms and WebAuthn biometric authentication.

## Key Features

- **Support for Traditional and WebAuthn Authentication**: 
  - Traditional workflows include email/password registration and login.
  - WebAuthn enables biometric authentication for enhanced security.
- **JWT-Based Authentication**:
  - Access tokens issued with a 1-hour validity.
  - Refresh tokens valid for up to 7 days.
  - A secure mechanism for refreshing access tokens via a dedicated handler.
- **PostgreSQL with Data Sharding**:
  - Data sharding optimizes read/write operations, ensuring high performance under heavy loads.
  - PostgreSQL is ACID-compliant, guaranteeing data consistency, reliability, and fault tolerance.
  - The use of a relational database enables structured queries and schema enforcement for robust data management.
- **Built with gRPC**:
  - Efficient HTTP/2 communication ensures low latency and high throughput.
  - Strongly-typed API definitions improve developer productivity and integration.

## Why PostgreSQL?

PostgreSQL was chosen as the database solution for Identia because of its:

1. **ACID Compliance**:
   - Ensures data consistency and durability, even in the event of crashes or errors.
   - Guarantees reliable transaction management, critical for authentication systems.
2. **Advanced Features**:
   - Native support for JSON/JSONB allows hybrid relational and non-relational data handling.
   - Indexing capabilities enhance query performance for both structured and semi-structured data.
3. **Data Sharding**:
   - Horizontal partitioning distributes data across multiple shards, optimizing performance for high-volume read and write operations.
   - This ensures scalability without sacrificing the benefits of a relational database.
4. **Robust Security**:
   - Role-based access control (RBAC) and advanced authentication methods align with Identia’s emphasis on security.
5. **Open Source and Community Support**:
   - A vast community and ecosystem ensure reliability, extensibility, and long-term support.

## System Overview

### Authentication Workflow

1. **Registration**: Users can register using email/password or by setting up a biometric key through WebAuthn.
2. **Login**: Supports both traditional email/password logins and biometric logins via WebAuthn.
3. **Token Management**:
   - Access tokens are used for session management, with a lifespan of 1 hour.
   - Refresh tokens allow seamless session renewal, valid for up to 7 days.
   - Refresh token logic is handled on the client side with an endpoint for token renewal.
4. **Logout**: Safely invalidates tokens to ensure session termination.

### Technology Stack

- **Backend**: Golang
- **Database**: PostgreSQL with data sharding
- **Protocol**: HTTP/2 with gRPC
- **Authentication**: JWT (Access + Refresh Tokens)

## Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/alexxpetrov/identia-be
   cd identia-be
   ```
2. Install dependencies:
   ```bash
   go mod tidy
   ```
3. Configure the database:
   - Ensure you have PostgreSQL installed and running.
   - Configure the database connection string in the environment variables.
4. Start the server:
   ```bash
   cd cmd
   go run main.go
   ```

