# RESTful Auth Service
Access control solution backend service to provide authorization and authentication to your RESTful endpoints. 
Useful when you want to host a solution to handle an access verification before they reach your features or other microservices.

![project_logo.png](project_logo.png)

## Tech Stack
This project was developed using modern and mature technologies like:
- Maven 3.9 (Building Tool)
- Java JDK 25
- Spring Boot 4
- Spring Security
- Spring JPA
- PostgreSQL (Relational Database)
- Redis (for tokens invalidation when users logs out)
- Docker for containerization

## Prerequisites
As this project aims for those who wants to self-host an access control solution you have to have these tools installed
beforehand if you want to do some customization, make maintenance or even submit a contribution:
- Docker
- JDK 25
- Maven 3.9.11
- PostgreSQL 18.1
- Redis 8.2.4

## Features
- Register User
- Login
- Logout
- JWT (Tokens and Refresh Tokens)
- Role-Based Authorization
- PostgreSQL Database Integration (JPA, Hibernate)
- Password Recovery Flow
- Send e-mail verification
- 2FA with OTP code to e-mail

### Stateless
The project uses JSON Web Token (JWT) and the authentication/authorization are stateless. 
When the user makes login the response body brings a ```token``` and ```refreshToken```.

## Usage

### Environment Variables
You might want to configure the environment variables accordingly to your case. Please make sure to export these variables

| **Variable Name**                 | **Description**                                                                                                                                   | **Default Value** |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|
| APP_TIMEZONE                      | Defines the app timezone. It usually necessary when persisting data.                                                                              | America/Sao_Paulo |
| POSTGRESQL_DB_URL                 | PostgreSQL database URL server (jdbc:postgresql://localhost:5432/bnauth). If not informed, then system will use the container address 'pgserver'. | pgserver          |
| POSTGRESQL_DB_USER                | PostgreSQL database user.                                                                                                                         | bn                |
| POSTGRESQL_DB_PASSWORD            | PostgreSQL database password.                                                                                                                     | secret123         |
| SHOW_SQL                          | Set to true if you want to see SQL commands printed it out in logs                                                                                | false             |
| REDIS_HOST                        | Redis database URL server. If not informed, then system will use the container address 'redis'.                                                   | redis             |
| REDIS_PORT                        | Redis database port.                                                                                                                              | 6379              |
| JWT_SECRET                        | Secret key to sign the brand new generated JWT tokens.                                                                                            | mySecretKey       |
| JWT_ACCESS_TOKEN_EXPIRATION_TIME  | Configuration to set the token expiration time in milliseconds.                                                                                   | 900000            |
| JWT_REFRESH_TOKEN_EXPIRATION_TIME | Configuration to set the refresh token expiration time in milliseconds.                                                                           | 604800000         |

### Run in your hosted environment
If you have Docker and Docker Compose installed, simply run 
```docker-compose up -d``` in the project folder so you can have the API up and running. 

## Installation

## Routes
