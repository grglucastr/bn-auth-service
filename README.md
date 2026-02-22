# RESTful Auth Service
Access control solution backend service to provide authorization and authentication to your RESTful endpoints. 
Useful when you want to host a solution to handle an access verification before they reach your features or other microservices.

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
- E-mail simulation

### Stateless
The project uses JSON Web Token (JWT) and the authentication/authorization are stateless. 
When the user makes login the response body brings a ```token``` and ```refreshToken```.

## Usage

### Run in your hosted environment
If you have Docker and Docker Compose installed, simply run 
```docker-compose up -d``` in the project folder so you can have the API up and running. 

## Installation

## Routes
