# Iamsspm07 FastAPI Application

## Overview
Iamsspm07 is a production-ready FastAPI application that integrates MySQL for database operations, implements user authentication, and includes utility functions for password hashing and JWT token management.

## Features
- User Registration and Authentication
- Database interactions using SQLAlchemy
- JWT token generation and verification
- Comprehensive logging for debugging and monitoring
- Environment variable management using `dotenv`

## File Structure
- `config.py`: Handles application settings and environment variables.
- `crud.py`: Contains CRUD operations for user management.
- `database.py`: Configures the database connection and session management.
- `main.py`: Initializes the FastAPI application and sets up routes and middleware.
- `models.py`: Defines SQLAlchemy models for database tables.
- `routes.py`: Defines the API endpoints and their corresponding handlers.
- `schemas.py`: Defines Pydantic models for request and response validation.
- `utils.py`: Contains utility functions for password hashing, validation, and token creation.

## Getting Started
1. Clone the repository.
2. Create a `.env` file with the necessary environment variables.
3. Install the required dependencies using `pip install -r requirements.txt`.
4. Run the application using `uvicorn main:app --reload`.

## Environment Variables
- `DB_USER`: Database username.
- `DB_PASSWORD`: Database password.
- `DB_HOST`: Database host.
- `DB_PORT`: Database port.
- `DB_NAME`: Database name.
- `SECRET_KEY`: Secret key for JWT.
- `ALGORITHM`: Algorithm for JWT.
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Token expiration time in minutes.

## Available API Endpoints
- `POST /register/`: Register a new user.
- `POST /login/`: Authenticate a user.
- `DELETE /delete/`: Delete a user by phone number.

## Logging
The application uses Python's logging module to log information, warnings, errors, and critical errors. Logs are formatted to include timestamps and log levels.

## Dependencies
- `FastAPI`
- `SQLAlchemy`
- `Pydantic`
- `bcrypt`
- `python-dotenv`
- `jose`
