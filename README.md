# Auth API (Go)

[English](README.md) · [Русский](README.ru.md)

A simple RESTful authentication API written in Go, with user registration, login (JWT) and secure profile access.

## Features

- Register new users
- Login with username and password
- JWT-based authentication
- JSON-based user storage (no database required)
- Clean and minimal Go codebase

## Endpoints

### POST `/register`

Registers a new user.

**Request body:**

```json
{
  "username": "valera",
  "password": "12345"
}
```

**Response:**

```json
{"message":"User registered"}
```

### POST `/login`

Authenticates a user and returns a JWT token.

**Request body:**

```json
{
  "username": "valera",
  "password": "12345"
}
```

**Response:**

```json
{"token":"<JWT_TOKEN>"}
```

### GET `/me`

Returns current user info based on the JWT.

**Header:**

```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**

```json
{"username":"valera"}
```

## Getting Started

```bash
export JWT_SECRET="mysecretkey"
go run main.go
```
