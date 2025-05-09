# 🔐 Auth API (Go)

A simple RESTful authentication API written in Go with user registration, login (JWT), and secure profile access.

---

## 📦 Features

- 📝 Register new users
- 🔑 Login with username and password
- 🛡 JWT-based authentication
- 🗂 JSON-based user storage (no database required)
- ⚙️ Clean and minimal Go codebase

---

## ▶️ Endpoints

### 📌 POST `/register`

Registers a new user.

**Request Body:**
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

---

### 📌 POST `/login`

Authenticates a user and returns a JWT token.

**Request Body:**
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

---

### 📌 GET `/me`

Returns current user info based on JWT.

**Header:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{"username":"valera"}
```

---

## 🛠 How to Run

```bash
# 1. Set JWT secret
export JWT_SECRET="mysecretkey"

# 2. Run server
go run main.go
```

---

## 🌟 Author

> A student on the path to Yandex. One step at a time.

GitHub: [CraftStick](https://github.com/CraftStick)
