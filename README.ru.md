# Auth API (Go)

[English](README.md) · [Русский](README.ru.md)

Простой RESTful API аутентификации на Go: регистрация пользователей, вход (JWT) и защищённый доступ к профилю.

## Возможности

- Регистрация новых пользователей
- Вход по имени пользователя и паролю
- Аутентификация на основе JWT
- Хранение пользователей в JSON (без базы данных)
- Чистая и минимальная кодовая база на Go

## Эндпоинты

### POST `/register`

Регистрирует нового пользователя.

**Тело запроса:**

```json
{
  "username": "valera",
  "password": "12345"
}
```

**Ответ:**

```json
{"message":"User registered"}
```

### POST `/login`

Проверяет пользователя и возвращает JWT-токен.

**Тело запроса:**

```json
{
  "username": "valera",
  "password": "12345"
}
```

**Ответ:**

```json
{"token":"<JWT_TOKEN>"}
```

### GET `/me`

Возвращает информацию о текущем пользователе по JWT.

**Заголовок:**

```
Authorization: Bearer <JWT_TOKEN>
```

**Ответ:**

```json
{"username":"valera"}
```

## Начало работы

```bash
export JWT_SECRET="mysecretkey"
go run main.go
```
