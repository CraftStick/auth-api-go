package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

const (
	usersFile     = "users.json"
	jwtSecretEnv  = "JWT_SECRET"
	tokenLifetime = time.Hour * 2
)

type User struct {
	Username string    `json:"username"`
	Password string    `json:"password"` // hashed
	Created  time.Time `json:"created"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var jwtSecret []byte

func loadUsers() ([]User, error) {
	if _, err := os.Stat(usersFile); errors.Is(err, os.ErrNotExist) {
		return []User{}, nil
	}
	data, err := ioutil.ReadFile(usersFile)
	if err != nil {
		return nil, err
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(usersFile, data, 0644)
}

func findUser(users []User, username string) *User {
	for i := range users {
		if users[i].Username == username {
			return &users[i]
		}
	}
	return nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	users, err := loadUsers()
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	if findUser(users, creds.Username) != nil {
		http.Error(w, "User exists", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	users = append(users, User{
		Username: creds.Username,
		Password: string(hash),
		Created:  time.Now(),
	})
	if err := saveUsers(users); err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, `{"message":"User registered"}`)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	users, _ := loadUsers()
	user := findUser(users, creds.Username)
	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   user.Username,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenLifetime)),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":"%s"}`, tokenString)
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(auth, "Bearer ")
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	username := claims["sub"].(string)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"username":"%s"}`, username)
}

func main() {
	secret := os.Getenv(jwtSecretEnv)
	if secret == "" {
		log.Fatalf("❌ Set JWT_SECRET env variable first!")
	}
	jwtSecret = []byte(secret)

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/me", meHandler)

	fmt.Println("🚀 Auth API running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
