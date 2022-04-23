package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"strconv"
	"strings"
	"time"
)

const ServerKey = "#sdf674%3255$"

func generateToken(mapClaims jwt.MapClaims, key string) string {
	tokenOrigin := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	token := ""
	token, _ = tokenOrigin.SignedString([]byte(key))
	return token
}

func parseToken(tokenString string, key string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"title":   "你好，世界 : )",
			"message": "如果你看到这条消息，说明本接口正常运行中",
			"notice":  "这个接口调用不需要带任何参数，如果需要调用其它接口，请使用serverKey",
			"version": "2.0.0",
		})
	})
	r.POST("/users", getUser)
	r.POST("/register", addUser)
	r.POST("/login", login)
	r.POST("/message/send", sendMessage)
	r.POST("/message/search", searchMessage)
	r.POST("/message/all", getAllMessage)
	r.POST("/user/edit", editUser)
	err := r.Run(":14514")
	if err != nil {
		return
	}
}

func getUser(c *gin.Context) {
	id := c.DefaultPostForm("id", "")
	serverKey := c.DefaultPostForm("server_key", "")
	print(serverKey)
	var user User
	found := false
	for _, u := range users {
		if strings.EqualFold(id, strconv.Itoa(u.ID)) {
			user = u
			found = true
			break
		}
	}
	if len(serverKey) == 0 || !strings.EqualFold(serverKey, ServerKey) {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	} else {
		if !found {
			c.JSON(404, gin.H{
				"status":  404,
				"message": "User not found",
			})
			return
		} else {
			c.JSON(200, gin.H{
				"status":  200,
				"message": "OK",
				"data":    user,
			})
			return
		}
	}
}

func addUser(c *gin.Context) {
	username := c.DefaultPostForm("username", "")
	password := c.DefaultPostForm("password", "")
	email := c.DefaultPostForm("email", "")
	serverKey := c.DefaultPostForm("server_key", "")
	if serverKey != ServerKey {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized"})
		return
	}
	if len(serverKey) == 0 {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized"})
		return
	}
	if username != "" {
		if serverKey != ServerKey {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized"})
			return
		}
		if len(serverKey) == 0 {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized"})
			return
		}
		for _, u := range users {
			if strings.EqualFold(username, u.Username) {
				c.JSON(409, gin.H{
					"status":  409,
					"message": "User already exists"})
				return
			}
		}
		now := time.Now()
		u := User{ID: len(users) + 1, Username: username, Password: password, Email: email, RegisterTime: now.Format("2006-01-02 15:04:05")}
		users = append(users, u)
		c.JSON(200, gin.H{"status": 200, "success": "user added successfully"})
	}
	if username == "" || password == "" {
		c.JSON(404, gin.H{"error": "username or password is empty"})
	}
}

func editUser(c *gin.Context) {
	username := c.DefaultPostForm("username", "")
	password := c.DefaultPostForm("password", "")
	email := c.DefaultPostForm("email", "")
	serverKey := c.DefaultPostForm("server_key", "")
	accewssToken := c.DefaultPostForm("access_token", "")
	if serverKey != ServerKey {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized"})
		return
	} else {
		if accewssToken != "" {
			claims, err := parseToken(accewssToken, ServerKey)
			if err != nil {
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Unauthorized"})
				return
			}
			userID := int(claims["user_id"].(float64))
			for ID, u := range users {
				if u.ID == userID {
					if username != "" {
						users[ID].Username = username
					}
					if password != "" {
						u.Password = password
					}
					if email != "" {
						u.Email = email
					}
					c.JSON(200, gin.H{"status": 200, "success": "user edited successfully"})
					return
				}
			}
		}
	}

}

func login(c *gin.Context) {
	username := c.DefaultPostForm("username", "")
	password := c.DefaultPostForm("password", "")
	if username != "" {
		for id, u := range users {
			if strings.EqualFold(username, u.Username) {
				if strings.EqualFold(password, u.Password) {
					now := time.Now()
					users[id].LastLogin = now.Format("2006-01-02 15:04:05")
					c.JSON(200, gin.H{
						"status":       200,
						"success":      "login successfully",
						"access_token": generateToken(jwt.MapClaims{"id": u.ID}, ServerKey)})
					return
				}
			}
		}
		c.JSON(404, gin.H{"status": 404, "error": "username or password is error"})
	}
	if username == "" || password == "" {
		c.JSON(404, gin.H{"status": 404, "error": "username or password is error"})
	}
}

func getAllMessage(c *gin.Context) {
	ServerKey := c.DefaultPostForm("server_key", "")
	if ServerKey != ServerKey {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized"})
		return
	} else {
		c.JSON(200, gin.H{"status": 200, "message": "get all message successfully", "data": messages})
	}
}

func searchMessage(c *gin.Context) {
	uid := c.DefaultPostForm("uid", "")
	serverKey := c.DefaultPostForm("server_key", "")
	found := false
	if len(serverKey) == 0 || !strings.EqualFold(serverKey, ServerKey) {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	} else {
		if len(uid) == 0 {
			c.JSON(404, gin.H{
				"status":  404,
				"message": "uid is empty",
			})
			return
		}
		var message []Message
		for _, m := range messages {
			if strings.EqualFold(uid, strconv.Itoa(m.UserID)) {
				message = append(message, m)
				found = true
			}
		}
		if !found {
			c.JSON(404, gin.H{
				"status":  404,
				"message": "Message not found",
			})
			return
		} else {
			c.JSON(200, gin.H{
				"status":  200,
				"message": "OK",
				"data":    message,
			})
			return
		}
	}
}

func sendMessage(c *gin.Context) {
	accessToken := c.DefaultPostForm("access_token", "")
	message := c.DefaultPostForm("message", "")
	serverKey := c.DefaultPostForm("server_key", "")
	if len(serverKey) == 0 || !strings.EqualFold(serverKey, ServerKey) {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Server_key is error. Unauthorized.",
		})
		return
	} else {
		if accessToken != "" {
			claims, err := parseToken(accessToken, ServerKey)
			if err != nil {
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Access_token is error. Unauthorized.",
				})
				return
			}
			if message != "" {
				now := time.Now()
				userId := int(claims["id"].(float64))
				m := Message{ID: len(messages) + 1, Message: message, UserID: userId, Time: now.Format("2006/01/02 15:04:05")}
				messages = append(messages, m)
				c.JSON(200, gin.H{
					"status":  200,
					"message": "message sent successfully",
					"userID":  userId,
				})
				return
			}
		}
	}
}

var users = []User{
	{ID: 1, Username: "admin", Password: "admin", Email: "admin@wildbox.cn", LastLogin: "2006-01-02 15:04:05", RegisterTime: "2006-01-02 15:04:05"},
	{ID: 2, Username: "user", Password: "user", Email: "user@wildbox.cn", LastLogin: "2006-01-02 15:04:05", RegisterTime: "2006-01-02 15:04:05"},
	{ID: 3, Username: "test", Password: "test", Email: "test@wildbox.cn", LastLogin: "2006-01-02 15:04:05", RegisterTime: "2006-01-02 15:04:05"},
}

var messages []Message

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Email        string `json:"email"`
	LastLogin    string `json:"last_login"`
	RegisterTime string `json:"register_time"`
}

type Message struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
	UserID  int    `json:"user_id"`
	Time    string `json:"time"`
}
