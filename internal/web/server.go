package web

import (
	"net/http"
	"os"
	"time"

	"github.com/fiensola/pass-web/internal/auth"
	"github.com/fiensola/pass-web/internal/config"
	"github.com/fiensola/pass-web/internal/crypto"
	"github.com/fiensola/pass-web/internal/entries"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var logger *zap.Logger
var sessionManager *auth.SessionManager

func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	sessionManager = auth.NewSessionManager()
}

func StartServer() {
	cfg := config.Load()

	err := os.MkdirAll(cfg.VaultDir, 0700)
	if err != nil {
		logger.Fatal("fail to create vault dir", zap.Error(err))
	}

	r := gin.Default()

	r.StaticFile("/vault/meta.json", "vault/meta.json")
	r.Static("/static", "web")

	r.GET("/", func(c *gin.Context) {
		c.File("web/index.html")
		/*c.JSON(http.StatusOK, gin.H{
			"mess": "test",
		})*/
	})
	r.POST("/api/v1/setup", SetupHandler(cfg.VaultDir))
	r.POST("/api/v1/login", LoginHandler(cfg.VaultDir))
	r.POST("/api/v1/entries/list", AuthRequired(), entriesListHandler(cfg.VaultDir))
	r.POST("/api/v1/entries", AuthRequired(), entriesCreateHandler(cfg.VaultDir))

	port := ":" + cfg.Port
	logger.Info("starting server", zap.String("port", port))

	if err := r.Run(port); err != nil {
		logger.Fatal("faild to start server", zap.Error(err))
	}
}

func SetupHandler(vaultDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		if request.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password required"})
			return
		}

		existingHash, _ := auth.Load(vaultDir)
		if existingHash != "" {
			c.JSON(http.StatusConflict, gin.H{"error": "vault already initialized"})
			return
		}

		hash, err := crypto.HashPassword(request.Password)
		if err != nil {
			logger.Error("fail to hash password", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		if err := auth.Save(vaultDir, hash); err != nil {
			logger.Error("fail to save password", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true})
	}
}

func LoginHandler(vaultDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		isPasswordError, status, message := checkPassword(request.Password, vaultDir)
		if isPasswordError {
			c.JSON(status, gin.H{"error": message})
			return
		}

		sessionID := sessionManager.CreateSession()

		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"session_id": sessionID,
			"expire":     int64(auth.SessionTTL.Seconds()),
		})
	}
}

func entriesListHandler(vaultDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		isPasswordError, status, message := checkPassword(request.Password, vaultDir)
		if isPasswordError {
			c.JSON(status, gin.H{"error": message})
			return
		}

		entries, err := entries.Load(vaultDir, request.Password)
		if err != nil {
			logger.Error("failed to load entries", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load data"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"entries": entries})
	}
}

func entriesCreateHandler(vaultDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Password string `json:"password"`
			Entry    struct {
				Title    string `json:"title"`
				URL      string `json:"url"`
				Username string `json:"username"`
				Password string `json:"password"`
				Notes    string `json:"notes"`
			} `json:"entry"`
		}
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid reqeust"})
			return
		}

		isPasswordError, status, message := checkPassword(request.Password, vaultDir)
		if isPasswordError {
			c.JSON(status, gin.H{"error": message})
			return
		}

		current, err := entries.Load(vaultDir, request.Password)
		if err != nil {
			logger.Error("failed to load entries", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load data"})
			return
		}

		newEntry := entries.Entry{
			ID:        entries.NewID(),
			Title:     request.Entry.Title,
			URL:       request.Entry.URL,
			Username:  request.Entry.Username,
			Password:  request.Entry.Password,
			Notes:     request.Entry.Notes,
			CreatedAt: time.Now(),
		}

		current = append(current, newEntry)

		err = entries.Save(vaultDir, current, request.Password)
		if err != nil {
			logger.Error("failed to save entries", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"success": true, "id": newEntry.ID})
	}
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessID := c.GetHeader("X-Session-ID")
		if sessID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "messing session id"})
			c.Abort()
			return
		}

		if !sessionManager.IsValid(sessID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func checkPassword(password string, vaultDir string) (bool, int, string) {
	hash, err := auth.Load(vaultDir)
	if err != nil || hash == "" {
		return true, http.StatusInternalServerError, "vault error"
	}

	valid, err := crypto.VerifyPassword(password, hash)
	if err != nil || !valid {
		return true, http.StatusUnauthorized, "invalid password"
	}

	return false, 0, ""
}
