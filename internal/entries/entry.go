package entries

import (
	"time"

	"github.com/google/uuid"
)

type Entry struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	URL       string    `json:"url"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
}

func NewID() string {
	return uuid.New().String()
}
