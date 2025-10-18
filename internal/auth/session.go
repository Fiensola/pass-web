package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const SessionTTL = 10 * time.Minute

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]time.Time
}

func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]time.Time),
	}

	go sm.CleanupExpired()

	return sm
}

func (sm *SessionManager) CreateSession() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for {
		id := generateSessID()
		if _, exists := sm.sessions[id]; !exists {
			sm.sessions[id] = time.Now().Add(SessionTTL)
			return id
		}
	} // for collision
}

func (sm *SessionManager) IsValid(sessID string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	expireTime, exists := sm.sessions[sessID]
	if !exists {
		return false
	}

	return time.Now().Before(expireTime)
}

func (sm *SessionManager) DeleteSession(sessID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessID)
}

func (sm *SessionManager) CleanupExpired() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, expire := range sm.sessions {
			if now.After(expire) {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

func generateSessID() string {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}

	return hex.EncodeToString(bytes)
}
