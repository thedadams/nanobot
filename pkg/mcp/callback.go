package mcp

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"sync"
)

type AuthURLHandler interface {
	HandleAuthURL(context.Context, string, string) error
}

type CallbackServer interface {
	http.Handler
	AuthURLHandler
	NewState() (string, <-chan string, error)
}

type callbackServer struct {
	AuthURLHandler
	lock  *sync.Mutex
	state map[string]chan<- string
}

func NewCallbackServer(authURLHandler AuthURLHandler) CallbackServer {
	return &callbackServer{
		lock:           new(sync.Mutex),
		state:          make(map[string]chan<- string),
		AuthURLHandler: authURLHandler,
	}
}

func (s *callbackServer) NewState() (string, <-chan string, error) {
	state := strings.ToLower(rand.Text())
	ch := make(chan string)
	s.lock.Lock()
	s.state[state] = ch
	s.lock.Unlock()
	return state, ch, nil
}

func (s *callbackServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")

	s.lock.Lock()
	ch, ok := s.state[state]
	delete(s.state, state)
	s.lock.Unlock()

	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	ch <- r.URL.Query().Get("code")
	close(ch)

	_, _ = w.Write([]byte("Success!!"))
}
