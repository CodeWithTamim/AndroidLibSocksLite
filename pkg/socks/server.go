package socks

import (
	"AndroidLibSocksLite/pkg/logging"
	"encoding/json"
	"fmt"
	"github.com/armon/go-socks5"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

const coreVersion = "1.0.1"

// CheckCoreVersion returns the current version of the core.
func CheckCoreVersion() string {
	return coreVersion
}

// User represents the user credentials for SOCKS5 authentication.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int    `json:"port"`
}

var (
	isCoreRunning   bool
	servers         = make(map[int]*socks5.Server)
	listeners       = make(map[int]net.Listener)
	userCredentials = make(map[int]User)
	mutex           sync.RWMutex
)

// StartSocksServers initializes multiple SOCKS5 servers.
func StartSocksServers(host string, jsonData string) error {
	mutex.Lock()
	defer mutex.Unlock()

	if isCoreRunning {
		logging.LogInfo("Core is already running.")
		return fmt.Errorf("core is already running")
	}

	var users []User
	if err := json.Unmarshal([]byte(jsonData), &users); err != nil {
		logging.LogError(fmt.Sprintf("Error parsing JSON data: %v", err))
		return fmt.Errorf("error parsing JSON data: %v", err)
	}

	for _, user := range users {
		if err := startServerForUser(host, user); err != nil {
			logging.LogError(err.Error())
			continue
		}
	}

	isCoreRunning = true
	logging.LogInfo("Core started successfully.")

	go handleShutdown()

	return nil
}

// startServerForUser starts a SOCKS5 server for a given user.
func startServerForUser(host string, user User) error {
	credMap := socks5.StaticCredentials{user.Username: user.Password}
	auth := socks5.UserPassAuthenticator{Credentials: credMap}
	conf := &socks5.Config{AuthMethods: []socks5.Authenticator{auth}}

	server, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("error creating SOCKS5 server for user %s: %v", user.Username, err)
	}

	addr := fmt.Sprintf("%s:%d", host, user.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("error creating listener on %s: %v", addr, err)
	}

	servers[user.Port] = server
	listeners[user.Port] = listener
	userCredentials[user.Port] = user

	go serveConnections(server, listener, user.Username)

	logging.LogInfo(fmt.Sprintf("User %s server started on %s", user.Username, addr))
	return nil
}

// serveConnections accepts connections and serves them with the SOCKS5 server.
func serveConnections(s *socks5.Server, l net.Listener, username string) {
	for {
		conn, err := l.Accept()
		if err != nil {
			logging.LogError(fmt.Sprintf("Error accepting connection: %v", err))
			return
		}

		wrappedConn := &loggingConn{Conn: conn, username: username}
		go s.ServeConn(wrappedConn)
	}
}

// handleShutdown listens for termination signals and shuts down servers gracefully.
func handleShutdown() {
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
	<-shutdownChan
	logging.LogInfo("Shutting down servers...")
	if err := Shutdown(); err != nil {
		logging.LogError(fmt.Sprintf("Error during shutdown: %v", err))
	}
}

// Shutdown gracefully shuts down all SOCKS5 servers.
func Shutdown() error {
	mutex.Lock()
	defer mutex.Unlock()

	for port, listener := range listeners {
		listener.Close()
		delete(servers, port)
		delete(listeners, port)
	}
	isCoreRunning = false
	logging.LogInfo("All servers shut down.")
	return nil
}

// loggingConn is a wrapper around net.Conn that logs each request's destination address.
type loggingConn struct {
	net.Conn
	username string
}

// Write logs the destination address before forwarding the request.
func (c *loggingConn) Write(b []byte) (int, error) {
	destAddr := c.RemoteAddr().String()
	logging.LogInfo(fmt.Sprintf("User %s connected to %s", c.username, destAddr))
	return c.Conn.Write(b)
}

// IsCoreRunning returns whether the core is running.
func IsCoreRunning() bool {
	mutex.RLock()
	defer mutex.RUnlock()
	return isCoreRunning
}

// ActiveServers returns the list of active servers.
func ActiveServers() map[int]*socks5.Server {
	mutex.RLock()
	defer mutex.RUnlock()
	return servers
}
