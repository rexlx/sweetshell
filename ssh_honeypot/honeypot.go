package sshhoneypot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/rexlx/sweetshell/internal"
	"golang.org/x/crypto/ssh"
)

type SSHHoneypot struct {
	Memory   sync.RWMutex
	Stats    []internal.Stat
	Port     int
	listener net.Listener
	stopChan chan struct{}
}

func NewSSHHoneypot(port int) *SSHHoneypot {
	return &SSHHoneypot{
		Port:     port,
		Stats:    make([]internal.Stat, 0),
		stopChan: make(chan struct{}),
	}
}

func (s *SSHHoneypot) Start() error {
	// we mask our ssh server so attackers dont realize its a honetpot
	// but we dont match out ciphers to that version which doesnt help the fact
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			sessionID := hex.EncodeToString(c.SessionID())
			s.AddStat(internal.Stat{
				TransactionID: sessionID,
				Time:          time.Now(),
				Info:          fmt.Sprintf("Login Attempt from %s", c.RemoteAddr().String()),
				Value:         fmt.Sprintf("user:%s pass:%s", c.User(), string(pass)),
			})

			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	// Generate a temporary host key for the server
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	privateBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return err
	}
	config.AddHostKey(signer)

	// Start listening
	addr := fmt.Sprintf(":%d", s.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = listener

	log.Printf("SSH Honeypot listening on %s", addr)

	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopChan:
					return
				default:
					log.Printf("Error accepting connection: %v", err)
					continue
				}
			}
			go s.handleConnection(conn, config)
		}
	}()

	return nil
}

func (s *SSHHoneypot) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	// Perform the SSH handshake. The PasswordCallback defined above
	// will trigger during this process.
	_, _, _, err := ssh.NewServerConn(conn, config)
	if err != nil {
		// Handshake failure is expected since we reject passwords
		return
	}
}

func (s *SSHHoneypot) Stop() error {
	close(s.stopChan)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SSHHoneypot) ClearData() error {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Stats = []internal.Stat{}
	return nil
}

func (s *SSHHoneypot) AddStat(stat internal.Stat) error {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Stats = append(s.Stats, stat)
	// fmt.Println(stat.Info)
	return nil
}

func (s *SSHHoneypot) GetStats() ([]internal.Stat, error) {
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	// Return a copy of the slice to avoid data races when the API reads it
	statsCopy := make([]internal.Stat, len(s.Stats))
	copy(statsCopy, s.Stats)
	return statsCopy, nil
}
