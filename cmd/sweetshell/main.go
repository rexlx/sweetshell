package main

import (
	"net/http"
	"time"

	"github.com/rexlx/sweetshell/internal"
	sshhoneypot "github.com/rexlx/sweetshell/ssh_honeypot"
)

func main() {
	connStr := "postgres://rxlx:thereISnosp0)n@192.168.86.120:5432/sweetshell?sslmode=disable"
	err := internal.InitDB(connStr)
	if err != nil {
		panic(err)
	}
	app := internal.NewApp("my-secret-key", 24*time.Hour)

	sshPot := sshhoneypot.NewSSHHoneypot(2222)
	sshPot.Start()

	app.AddHoneypot("ssh", sshPot)

	// Start the HTTP server for the API
	if err := http.ListenAndServe(":8080", app.Gateway); err != nil {
		panic(err)
	}
}
