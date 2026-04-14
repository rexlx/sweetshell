package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rexlx/sweetshell/internal"
	sshhoneypot "github.com/rexlx/sweetshell/ssh_honeypot"
)

func main() {
	stopch := make(chan struct{})
	// connStr := "postgres://user:password@192.168.86.120:5432/sweetshell?sslmode=disable"
	connStr := os.Getenv("SWEETSHELL_DSN")
	thatKey := os.Getenv("SWEETSHELL_API_KEY")
	if connStr == "" || thatKey == "" {
		log.Fatal("missing environment variable(s)")
	}
	err := internal.InitDB(connStr)
	if err != nil {
		panic(err)
	}
	app := internal.NewApp(thatKey, 24*time.Hour)

	sshPot := sshhoneypot.NewSSHHoneypot(2222)
	sshPot.StopChan = stopch
	sshPot.Start()

	app.AddHoneypot("ssh", sshPot)
	go app.RotateLogs(6*time.Hour, stopch)

	// Start the HTTP server for the API
	if err := http.ListenAndServe(":8080", app.Gateway); err != nil {
		fmt.Println(err)
		fmt.Println("Shutting down honeypots...")
	}
	close(stopch)
}
