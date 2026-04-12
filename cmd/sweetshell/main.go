package main

import (
	"time"

	"github.com/rexlx/sweetshell/internal"
	sshhoneypot "github.com/rexlx/sweetshell/ssh_honeypot"
)

func main() {
	app := internal.NewApp("my-secret-key", 24*time.Hour)

	sshPot := sshhoneypot.NewSSHHoneypot(2222)
	sshPot.Start()

	app.AddHoneypot("ssh", sshPot)

	// Block forever
	select {}
}
