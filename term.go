package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// readValue obtains a value for `set` without it ever touching shell history or
// argv: a hidden (no-echo) prompt when run interactively, or piped stdin for
// scripts/CI (`cat key.txt | envd set …`).
func readValue(label string) string {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprintf(os.Stderr, "%s (input hidden, Enter to submit): ", label)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatalf("reading value: %v", err)
		}
		return string(b)
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatalf("reading value: %v", err)
	}
	return strings.TrimRight(string(b), "\r\n")
}

// stdinIsTTY reports whether stdin is an interactive terminal (so we can prompt).
func stdinIsTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// confirm asks a y/N question on the terminal. Returns false if stdin isn't a TTY.
func confirm(prompt string) bool {
	if !stdinIsTTY() {
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}
