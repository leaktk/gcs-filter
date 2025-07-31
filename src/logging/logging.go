package logging

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	glog "github.com/zricethezav/gitleaks/v8/logging"
)

func init() {
	// Disable log prefixes such as the default timestamp.
	// Prefix text prevents the message from being parsed as JSON.
	// A timestamp is added when shipping logs to Cloud Logging.
	log.SetFlags(0)

	// Disable logging by default to make sure that gitleaks can't produce logs
	// without being specifically configured
	glog.Logger.Level(zerolog.Disabled)

	// Provide a custom handler to map to this logging framework
	glog.Logger = zlog.Output(zerologMapper{})
}

// zerologMapper helps translate logs from subsystems that use zerolog
type zerologMapper struct {
}

// Write implements an io.Writer interface
func (m zerologMapper) Write(data []byte) (int, error) {
	var event struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(data, &event); err != nil {
		Error("could not decode zerolog event %w", err)
		return 0, nil
	}

	switch event.Level {
	case "info":
		Info("gitleaks: %s", event.Message)
	case "warn":
		Warning("gitleaks: %s", event.Message)
	case "error":
		Error("gitleaks: %s", event.Message)
	case "fatal":
		Critical("gitleaks: %s", event.Message)
	case "panic":
		Critical("gitleaks: %s", event.Message)
	}

	return len(data), nil
}

// LogEntry defines a log entry for google logging
type LogEntry struct {
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"`
	Trace    string `json:"logging.googleapis.com/trace,omitempty"`

	// Logs Explorer allows filtering and display of this as `jsonPayload.component`.
	Component string `json:"component,omitempty"`
}

// String renders a log entry structure to the JSON format expected by Cloud Logging.
func (e LogEntry) String() string {
	if e.Severity == "" {
		e.Severity = "INFO"
	}

	out, err := json.Marshal(e)
	if err != nil {
		log.Printf("json.Marshal: %v", err)
	}

	return string(out)
}

// Debug emits an DEBUG level log
func Debug(msg string, a ...any) {
	log.Println(LogEntry{
		Severity: "DEBUG",
		Message:  fmt.Sprintf(msg, a...),
	})
}

// Warning emits an WARNING level log
func Warning(msg string, a ...any) {
	log.Println(LogEntry{
		Severity: "WARNING",
		Message:  fmt.Sprintf(msg, a...),
	})
}

// Info emits an INFO level log
func Info(msg string, a ...any) {
	log.Println(LogEntry{
		Severity: "INFO",
		Message:  fmt.Sprintf(msg, a...),
	})
}

// Error emits an ERROR level log
func Error(msg string, a ...any) {
	log.Println(LogEntry{
		Severity: "ERROR",
		Message:  fmt.Errorf(msg, a...).Error(),
	})
}

// Critical emits an CRITICAL level log
func Critical(msg string, a ...any) {
	log.Println(LogEntry{
		Severity: "CRITICAL",
		Message:  fmt.Errorf(msg, a...).Error(),
	})
}

// Fatal emits an CRITICAL level log and stops the program
func Fatal(msg string, a ...any) {
	log.Fatal(LogEntry{
		Severity: "CRITICAL",
		Message:  fmt.Errorf(msg, a...).Error(),
	})
}
