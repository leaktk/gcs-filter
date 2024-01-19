package logging

import (
	"encoding/json"
	"fmt"
	"log"
)

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

func init() {
	// Disable log prefixes such as the default timestamp.
	// Prefix text prevents the message from being parsed as JSON.
	// A timestamp is added when shipping logs to Cloud Logging.
	log.SetFlags(0)
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

// Fatal emits an ERROR level log and stops the program
func Fatal(msg string, a ...any) {
	log.Fatal(LogEntry{
		Severity: "ERROR",
		Message:  fmt.Errorf(msg, a...).Error(),
	})
}
