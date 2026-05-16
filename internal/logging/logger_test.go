package logging

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarning, "WARN"},
		{LevelError, "ERROR"},
		{LogLevel(999), "INFO"}, // Unknown level defaults to INFO
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	logger := NewLogger()

	if logger == nil {
		t.Fatal("Expected logger to be created")
	}

	// Default level should be from environment or INFO
	if logger.level != getLogLevelFromEnv() {
		t.Errorf("Expected level %v, got %v", getLogLevelFromEnv(), logger.level)
	}
}

func TestNewLoggerWithLevel(t *testing.T) {
	tests := []LogLevel{
		LevelDebug,
		LevelInfo,
		LevelWarning,
		LevelError,
	}

	for _, level := range tests {
		t.Run(level.String(), func(t *testing.T) {
			logger := NewLoggerWithLevel(level)

			if logger == nil {
				t.Fatal("Expected logger to be created")
			}

			if logger.level != level {
				t.Errorf("Expected level %v, got %v", level, logger.level)
			}
		})
	}
}

func TestGetLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected LogLevel
	}{
		{"Debug level", "DEBUG", LevelDebug},
		{"Info level", "INFO", LevelInfo},
		{"Info level lowercase", "info", LevelInfo},
		{"Warning level", "WARN", LevelWarning},
		{"Warning level alt", "WARNING", LevelWarning},
		{"Error level", "ERROR", LevelError},
		{"Empty defaults to Info", "", LevelInfo},
		{"Unknown defaults to Info", "INVALID", LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			oldValue := os.Getenv("LOG_LEVEL")
			defer func() { _ = os.Setenv("LOG_LEVEL", oldValue) }()

			_ = os.Setenv("LOG_LEVEL", tt.envValue)

			result := getLogLevelFromEnv()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestLogger_SetAndGetLevel(t *testing.T) {
	logger := NewLogger()

	tests := []LogLevel{
		LevelDebug,
		LevelInfo,
		LevelWarning,
		LevelError,
	}

	for _, level := range tests {
		logger.SetLevel(level)
		result := logger.GetLevel()

		if result != level {
			t.Errorf("Expected level %v, got %v", level, result)
		}
	}
}

func TestLogger_LogMessage_RespectLevel(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewLoggerWithLevel(LevelWarning)
	logger.syslogOnly = false // Ensure console logging is enabled

	// Debug and Info should not appear (below warning level)
	logger.Debug("debug message")
	logger.Info("info message")

	// Warning and Error should appear (at or above warning level)
	logger.Warning("warning message")
	logger.Error("error message")

	output := buf.String()

	// Debug and Info should not be in output
	if strings.Contains(output, "debug message") {
		t.Error("Debug message should not appear when level is Warning")
	}
	if strings.Contains(output, "info message") {
		t.Error("Info message should not appear when level is Warning")
	}

	// Warning and Error should be in output
	if !strings.Contains(output, "warning message") {
		t.Error("Warning message should appear when level is Warning")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error message should appear when level is Warning")
	}
}

func TestLogger_LogMessage_Formatting(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewLoggerWithLevel(LevelInfo)
	logger.syslogOnly = false

	logger.Info("test message with %s and %d", "string", 42)

	output := buf.String()

	if !strings.Contains(output, "test message with string and 42") {
		t.Errorf("Expected formatted message, got: %s", output)
	}
	if !strings.Contains(output, "[INFO]") {
		t.Error("Expected [INFO] prefix in output")
	}
}

func TestLogger_AllLogLevels(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewLoggerWithLevel(LevelDebug) // Set to debug to see all messages
	logger.syslogOnly = false

	logger.Debug("debug test")
	logger.Info("info test")
	logger.Warning("warning test")
	logger.Error("error test")

	output := buf.String()

	// All messages should appear
	if !strings.Contains(output, "debug test") {
		t.Error("Debug message missing")
	}
	if !strings.Contains(output, "info test") {
		t.Error("Info message missing")
	}
	if !strings.Contains(output, "warning test") {
		t.Error("Warning message missing")
	}
	if !strings.Contains(output, "error test") {
		t.Error("Error message missing")
	}

	// Check for proper level tags
	if !strings.Contains(output, "[DEBUG]") {
		t.Error("DEBUG tag missing")
	}
	if !strings.Contains(output, "[INFO]") {
		t.Error("INFO tag missing")
	}
	if !strings.Contains(output, "[WARN]") {
		t.Error("WARN tag missing")
	}
	if !strings.Contains(output, "[ERROR]") {
		t.Error("ERROR tag missing")
	}
}

func TestGlobalLoggingFunctions(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Use global logger
	SetLevel(LevelDebug)

	// Ensure console logging is enabled
	DisableSyslogOnly()

	Debug("global debug")
	Info("global info")
	Warning("global warning")
	Error("global error")

	output := buf.String()

	if !strings.Contains(output, "global debug") {
		t.Error("Global debug missing")
	}
	if !strings.Contains(output, "global info") {
		t.Error("Global info missing")
	}
	if !strings.Contains(output, "global warning") {
		t.Error("Global warning missing")
	}
	if !strings.Contains(output, "global error") {
		t.Error("Global error missing")
	}
}

func TestGlobalSetAndGetLevel(t *testing.T) {
	originalLevel := GetLevel()
	defer SetLevel(originalLevel)

	SetLevel(LevelError)

	result := GetLevel()
	if result != LevelError {
		t.Errorf("Expected level %v, got %v", LevelError, result)
	}

	SetLevel(LevelDebug)

	result = GetLevel()
	if result != LevelDebug {
		t.Errorf("Expected level %v, got %v", LevelDebug, result)
	}
}

func TestEnableDisableSyslogOnly(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewLoggerWithLevel(LevelInfo)

	// Enable syslog-only mode
	_ = EnableSyslogOnly()

	logger.Info("syslog only message")

	output := buf.String()

	// Message should NOT appear in console output when syslog-only is enabled
	if strings.Contains(output, "syslog only message") {
		t.Error("Message should not appear in console when syslog-only is enabled")
	}

	// Reset buffer
	buf.Reset()

	// Disable syslog-only mode
	DisableSyslogOnly()

	logger.Info("console message")

	output = buf.String()

	// Message SHOULD appear in console output when syslog-only is disabled
	if !strings.Contains(output, "console message") {
		t.Error("Message should appear in console when syslog-only is disabled")
	}
}

func TestLogger_Close(t *testing.T) {
	logger := NewLogger()

	// Should not panic even if syslog writer is nil
	logger.Close()

	// If syslog writer exists, it should be closed
	if logger.syslogWriter != nil {
		// No way to test if it's actually closed, but at least verify no panic
		logger.Close()
	}
}

func TestLogger_SyslogOnly_InstanceFlag(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Ensure global flag is disabled
	DisableSyslogOnly()

	logger := NewLoggerWithLevel(LevelInfo)
	logger.syslogOnly = true // Set instance flag

	logger.Info("instance syslog only")

	output := buf.String()

	// Should not appear in console
	if strings.Contains(output, "instance syslog only") {
		t.Error("Message should not appear when instance syslog-only flag is set")
	}
}

func TestShouldLogRepeatedFailure(t *testing.T) {
	tests := []struct {
		name         string
		attempt      int
		firstVisible int
		repeatEvery  int
		want         bool
	}{
		{name: "zero attempt", attempt: 0, firstVisible: 3, repeatEvery: 10, want: false},
		{name: "below threshold", attempt: 2, firstVisible: 3, repeatEvery: 10, want: false},
		{name: "at threshold", attempt: 3, firstVisible: 3, repeatEvery: 10, want: true},
		{name: "between threshold and interval", attempt: 7, firstVisible: 3, repeatEvery: 10, want: false},
		{name: "first repeated interval", attempt: 13, firstVisible: 3, repeatEvery: 10, want: true},
		{name: "no repeat interval only threshold", attempt: 4, firstVisible: 3, repeatEvery: 0, want: false},
		{name: "always visible from first with interval", attempt: 1, firstVisible: 1, repeatEvery: 5, want: true},
		{name: "visible at repeated interval from first", attempt: 6, firstVisible: 1, repeatEvery: 5, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldLogRepeatedFailure(tt.attempt, tt.firstVisible, tt.repeatEvery)
			if got != tt.want {
				t.Errorf("ShouldLogRepeatedFailure(%d, %d, %d) = %v, want %v", tt.attempt, tt.firstVisible, tt.repeatEvery, got, tt.want)
			}
		})
	}
}
