package logging

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strings"
)

// LogLevel defines the logging level
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarning
	LevelError
)

const (
	DefaultRepeatedFailureThreshold = 3
	DefaultRepeatedFailureInterval  = 10
)

func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarning:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Logger provides structured logging with configurable levels
type Logger struct {
	syslogWriter *syslog.Writer
	level        LogLevel
	syslogOnly   bool // If true, only log to syslog (daemon mode)
}

var defaultLogger *Logger
var globalSyslogOnly bool // Global flag that affects all logger instances

func init() {
	defaultLogger = NewLogger()
}

// NewLogger creates a new logger with default configuration
func NewLogger() *Logger {
	return NewLoggerWithLevel(getLogLevelFromEnv())
}

// NewLoggerWithLevel creates a logger with specified level
func NewLoggerWithLevel(level LogLevel) *Logger {
	l := &Logger{
		level: level,
	}

	// Try to connect to syslog (use "nannyagent" identifier for consistency)
	if writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "nannyagent"); err == nil {
		l.syslogWriter = writer
	}

	return l
}

// getLogLevelFromEnv parses log level from environment variable
func getLogLevelFromEnv() LogLevel {
	level := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	switch level {
	case "DEBUG":
		return LevelDebug
	case "INFO", "":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarning
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// ShouldLogRepeatedFailure returns true when a repeated failure should be surfaced
// beyond debug logging. It emits at the first visible threshold, then every
// repeatEvery attempts after that.
func ShouldLogRepeatedFailure(attempt, firstVisible, repeatEvery int) bool {
	if attempt <= 0 {
		return false
	}
	if firstVisible <= 1 {
		if repeatEvery <= 0 {
			return true
		}
		return attempt == 1 || (attempt-1)%repeatEvery == 0
	}
	if attempt < firstVisible {
		return false
	}
	if repeatEvery <= 0 {
		return attempt == firstVisible
	}
	return attempt == firstVisible || (attempt-firstVisible)%repeatEvery == 0
}

// logMessage handles the actual logging
func (l *Logger) logMessage(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)

	// Set prefix based on log level
	prefix := fmt.Sprintf("[%s]", level.String())

	// Log to syslog if available
	if l.syslogWriter != nil {
		switch level {
		case LevelDebug:
			_ = l.syslogWriter.Debug(msg)
		case LevelInfo:
			_ = l.syslogWriter.Info(msg)
		case LevelWarning:
			_ = l.syslogWriter.Warning(msg)
		case LevelError:
			_ = l.syslogWriter.Err(msg)
		}
	}

	// Print to stdout/stderr (unless syslog-only mode)
	// Check both instance and global flags
	if !l.syslogOnly && !globalSyslogOnly {
		log.Printf("%s %s", prefix, msg)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.logMessage(LevelDebug, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.logMessage(LevelInfo, format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.logMessage(LevelWarning, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.logMessage(LevelError, format, args...)
}

// SetLevel changes the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// GetLevel returns current logging level
func (l *Logger) GetLevel() LogLevel {
	return l.level
}

func (l *Logger) Close() {
	if l.syslogWriter != nil {
		_ = l.syslogWriter.Close()
	}
}

// Global logging functions
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

func Warning(format string, args ...interface{}) {
	defaultLogger.Warning(format, args...)
}

func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// SetLevel sets the global logger level
func SetLevel(level LogLevel) {
	defaultLogger.SetLevel(level)
}

// GetLevel gets the global logger level
func GetLevel() LogLevel {
	return defaultLogger.GetLevel()
}

// EnableSyslogOnly sets syslog-only mode globally for ALL logger instances
func EnableSyslogOnly() error {
	if defaultLogger.syslogWriter == nil {
		return fmt.Errorf("syslog writer not initialized")
	}
	globalSyslogOnly = true
	defaultLogger.syslogOnly = true
	return nil
}

// DisableSyslogOnly disables syslog-only mode globally for ALL logger instances
func DisableSyslogOnly() {
	globalSyslogOnly = false
	defaultLogger.syslogOnly = false
}
