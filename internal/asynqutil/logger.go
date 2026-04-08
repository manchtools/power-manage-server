package asynqutil

import (
	"fmt"
	"log/slog"
)

// Logger adapts slog.Logger to the asynq.Logger interface.
type Logger struct {
	logger *slog.Logger
}

// NewLogger creates a new asynq-compatible logger.
// If l is nil, a default logger writing to stderr is used.
func NewLogger(l *slog.Logger) *Logger {
	if l == nil {
		l = slog.Default()
	}
	return &Logger{logger: l}
}

func (l *Logger) Debug(args ...any) { l.logger.Debug(fmt.Sprint(args...)) }
func (l *Logger) Info(args ...any)  { l.logger.Info(fmt.Sprint(args...)) }
func (l *Logger) Warn(args ...any)  { l.logger.Warn(fmt.Sprint(args...)) }
func (l *Logger) Error(args ...any) { l.logger.Error(fmt.Sprint(args...)) }

// Fatal logs at error level. We intentionally do not call os.Exit here —
// asynq may call Fatal on configuration errors, and killing the process
// without cleanup (deferred DB close, graceful shutdown) is worse than
// logging and letting the caller handle it.
func (l *Logger) Fatal(args ...any) { l.logger.Error(fmt.Sprint(args...)) }
