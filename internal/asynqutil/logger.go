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
func NewLogger(l *slog.Logger) *Logger {
	return &Logger{logger: l}
}

func (l *Logger) Debug(args ...any) { l.logger.Debug(fmt.Sprint(args...)) }
func (l *Logger) Info(args ...any)  { l.logger.Info(fmt.Sprint(args...)) }
func (l *Logger) Warn(args ...any)  { l.logger.Warn(fmt.Sprint(args...)) }
func (l *Logger) Error(args ...any) { l.logger.Error(fmt.Sprint(args...)) }
func (l *Logger) Fatal(args ...any) { l.logger.Error(fmt.Sprint(args...)) }
