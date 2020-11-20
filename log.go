package sshx

import "log"

// Logger is a log interface
type Logger interface {
	Debugf(format string, v ...interface{})
	DebugEnabled() bool
}

// DefaultLogger is a default logger
type DefaultLogger struct{}

func (DefaultLogger) Debugf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

func (DefaultLogger) DebugEnabled() bool {
	return true
}
