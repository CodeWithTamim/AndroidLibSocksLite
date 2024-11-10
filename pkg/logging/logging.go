package logging

import "log"

// LogInfo logs informational messages with an [INFO] prefix.
func LogInfo(message string) {
	logMessage("[INFO]", message)
}

// LogError logs error messages with an [ERROR] prefix.
func LogError(message string) {
	logMessage("[ERROR]", message)
}

// logMessage is a helper function to format and log messages.
func logMessage(level, message string) {
	log.Printf("%s %s\n", level, message)
}
