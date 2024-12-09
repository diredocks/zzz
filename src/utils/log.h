#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

// Define maximum log message size
#define MAX_LOG_MESSAGE 1024

// ANSI color codes
#define RESET_COLOR "\033[0m"
#define INFO_COLOR "\033[32m\033[1m"  // Green for INFO
#define WARN_COLOR "\033[33m\033[1m"  // Yellow for WARN
#define ERROR_COLOR "\033[31m\033[1m" // Red for ERROR
#define DIMMED_COLOR "\033[2m"        // Dimmed white for keys

// Log levels
typedef enum { LOG_LEVEL_INFO, LOG_LEVEL_WARN, LOG_LEVEL_ERROR } LogLevel;

// Logging functions
void log_message(LogLevel level, const char *message, ...);
#define log_info(msg, ...) log_message(LOG_LEVEL_INFO, msg, __VA_ARGS__, NULL)
#define log_warn(msg, ...) log_message(LOG_LEVEL_WARN, msg, __VA_ARGS__, NULL)
#define log_error(msg, ...) log_message(LOG_LEVEL_ERROR, msg, __VA_ARGS__, NULL)

#endif // LOG_H
