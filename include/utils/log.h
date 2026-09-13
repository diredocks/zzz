#ifndef ZZZ_LOG_H
#define ZZZ_LOG_H

#include <stdlib.h>

#define RESET_COLOR "\033[0m"
#define INFO_COLOR "\033[32m\033[1m"
#define WARN_COLOR "\033[33m\033[1m"
#define ERROR_COLOR "\033[31m\033[1m"
#define DIMMED_COLOR "\033[2m"

typedef enum _log_level {
  LOG_LEVEL_INFO,
  LOG_LEVEL_WARN,
  LOG_LEVEL_ERROR
} LogLevel;

void log_message(LogLevel level, const char *message, ...);
#define LOG(level, msg, ...) log_message(level, msg, __VA_ARGS__, NULL)
#define log_info(msg, ...) LOG(LOG_LEVEL_INFO, msg, __VA_ARGS__)
#define log_warn(msg, ...) LOG(LOG_LEVEL_WARN, msg, __VA_ARGS__)
#define log_error(msg, ...) LOG(LOG_LEVEL_ERROR, msg, __VA_ARGS__)

void log_message_f(LogLevel level, const char *format, ...);
#define LOGF(level, fmt, ...) log_message_f(level, fmt, ##__VA_ARGS__)
#define log_infof(fmt, ...) LOGF(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define log_warnf(fmt, ...) LOGF(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define log_errorf(fmt, ...) LOGF(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

#endif // !ZZZ_LOG_H
