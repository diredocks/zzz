#include "utils/log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

void log_message(LogLevel level, const char *message, ...) {
  char time_buffer[20];
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  // Format the timestamp
  strftime(time_buffer, sizeof(time_buffer), "%Y/%m/%d %H:%M:%S", tm_info);

  // Select log level color and label
  const char *level_str;
  const char *level_color;
  FILE *output_stream;
  switch (level) {
  case LOG_LEVEL_INFO:
    level_str = "INFO";
    level_color = INFO_COLOR;
    output_stream = stdout; // INFO goes to stdout
    break;
  case LOG_LEVEL_WARN:
    level_str = "WARN";
    level_color = WARN_COLOR;
    output_stream = stderr; // WARN goes to stderr
    break;
  case LOG_LEVEL_ERROR:
    level_str = "ERRO";
    level_color = ERROR_COLOR;
    output_stream = stderr; // ERROR goes to stderr
    break;
  default:
    level_str = "UNKW";
    level_color = RESET_COLOR;
    output_stream = stderr; // Default to stderr for unknown levels
    break;
  }

  // Print timestamp and level
  fprintf(output_stream, "%s %s%s%s %s", time_buffer, level_color, level_str,
          RESET_COLOR, message);

  // Process variadic arguments
  va_list args;
  va_start(args, message);
  while (1) {
    const char *key = va_arg(args, const char *);
    if (key == NULL)
      break; // End of arguments

    const int value = va_arg(args, const int);
    if (value < 0 || value > 255)
      break; // Malformed input
    fprintf(output_stream, " %s%s=%s%d", DIMMED_COLOR, key, RESET_COLOR, value);
    // Print key-value pairs
  }
  va_end(args);

  fprintf(output_stream, "\n"); // End the log line
}
