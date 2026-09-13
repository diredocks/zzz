#include "utils/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static FILE *log_start(LogLevel level) {
  char time_buffer[20];
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);

  // format the timestamp
  strftime(time_buffer, sizeof(time_buffer), "%Y/%m/%d %H:%M:%S", tm_info);

  // select color and lable base on lovel
  const char *level_str;
  const char *level_color;
  FILE *output_stream;

  switch (level) {
  case LOG_LEVEL_INFO:
    level_str = "INFO";
    level_color = INFO_COLOR;
    output_stream = stdout;
    break;
  case LOG_LEVEL_WARN:
    level_str = "WARN";
    level_color = WARN_COLOR;
    output_stream = stderr;
    break;
  case LOG_LEVEL_ERROR:
    level_str = "ERRO";
    level_color = ERROR_COLOR;
    output_stream = stderr;
    break;
  default:
    level_str = "UNKW";
    level_color = RESET_COLOR;
    output_stream = stderr;
    break;
  }

  fprintf(output_stream, "%s %s%s%s ", time_buffer, level_color, level_str,
          RESET_COLOR);
  return output_stream;
}

void log_message(LogLevel level, const char *message, ...) {
  FILE *output_stream = log_start(level);

  fprintf(output_stream, "%s", message);

  // process variadic arguments
  va_list args;
  va_start(args, message);
  while (1) {
    const char *key = va_arg(args, const char *);
    if (key == NULL)
      break; // end of arguments

    const int value = va_arg(args, const int);
    if (value < 0 || value > 255)
      break; // malformed input
    // print key-value pairs
    fprintf(output_stream, " %s%s=%s%d", DIMMED_COLOR, key, RESET_COLOR, value);
  }
  va_end(args);

  // end the log line
  fprintf(output_stream, "\n");
}

void log_message_f(LogLevel level, const char *format, ...) {
  FILE *output_stream = log_start(level);

  va_list ap;
  va_start(ap, format);
  vfprintf(output_stream, format, ap);
  va_end(ap);

  // end the log line
  fprintf(output_stream, "\n");
}
