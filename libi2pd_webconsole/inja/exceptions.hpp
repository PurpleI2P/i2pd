#ifndef INCLUDE_INJA_EXCEPTIONS_HPP_
#define INCLUDE_INJA_EXCEPTIONS_HPP_

#include <stdexcept>
#include <string>

namespace inja {

struct SourceLocation {
  size_t line;
  size_t column;
};

struct InjaError : public std::runtime_error {
  const std::string type;
  const std::string message;

  const SourceLocation location;

  explicit InjaError(const std::string& type, const std::string& message)
      : std::runtime_error("[inja.exception." + type + "] " + message), type(type), message(message), location({0, 0}) {}

  explicit InjaError(const std::string& type, const std::string& message, SourceLocation location)
      : std::runtime_error("[inja.exception." + type + "] (at " + std::to_string(location.line) + ":" + std::to_string(location.column) + ") " + message),
        type(type), message(message), location(location) {}
};

struct ParserError : public InjaError {
  explicit ParserError(const std::string& message, SourceLocation location): InjaError("parser_error", message, location) {}
};

struct RenderError : public InjaError {
  explicit RenderError(const std::string& message, SourceLocation location): InjaError("render_error", message, location) {}
};

struct FileError : public InjaError {
  explicit FileError(const std::string& message): InjaError("file_error", message) {}
  explicit FileError(const std::string& message, SourceLocation location): InjaError("file_error", message, location) {}
};

struct DataError : public InjaError {
  explicit DataError(const std::string& message, SourceLocation location): InjaError("data_error", message, location) {}
};

} // namespace inja

#endif // INCLUDE_INJA_EXCEPTIONS_HPP_
