#ifndef INCLUDE_INJA_CONFIG_HPP_
#define INCLUDE_INJA_CONFIG_HPP_

#include <functional>
#include <string>

#include "template.hpp"

namespace inja {

/*!
 * \brief Class for lexer configuration.
 */
struct LexerConfig {
  std::string statement_open {"{%"};
  std::string statement_open_no_lstrip {"{%+"};
  std::string statement_open_force_lstrip {"{%-"};
  std::string statement_close {"%}"};
  std::string statement_close_force_rstrip {"-%}"};
  std::string line_statement {"##"};
  std::string expression_open {"{{"};
  std::string expression_open_force_lstrip {"{{-"};
  std::string expression_close {"}}"};
  std::string expression_close_force_rstrip {"-}}"};
  std::string comment_open {"{#"};
  std::string comment_open_force_lstrip {"{#-"};
  std::string comment_close {"#}"};
  std::string comment_close_force_rstrip {"-#}"};
  std::string open_chars {"#{"};

  bool trim_blocks {false};
  bool lstrip_blocks {false};

  void update_open_chars() {
    open_chars = "";
    if (open_chars.find(line_statement[0]) == std::string::npos) {
      open_chars += line_statement[0];
    }
    if (open_chars.find(statement_open[0]) == std::string::npos) {
      open_chars += statement_open[0];
    }
    if (open_chars.find(statement_open_no_lstrip[0]) == std::string::npos) {
      open_chars += statement_open_no_lstrip[0];
    }
    if (open_chars.find(statement_open_force_lstrip[0]) == std::string::npos) {
      open_chars += statement_open_force_lstrip[0];
    }
    if (open_chars.find(expression_open[0]) == std::string::npos) {
      open_chars += expression_open[0];
    }
    if (open_chars.find(expression_open_force_lstrip[0]) == std::string::npos) {
      open_chars += expression_open_force_lstrip[0];
    }
    if (open_chars.find(comment_open[0]) == std::string::npos) {
      open_chars += comment_open[0];
    }
    if (open_chars.find(comment_open_force_lstrip[0]) == std::string::npos) {
      open_chars += comment_open_force_lstrip[0];
    }
  }
};

/*!
 * \brief Class for parser configuration.
 */
struct ParserConfig {
  bool search_included_templates_in_files {true};

  std::function<Template(const std::string&, const std::string&)> include_callback;
};

/*!
 * \brief Class for render configuration.
 */
struct RenderConfig {
  bool throw_at_missing_includes {true};
};

} // namespace inja

#endif // INCLUDE_INJA_CONFIG_HPP_
