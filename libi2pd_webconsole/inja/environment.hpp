#ifndef INCLUDE_INJA_ENVIRONMENT_HPP_
#define INCLUDE_INJA_ENVIRONMENT_HPP_

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>

#include "config.hpp"
#include "function_storage.hpp"
#include "parser.hpp"
#include "renderer.hpp"
#include "template.hpp"
#include "utils.hpp"

namespace inja {

/*!
 * \brief Class for changing the configuration.
 */
class Environment {
  LexerConfig lexer_config;
  ParserConfig parser_config;
  RenderConfig render_config;

  FunctionStorage function_storage;
  TemplateStorage template_storage;

protected:
  std::string input_path;
  std::string output_path;

public:
  Environment(): Environment("") {}

  explicit Environment(const std::string& global_path): input_path(global_path), output_path(global_path) {}

  Environment(const std::string& input_path, const std::string& output_path): input_path(input_path), output_path(output_path) {}

  /// Sets the opener and closer for template statements
  void set_statement(const std::string& open, const std::string& close) {
    lexer_config.statement_open = open;
    lexer_config.statement_open_no_lstrip = open + "+";
    lexer_config.statement_open_force_lstrip = open + "-";
    lexer_config.statement_close = close;
    lexer_config.statement_close_force_rstrip = "-" + close;
    lexer_config.update_open_chars();
  }

  /// Sets the opener for template line statements
  void set_line_statement(const std::string& open) {
    lexer_config.line_statement = open;
    lexer_config.update_open_chars();
  }

  /// Sets the opener and closer for template expressions
  void set_expression(const std::string& open, const std::string& close) {
    lexer_config.expression_open = open;
    lexer_config.expression_open_force_lstrip = open + "-";
    lexer_config.expression_close = close;
    lexer_config.expression_close_force_rstrip = "-" + close;
    lexer_config.update_open_chars();
  }

  /// Sets the opener and closer for template comments
  void set_comment(const std::string& open, const std::string& close) {
    lexer_config.comment_open = open;
    lexer_config.comment_open_force_lstrip = open + "-";
    lexer_config.comment_close = close;
    lexer_config.comment_close_force_rstrip = "-" + close;
    lexer_config.update_open_chars();
  }

  /// Sets whether to remove the first newline after a block
  void set_trim_blocks(bool trim_blocks) {
    lexer_config.trim_blocks = trim_blocks;
  }

  /// Sets whether to strip the spaces and tabs from the start of a line to a block
  void set_lstrip_blocks(bool lstrip_blocks) {
    lexer_config.lstrip_blocks = lstrip_blocks;
  }

  /// Sets the element notation syntax
  void set_search_included_templates_in_files(bool search_in_files) {
    parser_config.search_included_templates_in_files = search_in_files;
  }

  /// Sets whether a missing include will throw an error
  void set_throw_at_missing_includes(bool will_throw) {
    render_config.throw_at_missing_includes = will_throw;
  }

  Template parse(std::string_view input) {
    Parser parser(parser_config, lexer_config, template_storage, function_storage);
    return parser.parse(input);
  }

  Template parse_template(const std::string& filename) {
    Parser parser(parser_config, lexer_config, template_storage, function_storage);
    auto result = Template(parser.load_file(input_path + static_cast<std::string>(filename)));
    parser.parse_into_template(result, input_path + static_cast<std::string>(filename));
    return result;
  }

  Template parse_file(const std::string& filename) {
    return parse_template(filename);
  }

  std::string render(std::string_view input, const json& data) {
    return render(parse(input), data);
  }

  std::string render(const Template& tmpl, const json& data) {
    std::stringstream os;
    render_to(os, tmpl, data);
    return os.str();
  }

  std::string render_file(const std::string& filename, const json& data) {
    return render(parse_template(filename), data);
  }

  std::string render_file_with_json_file(const std::string& filename, const std::string& filename_data) {
    const json data = load_json(filename_data);
    return render_file(filename, data);
  }

  void write(const std::string& filename, const json& data, const std::string& filename_out) {
    std::ofstream file(output_path + filename_out);
    file << render_file(filename, data);
    file.close();
  }

  void write(const Template& temp, const json& data, const std::string& filename_out) {
    std::ofstream file(output_path + filename_out);
    file << render(temp, data);
    file.close();
  }

  void write_with_json_file(const std::string& filename, const std::string& filename_data, const std::string& filename_out) {
    const json data = load_json(filename_data);
    write(filename, data, filename_out);
  }

  void write_with_json_file(const Template& temp, const std::string& filename_data, const std::string& filename_out) {
    const json data = load_json(filename_data);
    write(temp, data, filename_out);
  }

  std::ostream& render_to(std::ostream& os, const Template& tmpl, const json& data) {
    Renderer(render_config, template_storage, function_storage).render_to(os, tmpl, data);
    return os;
  }

  std::string load_file(const std::string& filename) {
    Parser parser(parser_config, lexer_config, template_storage, function_storage);
    return parser.load_file(input_path + filename);
  }

  json load_json(const std::string& filename) {
    std::ifstream file;
    file.open(input_path + filename);
    if (file.fail()) {
      INJA_THROW(FileError("failed accessing file at '" + input_path + filename + "'"));
    }

    return json::parse(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  }

  /*!
  @brief Adds a variadic callback
  */
  void add_callback(const std::string& name, const CallbackFunction& callback) {
    add_callback(name, -1, callback);
  }

  /*!
  @brief Adds a variadic void callback
  */
  void add_void_callback(const std::string& name, const VoidCallbackFunction& callback) {
    add_void_callback(name, -1, callback);
  }

  /*!
  @brief Adds a callback with given number or arguments
  */
  void add_callback(const std::string& name, int num_args, const CallbackFunction& callback) {
    function_storage.add_callback(name, num_args, callback);
  }

  /*!
  @brief Adds a void callback with given number or arguments
  */
  void add_void_callback(const std::string& name, int num_args, const VoidCallbackFunction& callback) {
    function_storage.add_callback(name, num_args, [callback](Arguments& args) {
      callback(args);
      return json();
    });
  }

  /** Includes a template with a given name into the environment.
   * Then, a template can be rendered in another template using the
   * include "<name>" syntax.
   */
  void include_template(const std::string& name, const Template& tmpl) {
    template_storage[name] = tmpl;
  }

  /*!
  @brief Sets a function that is called when an included file is not found
  */
  void set_include_callback(const std::function<Template(const std::string&, const std::string&)>& callback) {
    parser_config.include_callback = callback;
  }
};

/*!
@brief render with default settings to a string
*/
inline std::string render(std::string_view input, const json& data) {
  return Environment().render(input, data);
}

/*!
@brief render with default settings to the given output stream
*/
inline void render_to(std::ostream& os, std::string_view input, const json& data) {
  Environment env;
  env.render_to(os, env.parse(input), data);
}

} // namespace inja

#endif // INCLUDE_INJA_ENVIRONMENT_HPP_
