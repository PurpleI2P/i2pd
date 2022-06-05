#ifndef INCLUDE_INJA_PARSER_HPP_
#define INCLUDE_INJA_PARSER_HPP_

#include <limits>
#include <stack>
#include <string>
#include <utility>
#include <vector>

#include "config.hpp"
#include "exceptions.hpp"
#include "function_storage.hpp"
#include "lexer.hpp"
#include "node.hpp"
#include "template.hpp"
#include "token.hpp"
#include "utils.hpp"

namespace inja {

/*!
 * \brief Class for parsing an inja Template.
 */
class Parser {
  const ParserConfig& config;

  Lexer lexer;
  TemplateStorage& template_storage;
  const FunctionStorage& function_storage;

  Token tok, peek_tok;
  bool have_peek_tok {false};

  size_t current_paren_level {0};
  size_t current_bracket_level {0};
  size_t current_brace_level {0};

  std::string_view literal_start;

  BlockNode* current_block {nullptr};
  ExpressionListNode* current_expression_list {nullptr};
  std::stack<std::pair<FunctionNode*, size_t>> function_stack;
  std::vector<std::shared_ptr<ExpressionNode>> arguments;

  std::stack<std::shared_ptr<FunctionNode>> operator_stack;
  std::stack<IfStatementNode*> if_statement_stack;
  std::stack<ForStatementNode*> for_statement_stack;
  std::stack<BlockStatementNode*> block_statement_stack;

  inline void throw_parser_error(const std::string& message) const {
    INJA_THROW(ParserError(message, lexer.current_position()));
  }

  inline void get_next_token() {
    if (have_peek_tok) {
      tok = peek_tok;
      have_peek_tok = false;
    } else {
      tok = lexer.scan();
    }
  }

  inline void get_peek_token() {
    if (!have_peek_tok) {
      peek_tok = lexer.scan();
      have_peek_tok = true;
    }
  }

  inline void add_literal(const char* content_ptr) {
    std::string_view data_text(literal_start.data(), tok.text.data() - literal_start.data() + tok.text.size());
    arguments.emplace_back(std::make_shared<LiteralNode>(data_text, data_text.data() - content_ptr));
  }

  inline void add_operator() {
    auto function = operator_stack.top();
    operator_stack.pop();

    for (int i = 0; i < function->number_args; ++i) {
      function->arguments.insert(function->arguments.begin(), arguments.back());
      arguments.pop_back();
    }
    arguments.emplace_back(function);
  }

  void add_to_template_storage(std::string_view path, std::string& template_name) {
    if (template_storage.find(template_name) != template_storage.end()) {
      return;
    }

    std::string original_path = static_cast<std::string>(path);
    std::string original_name = template_name;

    if (config.search_included_templates_in_files) {
      // Build the relative path
      template_name = original_path + original_name;
      if (template_name.compare(0, 2, "./") == 0) {
        template_name.erase(0, 2);
      }

      if (template_storage.find(template_name) == template_storage.end()) {
        // Load file
        std::ifstream file;
        file.open(template_name);
        if (!file.fail()) {
          std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

          auto include_template = Template(text);
          template_storage.emplace(template_name, include_template);
          parse_into_template(template_storage[template_name], template_name);
          return;
        } else if (!config.include_callback) {
          INJA_THROW(FileError("failed accessing file at '" + template_name + "'"));
        }
      }
    }

    // Try include callback
    if (config.include_callback) {
      auto include_template = config.include_callback(original_path, original_name);
      template_storage.emplace(template_name, include_template);
    }
  }

  std::string parse_filename(const Token& tok) const {
    if (tok.kind != Token::Kind::String) {
      throw_parser_error("expected string, got '" + tok.describe() + "'");
    }

    if (tok.text.length() < 2) {
      throw_parser_error("expected filename, got '" + static_cast<std::string>(tok.text) + "'");
    }

    // Remove first and last character ""
    return std::string {tok.text.substr(1, tok.text.length() - 2)};
  }

  bool parse_expression(Template& tmpl, Token::Kind closing) {
    while (tok.kind != closing && tok.kind != Token::Kind::Eof) {
      // Literals
      switch (tok.kind) {
      case Token::Kind::String: {
        if (current_brace_level == 0 && current_bracket_level == 0) {
          literal_start = tok.text;
          add_literal(tmpl.content.c_str());
        }
      } break;
      case Token::Kind::Number: {
        if (current_brace_level == 0 && current_bracket_level == 0) {
          literal_start = tok.text;
          add_literal(tmpl.content.c_str());
        }
      } break;
      case Token::Kind::LeftBracket: {
        if (current_brace_level == 0 && current_bracket_level == 0) {
          literal_start = tok.text;
        }
        current_bracket_level += 1;
      } break;
      case Token::Kind::LeftBrace: {
        if (current_brace_level == 0 && current_bracket_level == 0) {
          literal_start = tok.text;
        }
        current_brace_level += 1;
      } break;
      case Token::Kind::RightBracket: {
        if (current_bracket_level == 0) {
          throw_parser_error("unexpected ']'");
        }

        current_bracket_level -= 1;
        if (current_brace_level == 0 && current_bracket_level == 0) {
          add_literal(tmpl.content.c_str());
        }
      } break;
      case Token::Kind::RightBrace: {
        if (current_brace_level == 0) {
          throw_parser_error("unexpected '}'");
        }

        current_brace_level -= 1;
        if (current_brace_level == 0 && current_bracket_level == 0) {
          add_literal(tmpl.content.c_str());
        }
      } break;
      case Token::Kind::Id: {
        get_peek_token();

        // Data Literal
        if (tok.text == static_cast<decltype(tok.text)>("true") || tok.text == static_cast<decltype(tok.text)>("false") ||
            tok.text == static_cast<decltype(tok.text)>("null")) {
          if (current_brace_level == 0 && current_bracket_level == 0) {
            literal_start = tok.text;
            add_literal(tmpl.content.c_str());
          }

          // Operator
        } else if (tok.text == "and" || tok.text == "or" || tok.text == "in" || tok.text == "not") {
          goto parse_operator;

          // Functions
        } else if (peek_tok.kind == Token::Kind::LeftParen) {
          operator_stack.emplace(std::make_shared<FunctionNode>(static_cast<std::string>(tok.text), tok.text.data() - tmpl.content.c_str()));
          function_stack.emplace(operator_stack.top().get(), current_paren_level);

          // Variables
        } else {
          arguments.emplace_back(std::make_shared<DataNode>(static_cast<std::string>(tok.text), tok.text.data() - tmpl.content.c_str()));
        }

        // Operators
      } break;
      case Token::Kind::Equal:
      case Token::Kind::NotEqual:
      case Token::Kind::GreaterThan:
      case Token::Kind::GreaterEqual:
      case Token::Kind::LessThan:
      case Token::Kind::LessEqual:
      case Token::Kind::Plus:
      case Token::Kind::Minus:
      case Token::Kind::Times:
      case Token::Kind::Slash:
      case Token::Kind::Power:
      case Token::Kind::Percent:
      case Token::Kind::Dot: {

      parse_operator:
        FunctionStorage::Operation operation;
        switch (tok.kind) {
        case Token::Kind::Id: {
          if (tok.text == "and") {
            operation = FunctionStorage::Operation::And;
          } else if (tok.text == "or") {
            operation = FunctionStorage::Operation::Or;
          } else if (tok.text == "in") {
            operation = FunctionStorage::Operation::In;
          } else if (tok.text == "not") {
            operation = FunctionStorage::Operation::Not;
          } else {
            throw_parser_error("unknown operator in parser.");
          }
        } break;
        case Token::Kind::Equal: {
          operation = FunctionStorage::Operation::Equal;
        } break;
        case Token::Kind::NotEqual: {
          operation = FunctionStorage::Operation::NotEqual;
        } break;
        case Token::Kind::GreaterThan: {
          operation = FunctionStorage::Operation::Greater;
        } break;
        case Token::Kind::GreaterEqual: {
          operation = FunctionStorage::Operation::GreaterEqual;
        } break;
        case Token::Kind::LessThan: {
          operation = FunctionStorage::Operation::Less;
        } break;
        case Token::Kind::LessEqual: {
          operation = FunctionStorage::Operation::LessEqual;
        } break;
        case Token::Kind::Plus: {
          operation = FunctionStorage::Operation::Add;
        } break;
        case Token::Kind::Minus: {
          operation = FunctionStorage::Operation::Subtract;
        } break;
        case Token::Kind::Times: {
          operation = FunctionStorage::Operation::Multiplication;
        } break;
        case Token::Kind::Slash: {
          operation = FunctionStorage::Operation::Division;
        } break;
        case Token::Kind::Power: {
          operation = FunctionStorage::Operation::Power;
        } break;
        case Token::Kind::Percent: {
          operation = FunctionStorage::Operation::Modulo;
        } break;
        case Token::Kind::Dot: {
          operation = FunctionStorage::Operation::AtId;
        } break;
        default: {
          throw_parser_error("unknown operator in parser.");
        }
        }
        auto function_node = std::make_shared<FunctionNode>(operation, tok.text.data() - tmpl.content.c_str());

        while (!operator_stack.empty() &&
               ((operator_stack.top()->precedence > function_node->precedence) ||
                (operator_stack.top()->precedence == function_node->precedence && function_node->associativity == FunctionNode::Associativity::Left)) &&
               (operator_stack.top()->operation != FunctionStorage::Operation::ParenLeft)) {
          add_operator();
        }

        operator_stack.emplace(function_node);
      } break;
      case Token::Kind::Comma: {
        if (current_brace_level == 0 && current_bracket_level == 0) {
          if (function_stack.empty()) {
            throw_parser_error("unexpected ','");
          }

          function_stack.top().first->number_args += 1;
        }
      } break;
      case Token::Kind::Colon: {
        if (current_brace_level == 0 && current_bracket_level == 0) {
          throw_parser_error("unexpected ':'");
        }
      } break;
      case Token::Kind::LeftParen: {
        current_paren_level += 1;
        operator_stack.emplace(std::make_shared<FunctionNode>(FunctionStorage::Operation::ParenLeft, tok.text.data() - tmpl.content.c_str()));

        get_peek_token();
        if (peek_tok.kind == Token::Kind::RightParen) {
          if (!function_stack.empty() && function_stack.top().second == current_paren_level - 1) {
            function_stack.top().first->number_args = 0;
          }
        }
      } break;
      case Token::Kind::RightParen: {
        current_paren_level -= 1;
        while (!operator_stack.empty() && operator_stack.top()->operation != FunctionStorage::Operation::ParenLeft) {
          add_operator();
        }

        if (!operator_stack.empty() && operator_stack.top()->operation == FunctionStorage::Operation::ParenLeft) {
          operator_stack.pop();
        }

        if (!function_stack.empty() && function_stack.top().second == current_paren_level) {
          auto func = function_stack.top().first;
          auto function_data = function_storage.find_function(func->name, func->number_args);
          if (function_data.operation == FunctionStorage::Operation::None) {
            throw_parser_error("unknown function " + func->name);
          }
          func->operation = function_data.operation;
          if (function_data.operation == FunctionStorage::Operation::Callback) {
            func->callback = function_data.callback;
          }

          if (operator_stack.empty()) {
            throw_parser_error("internal error at function " + func->name);
          }

          add_operator();
          function_stack.pop();
        }
      }
      default:
        break;
      }

      get_next_token();
    }

    while (!operator_stack.empty()) {
      add_operator();
    }

    if (arguments.size() == 1) {
      current_expression_list->root = arguments[0];
      arguments = {};
    } else if (arguments.size() > 1) {
      throw_parser_error("malformed expression");
    }

    return true;
  }

  bool parse_statement(Template& tmpl, Token::Kind closing, std::string_view path) {
    if (tok.kind != Token::Kind::Id) {
      return false;
    }

    if (tok.text == static_cast<decltype(tok.text)>("if")) {
      get_next_token();

      auto if_statement_node = std::make_shared<IfStatementNode>(current_block, tok.text.data() - tmpl.content.c_str());
      current_block->nodes.emplace_back(if_statement_node);
      if_statement_stack.emplace(if_statement_node.get());
      current_block = &if_statement_node->true_statement;
      current_expression_list = &if_statement_node->condition;

      if (!parse_expression(tmpl, closing)) {
        return false;
      }
    } else if (tok.text == static_cast<decltype(tok.text)>("else")) {
      if (if_statement_stack.empty()) {
        throw_parser_error("else without matching if");
      }
      auto& if_statement_data = if_statement_stack.top();
      get_next_token();

      if_statement_data->has_false_statement = true;
      current_block = &if_statement_data->false_statement;

      // Chained else if
      if (tok.kind == Token::Kind::Id && tok.text == static_cast<decltype(tok.text)>("if")) {
        get_next_token();

        auto if_statement_node = std::make_shared<IfStatementNode>(true, current_block, tok.text.data() - tmpl.content.c_str());
        current_block->nodes.emplace_back(if_statement_node);
        if_statement_stack.emplace(if_statement_node.get());
        current_block = &if_statement_node->true_statement;
        current_expression_list = &if_statement_node->condition;

        if (!parse_expression(tmpl, closing)) {
          return false;
        }
      }
    } else if (tok.text == static_cast<decltype(tok.text)>("endif")) {
      if (if_statement_stack.empty()) {
        throw_parser_error("endif without matching if");
      }

      // Nested if statements
      while (if_statement_stack.top()->is_nested) {
        if_statement_stack.pop();
      }

      auto& if_statement_data = if_statement_stack.top();
      get_next_token();

      current_block = if_statement_data->parent;
      if_statement_stack.pop();
    } else if (tok.text == static_cast<decltype(tok.text)>("block")) {
      get_next_token();

      if (tok.kind != Token::Kind::Id) {
        throw_parser_error("expected block name, got '" + tok.describe() + "'");
      }

      const std::string block_name = static_cast<std::string>(tok.text);

      auto block_statement_node = std::make_shared<BlockStatementNode>(current_block, block_name, tok.text.data() - tmpl.content.c_str());
      current_block->nodes.emplace_back(block_statement_node);
      block_statement_stack.emplace(block_statement_node.get());
      current_block = &block_statement_node->block;
      auto success = tmpl.block_storage.emplace(block_name, block_statement_node);
      if (!success.second) {
        throw_parser_error("block with the name '" + block_name + "' does already exist");
      }

      get_next_token();
    } else if (tok.text == static_cast<decltype(tok.text)>("endblock")) {
      if (block_statement_stack.empty()) {
        throw_parser_error("endblock without matching block");
      }

      auto& block_statement_data = block_statement_stack.top();
      get_next_token();

      current_block = block_statement_data->parent;
      block_statement_stack.pop();
    } else if (tok.text == static_cast<decltype(tok.text)>("for")) {
      get_next_token();

      // options: for a in arr; for a, b in obj
      if (tok.kind != Token::Kind::Id) {
        throw_parser_error("expected id, got '" + tok.describe() + "'");
      }

      Token value_token = tok;
      get_next_token();

      // Object type
      std::shared_ptr<ForStatementNode> for_statement_node;
      if (tok.kind == Token::Kind::Comma) {
        get_next_token();
        if (tok.kind != Token::Kind::Id) {
          throw_parser_error("expected id, got '" + tok.describe() + "'");
        }

        Token key_token = std::move(value_token);
        value_token = tok;
        get_next_token();

        for_statement_node = std::make_shared<ForObjectStatementNode>(static_cast<std::string>(key_token.text), static_cast<std::string>(value_token.text),
                                                                      current_block, tok.text.data() - tmpl.content.c_str());

        // Array type
      } else {
        for_statement_node =
            std::make_shared<ForArrayStatementNode>(static_cast<std::string>(value_token.text), current_block, tok.text.data() - tmpl.content.c_str());
      }

      current_block->nodes.emplace_back(for_statement_node);
      for_statement_stack.emplace(for_statement_node.get());
      current_block = &for_statement_node->body;
      current_expression_list = &for_statement_node->condition;

      if (tok.kind != Token::Kind::Id || tok.text != static_cast<decltype(tok.text)>("in")) {
        throw_parser_error("expected 'in', got '" + tok.describe() + "'");
      }
      get_next_token();

      if (!parse_expression(tmpl, closing)) {
        return false;
      }
    } else if (tok.text == static_cast<decltype(tok.text)>("endfor")) {
      if (for_statement_stack.empty()) {
        throw_parser_error("endfor without matching for");
      }

      auto& for_statement_data = for_statement_stack.top();
      get_next_token();

      current_block = for_statement_data->parent;
      for_statement_stack.pop();
    } else if (tok.text == static_cast<decltype(tok.text)>("include")) {
      get_next_token();

      std::string template_name = parse_filename(tok);
      add_to_template_storage(path, template_name);

      current_block->nodes.emplace_back(std::make_shared<IncludeStatementNode>(template_name, tok.text.data() - tmpl.content.c_str()));

      get_next_token();
    } else if (tok.text == static_cast<decltype(tok.text)>("extends")) {
      get_next_token();

      std::string template_name = parse_filename(tok);
      add_to_template_storage(path, template_name);

      current_block->nodes.emplace_back(std::make_shared<ExtendsStatementNode>(template_name, tok.text.data() - tmpl.content.c_str()));

      get_next_token();
    } else if (tok.text == static_cast<decltype(tok.text)>("set")) {
      get_next_token();

      if (tok.kind != Token::Kind::Id) {
        throw_parser_error("expected variable name, got '" + tok.describe() + "'");
      }

      std::string key = static_cast<std::string>(tok.text);
      get_next_token();

      auto set_statement_node = std::make_shared<SetStatementNode>(key, tok.text.data() - tmpl.content.c_str());
      current_block->nodes.emplace_back(set_statement_node);
      current_expression_list = &set_statement_node->expression;

      if (tok.text != static_cast<decltype(tok.text)>("=")) {
        throw_parser_error("expected '=', got '" + tok.describe() + "'");
      }
      get_next_token();

      if (!parse_expression(tmpl, closing)) {
        return false;
      }
    } else {
      return false;
    }
    return true;
  }

  void parse_into(Template& tmpl, std::string_view path) {
    lexer.start(tmpl.content);
    current_block = &tmpl.root;

    for (;;) {
      get_next_token();
      switch (tok.kind) {
      case Token::Kind::Eof: {
        if (!if_statement_stack.empty()) {
          throw_parser_error("unmatched if");
        }
        if (!for_statement_stack.empty()) {
          throw_parser_error("unmatched for");
        }
      }
        return;
      case Token::Kind::Text: {
        current_block->nodes.emplace_back(std::make_shared<TextNode>(tok.text.data() - tmpl.content.c_str(), tok.text.size()));
      } break;
      case Token::Kind::StatementOpen: {
        get_next_token();
        if (!parse_statement(tmpl, Token::Kind::StatementClose, path)) {
          throw_parser_error("expected statement, got '" + tok.describe() + "'");
        }
        if (tok.kind != Token::Kind::StatementClose) {
          throw_parser_error("expected statement close, got '" + tok.describe() + "'");
        }
      } break;
      case Token::Kind::LineStatementOpen: {
        get_next_token();
        if (!parse_statement(tmpl, Token::Kind::LineStatementClose, path)) {
          throw_parser_error("expected statement, got '" + tok.describe() + "'");
        }
        if (tok.kind != Token::Kind::LineStatementClose && tok.kind != Token::Kind::Eof) {
          throw_parser_error("expected line statement close, got '" + tok.describe() + "'");
        }
      } break;
      case Token::Kind::ExpressionOpen: {
        get_next_token();

        auto expression_list_node = std::make_shared<ExpressionListNode>(tok.text.data() - tmpl.content.c_str());
        current_block->nodes.emplace_back(expression_list_node);
        current_expression_list = expression_list_node.get();

        if (!parse_expression(tmpl, Token::Kind::ExpressionClose)) {
          throw_parser_error("expected expression, got '" + tok.describe() + "'");
        }

        if (tok.kind != Token::Kind::ExpressionClose) {
          throw_parser_error("expected expression close, got '" + tok.describe() + "'");
        }
      } break;
      case Token::Kind::CommentOpen: {
        get_next_token();
        if (tok.kind != Token::Kind::CommentClose) {
          throw_parser_error("expected comment close, got '" + tok.describe() + "'");
        }
      } break;
      default: {
        throw_parser_error("unexpected token '" + tok.describe() + "'");
      } break;
      }
    }
  }

public:
  explicit Parser(const ParserConfig& parser_config, const LexerConfig& lexer_config, TemplateStorage& template_storage,
                  const FunctionStorage& function_storage)
      : config(parser_config), lexer(lexer_config), template_storage(template_storage), function_storage(function_storage) {}

  Template parse(std::string_view input, std::string_view path) {
    auto result = Template(static_cast<std::string>(input));
    parse_into(result, path);
    return result;
  }

  Template parse(std::string_view input) {
    return parse(input, "./");
  }

  void parse_into_template(Template& tmpl, std::string_view filename) {
    std::string_view path = filename.substr(0, filename.find_last_of("/\\") + 1);

    // StringRef path = sys::path::parent_path(filename);
    auto sub_parser = Parser(config, lexer.get_config(), template_storage, function_storage);
    sub_parser.parse_into(tmpl, path);
  }

  std::string load_file(const std::string& filename) {
    std::ifstream file;
    file.open(filename);
    if (file.fail()) {
      INJA_THROW(FileError("failed accessing file at '" + filename + "'"));
    }
    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return text;
  }
};

} // namespace inja

#endif // INCLUDE_INJA_PARSER_HPP_
