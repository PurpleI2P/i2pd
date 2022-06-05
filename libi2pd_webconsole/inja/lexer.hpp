#ifndef INCLUDE_INJA_LEXER_HPP_
#define INCLUDE_INJA_LEXER_HPP_

#include <cctype>
#include <locale>

#include "config.hpp"
#include "token.hpp"
#include "utils.hpp"

namespace inja {

/*!
 * \brief Class for lexing an inja Template.
 */
class Lexer {
  enum class State {
    Text,
    ExpressionStart,
    ExpressionStartForceLstrip,
    ExpressionBody,
    LineStart,
    LineBody,
    StatementStart,
    StatementStartNoLstrip,
    StatementStartForceLstrip,
    StatementBody,
    CommentStart,
    CommentStartForceLstrip,
    CommentBody,
  };

  enum class MinusState {
    Operator,
    Number,
  };

  const LexerConfig& config;

  State state;
  MinusState minus_state;
  std::string_view m_in;
  size_t tok_start;
  size_t pos;

  Token scan_body(std::string_view close, Token::Kind closeKind, std::string_view close_trim = std::string_view(), bool trim = false) {
  again:
    // skip whitespace (except for \n as it might be a close)
    if (tok_start >= m_in.size()) {
      return make_token(Token::Kind::Eof);
    }
    const char ch = m_in[tok_start];
    if (ch == ' ' || ch == '\t' || ch == '\r') {
      tok_start += 1;
      goto again;
    }

    // check for close
    if (!close_trim.empty() && inja::string_view::starts_with(m_in.substr(tok_start), close_trim)) {
      state = State::Text;
      pos = tok_start + close_trim.size();
      const Token tok = make_token(closeKind);
      skip_whitespaces_and_newlines();
      return tok;
    }

    if (inja::string_view::starts_with(m_in.substr(tok_start), close)) {
      state = State::Text;
      pos = tok_start + close.size();
      const Token tok = make_token(closeKind);
      if (trim) {
        skip_whitespaces_and_first_newline();
      }
      return tok;
    }

    // skip \n
    if (ch == '\n') {
      tok_start += 1;
      goto again;
    }

    pos = tok_start + 1;
    if (std::isalpha(ch)) {
      minus_state = MinusState::Operator;
      return scan_id();
    }

    const MinusState current_minus_state = minus_state;
    if (minus_state == MinusState::Operator) {
      minus_state = MinusState::Number;
    }

    switch (ch) {
    case '+':
      return make_token(Token::Kind::Plus);
    case '-':
      if (current_minus_state == MinusState::Operator) {
        return make_token(Token::Kind::Minus);
      }
      return scan_number();
    case '*':
      return make_token(Token::Kind::Times);
    case '/':
      return make_token(Token::Kind::Slash);
    case '^':
      return make_token(Token::Kind::Power);
    case '%':
      return make_token(Token::Kind::Percent);
    case '.':
      return make_token(Token::Kind::Dot);
    case ',':
      return make_token(Token::Kind::Comma);
    case ':':
      return make_token(Token::Kind::Colon);
    case '(':
      return make_token(Token::Kind::LeftParen);
    case ')':
      minus_state = MinusState::Operator;
      return make_token(Token::Kind::RightParen);
    case '[':
      return make_token(Token::Kind::LeftBracket);
    case ']':
      minus_state = MinusState::Operator;
      return make_token(Token::Kind::RightBracket);
    case '{':
      return make_token(Token::Kind::LeftBrace);
    case '}':
      minus_state = MinusState::Operator;
      return make_token(Token::Kind::RightBrace);
    case '>':
      if (pos < m_in.size() && m_in[pos] == '=') {
        pos += 1;
        return make_token(Token::Kind::GreaterEqual);
      }
      return make_token(Token::Kind::GreaterThan);
    case '<':
      if (pos < m_in.size() && m_in[pos] == '=') {
        pos += 1;
        return make_token(Token::Kind::LessEqual);
      }
      return make_token(Token::Kind::LessThan);
    case '=':
      if (pos < m_in.size() && m_in[pos] == '=') {
        pos += 1;
        return make_token(Token::Kind::Equal);
      }
      return make_token(Token::Kind::Unknown);
    case '!':
      if (pos < m_in.size() && m_in[pos] == '=') {
        pos += 1;
        return make_token(Token::Kind::NotEqual);
      }
      return make_token(Token::Kind::Unknown);
    case '\"':
      return scan_string();
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      minus_state = MinusState::Operator;
      return scan_number();
    case '_':
    case '@':
    case '$':
      minus_state = MinusState::Operator;
      return scan_id();
    default:
      return make_token(Token::Kind::Unknown);
    }
  }

  Token scan_id() {
    for (;;) {
      if (pos >= m_in.size()) {
        break;
      }
      const char ch = m_in[pos];
      if (!std::isalnum(ch) && ch != '.' && ch != '/' && ch != '_' && ch != '-') {
        break;
      }
      pos += 1;
    }
    return make_token(Token::Kind::Id);
  }

  Token scan_number() {
    for (;;) {
      if (pos >= m_in.size()) {
        break;
      }
      const char ch = m_in[pos];
      // be very permissive in lexer (we'll catch errors when conversion happens)
      if (!(std::isdigit(ch) || ch == '.' || ch == 'e' || ch == 'E' || (ch == '+' && (pos == 0 || m_in[pos-1] == 'e' || m_in[pos-1] == 'E')) || (ch == '-' && (pos == 0 || m_in[pos-1] == 'e' || m_in[pos-1] == 'E')))) {
        break;
      }
      pos += 1;
    }
    return make_token(Token::Kind::Number);
  }

  Token scan_string() {
    bool escape {false};
    for (;;) {
      if (pos >= m_in.size()) {
        break;
      }
      const char ch = m_in[pos++];
      if (ch == '\\') {
        escape = true;
      } else if (!escape && ch == m_in[tok_start]) {
        break;
      } else {
        escape = false;
      }
    }
    return make_token(Token::Kind::String);
  }

  Token make_token(Token::Kind kind) const {
    return Token(kind, string_view::slice(m_in, tok_start, pos));
  }

  void skip_whitespaces_and_newlines() {
    if (pos < m_in.size()) {
      while (pos < m_in.size() && (m_in[pos] == ' ' || m_in[pos] == '\t' || m_in[pos] == '\n' || m_in[pos] == '\r')) {
        pos += 1;
      }
    }
  }

  void skip_whitespaces_and_first_newline() {
    if (pos < m_in.size()) {
      while (pos < m_in.size() && (m_in[pos] == ' ' || m_in[pos] == '\t')) {
        pos += 1;
      }
    }

    if (pos < m_in.size()) {
      const char ch = m_in[pos];
      if (ch == '\n') {
        pos += 1;
      } else if (ch == '\r') {
        pos += 1;
        if (pos < m_in.size() && m_in[pos] == '\n') {
          pos += 1;
        }
      }
    }
  }

  static std::string_view clear_final_line_if_whitespace(std::string_view text) {
    std::string_view result = text;
    while (!result.empty()) {
      const char ch = result.back();
      if (ch == ' ' || ch == '\t') {
        result.remove_suffix(1);
      } else if (ch == '\n' || ch == '\r') {
        break;
      } else {
        return text;
      }
    }
    return result;
  }

public:
  explicit Lexer(const LexerConfig& config): config(config), state(State::Text), minus_state(MinusState::Number) {}

  SourceLocation current_position() const {
    return get_source_location(m_in, tok_start);
  }

  void start(std::string_view input) {
    m_in = input;
    tok_start = 0;
    pos = 0;
    state = State::Text;
    minus_state = MinusState::Number;

    // Consume byte order mark (BOM) for UTF-8
    if (inja::string_view::starts_with(m_in, "\xEF\xBB\xBF")) {
      m_in = m_in.substr(3);
    }
  }

  Token scan() {
    tok_start = pos;

  again:
    if (tok_start >= m_in.size()) {
      return make_token(Token::Kind::Eof);
    }

    switch (state) {
    default:
    case State::Text: {
      // fast-scan to first open character
      const size_t open_start = m_in.substr(pos).find_first_of(config.open_chars);
      if (open_start == std::string_view::npos) {
        // didn't find open, return remaining text as text token
        pos = m_in.size();
        return make_token(Token::Kind::Text);
      }
      pos += open_start;

      // try to match one of the opening sequences, and get the close
      std::string_view open_str = m_in.substr(pos);
      bool must_lstrip = false;
      if (inja::string_view::starts_with(open_str, config.expression_open)) {
        if (inja::string_view::starts_with(open_str, config.expression_open_force_lstrip)) {
          state = State::ExpressionStartForceLstrip;
          must_lstrip = true;
        } else {
          state = State::ExpressionStart;
        }
      } else if (inja::string_view::starts_with(open_str, config.statement_open)) {
        if (inja::string_view::starts_with(open_str, config.statement_open_no_lstrip)) {
          state = State::StatementStartNoLstrip;
        } else if (inja::string_view::starts_with(open_str, config.statement_open_force_lstrip)) {
          state = State::StatementStartForceLstrip;
          must_lstrip = true;
        } else {
          state = State::StatementStart;
          must_lstrip = config.lstrip_blocks;
        }
      } else if (inja::string_view::starts_with(open_str, config.comment_open)) {
        if (inja::string_view::starts_with(open_str, config.comment_open_force_lstrip)) {
          state = State::CommentStartForceLstrip;
          must_lstrip = true;
        } else {
          state = State::CommentStart;
          must_lstrip = config.lstrip_blocks;
        }
      } else if ((pos == 0 || m_in[pos - 1] == '\n') && inja::string_view::starts_with(open_str, config.line_statement)) {
        state = State::LineStart;
      } else {
        pos += 1; // wasn't actually an opening sequence
        goto again;
      }

      std::string_view text = string_view::slice(m_in, tok_start, pos);
      if (must_lstrip) {
        text = clear_final_line_if_whitespace(text);
      }

      if (text.empty()) {
        goto again; // don't generate empty token
      }
      return Token(Token::Kind::Text, text);
    }
    case State::ExpressionStart: {
      state = State::ExpressionBody;
      pos += config.expression_open.size();
      return make_token(Token::Kind::ExpressionOpen);
    }
    case State::ExpressionStartForceLstrip: {
      state = State::ExpressionBody;
      pos += config.expression_open_force_lstrip.size();
      return make_token(Token::Kind::ExpressionOpen);
    }
    case State::LineStart: {
      state = State::LineBody;
      pos += config.line_statement.size();
      return make_token(Token::Kind::LineStatementOpen);
    }
    case State::StatementStart: {
      state = State::StatementBody;
      pos += config.statement_open.size();
      return make_token(Token::Kind::StatementOpen);
    }
    case State::StatementStartNoLstrip: {
      state = State::StatementBody;
      pos += config.statement_open_no_lstrip.size();
      return make_token(Token::Kind::StatementOpen);
    }
    case State::StatementStartForceLstrip: {
      state = State::StatementBody;
      pos += config.statement_open_force_lstrip.size();
      return make_token(Token::Kind::StatementOpen);
    }
    case State::CommentStart: {
      state = State::CommentBody;
      pos += config.comment_open.size();
      return make_token(Token::Kind::CommentOpen);
    }
    case State::CommentStartForceLstrip: {
      state = State::CommentBody;
      pos += config.comment_open_force_lstrip.size();
      return make_token(Token::Kind::CommentOpen);
    }
    case State::ExpressionBody:
      return scan_body(config.expression_close, Token::Kind::ExpressionClose, config.expression_close_force_rstrip);
    case State::LineBody:
      return scan_body("\n", Token::Kind::LineStatementClose);
    case State::StatementBody:
      return scan_body(config.statement_close, Token::Kind::StatementClose, config.statement_close_force_rstrip, config.trim_blocks);
    case State::CommentBody: {
      // fast-scan to comment close
      const size_t end = m_in.substr(pos).find(config.comment_close);
      if (end == std::string_view::npos) {
        pos = m_in.size();
        return make_token(Token::Kind::Eof);
      }

      // Check for trim pattern
      const bool must_rstrip = inja::string_view::starts_with(m_in.substr(pos + end - 1), config.comment_close_force_rstrip);

      // return the entire comment in the close token
      state = State::Text;
      pos += end + config.comment_close.size();
      Token tok = make_token(Token::Kind::CommentClose);

      if (must_rstrip || config.trim_blocks) {
        skip_whitespaces_and_first_newline();
      }
      return tok;
    }
    }
  }

  const LexerConfig& get_config() const {
    return config;
  }
};

} // namespace inja

#endif // INCLUDE_INJA_LEXER_HPP_
