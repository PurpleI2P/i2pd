#ifndef INCLUDE_INJA_NODE_HPP_
#define INCLUDE_INJA_NODE_HPP_

#include <string>
#include <string_view>
#include <utility>

#include "function_storage.hpp"
#include "utils.hpp"

namespace inja {

class NodeVisitor;
class BlockNode;
class TextNode;
class ExpressionNode;
class LiteralNode;
class DataNode;
class FunctionNode;
class ExpressionListNode;
class StatementNode;
class ForStatementNode;
class ForArrayStatementNode;
class ForObjectStatementNode;
class IfStatementNode;
class IncludeStatementNode;
class ExtendsStatementNode;
class BlockStatementNode;
class SetStatementNode;

class NodeVisitor {
public:
  virtual ~NodeVisitor() = default;

  virtual void visit(const BlockNode& node) = 0;
  virtual void visit(const TextNode& node) = 0;
  virtual void visit(const ExpressionNode& node) = 0;
  virtual void visit(const LiteralNode& node) = 0;
  virtual void visit(const DataNode& node) = 0;
  virtual void visit(const FunctionNode& node) = 0;
  virtual void visit(const ExpressionListNode& node) = 0;
  virtual void visit(const StatementNode& node) = 0;
  virtual void visit(const ForStatementNode& node) = 0;
  virtual void visit(const ForArrayStatementNode& node) = 0;
  virtual void visit(const ForObjectStatementNode& node) = 0;
  virtual void visit(const IfStatementNode& node) = 0;
  virtual void visit(const IncludeStatementNode& node) = 0;
  virtual void visit(const ExtendsStatementNode& node) = 0;
  virtual void visit(const BlockStatementNode& node) = 0;
  virtual void visit(const SetStatementNode& node) = 0;
};

/*!
 * \brief Base node class for the abstract syntax tree (AST).
 */
class AstNode {
public:
  virtual void accept(NodeVisitor& v) const = 0;

  size_t pos;

  AstNode(size_t pos): pos(pos) {}
  virtual ~AstNode() {}
};

class BlockNode : public AstNode {
public:
  std::vector<std::shared_ptr<AstNode>> nodes;

  explicit BlockNode(): AstNode(0) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class TextNode : public AstNode {
public:
  const size_t length;

  explicit TextNode(size_t pos, size_t length): AstNode(pos), length(length) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class ExpressionNode : public AstNode {
public:
  explicit ExpressionNode(size_t pos): AstNode(pos) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class LiteralNode : public ExpressionNode {
public:
  const json value;

  explicit LiteralNode(std::string_view data_text, size_t pos): ExpressionNode(pos), value(json::parse(data_text)) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class DataNode : public ExpressionNode {
public:
  const std::string name;
  const json::json_pointer ptr;

  static std::string convert_dot_to_ptr(std::string_view ptr_name) {
    std::string result;
    do {
      std::string_view part;
      std::tie(part, ptr_name) = string_view::split(ptr_name, '.');
      result.push_back('/');
      result.append(part.begin(), part.end());
    } while (!ptr_name.empty());
    return result;
  }

  explicit DataNode(std::string_view ptr_name, size_t pos): ExpressionNode(pos), name(ptr_name), ptr(json::json_pointer(convert_dot_to_ptr(ptr_name))) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class FunctionNode : public ExpressionNode {
  using Op = FunctionStorage::Operation;

public:
  enum class Associativity {
    Left,
    Right,
  };

  unsigned int precedence;
  Associativity associativity;

  Op operation;

  std::string name;
  int number_args; // Should also be negative -> -1 for unknown number
  std::vector<std::shared_ptr<ExpressionNode>> arguments;
  CallbackFunction callback;

  explicit FunctionNode(std::string_view name, size_t pos)
      : ExpressionNode(pos), precedence(8), associativity(Associativity::Left), operation(Op::Callback), name(name), number_args(1) {}
  explicit FunctionNode(Op operation, size_t pos): ExpressionNode(pos), operation(operation), number_args(1) {
    switch (operation) {
    case Op::Not: {
      number_args = 1;
      precedence = 4;
      associativity = Associativity::Left;
    } break;
    case Op::And: {
      number_args = 2;
      precedence = 1;
      associativity = Associativity::Left;
    } break;
    case Op::Or: {
      number_args = 2;
      precedence = 1;
      associativity = Associativity::Left;
    } break;
    case Op::In: {
      number_args = 2;
      precedence = 2;
      associativity = Associativity::Left;
    } break;
    case Op::Equal: {
      number_args = 2;
      precedence = 2;
      associativity = Associativity::Left;
    } break;
    case Op::NotEqual: {
      number_args = 2;
      precedence = 2;
      associativity = Associativity::Left;
    } break;
    case Op::Greater: {
      number_args = 2;
      precedence = 2;
      associativity = Associativity::Left;
    } break;
    case Op::GreaterEqual: {
      number_args = 2;
      precedence = 2;
      associativity = Associativity::Left;
    } break;
    case Op::Less: {
      number_args = 2;
      precedence = 2;
      associativity = Associativity::Left;
    } break;
    case Op::LessEqual: {
      number_args = 2;
      precedence = 2;
      associativity = Associativity::Left;
    } break;
    case Op::Add: {
      number_args = 2;
      precedence = 3;
      associativity = Associativity::Left;
    } break;
    case Op::Subtract: {
      number_args = 2;
      precedence = 3;
      associativity = Associativity::Left;
    } break;
    case Op::Multiplication: {
      number_args = 2;
      precedence = 4;
      associativity = Associativity::Left;
    } break;
    case Op::Division: {
      number_args = 2;
      precedence = 4;
      associativity = Associativity::Left;
    } break;
    case Op::Power: {
      number_args = 2;
      precedence = 5;
      associativity = Associativity::Right;
    } break;
    case Op::Modulo: {
      number_args = 2;
      precedence = 4;
      associativity = Associativity::Left;
    } break;
    case Op::AtId: {
      number_args = 2;
      precedence = 8;
      associativity = Associativity::Left;
    } break;
    default: {
      precedence = 1;
      associativity = Associativity::Left;
    }
    }
  }

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class ExpressionListNode : public AstNode {
public:
  std::shared_ptr<ExpressionNode> root;

  explicit ExpressionListNode(): AstNode(0) {}
  explicit ExpressionListNode(size_t pos): AstNode(pos) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class StatementNode : public AstNode {
public:
  StatementNode(size_t pos): AstNode(pos) {}

  virtual void accept(NodeVisitor& v) const = 0;
};

class ForStatementNode : public StatementNode {
public:
  ExpressionListNode condition;
  BlockNode body;
  BlockNode* const parent;

  ForStatementNode(BlockNode* const parent, size_t pos): StatementNode(pos), parent(parent) {}

  virtual void accept(NodeVisitor& v) const = 0;
};

class ForArrayStatementNode : public ForStatementNode {
public:
  const std::string value;

  explicit ForArrayStatementNode(const std::string& value, BlockNode* const parent, size_t pos): ForStatementNode(parent, pos), value(value) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class ForObjectStatementNode : public ForStatementNode {
public:
  const std::string key;
  const std::string value;

  explicit ForObjectStatementNode(const std::string& key, const std::string& value, BlockNode* const parent, size_t pos)
      : ForStatementNode(parent, pos), key(key), value(value) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class IfStatementNode : public StatementNode {
public:
  ExpressionListNode condition;
  BlockNode true_statement;
  BlockNode false_statement;
  BlockNode* const parent;

  const bool is_nested;
  bool has_false_statement {false};

  explicit IfStatementNode(BlockNode* const parent, size_t pos): StatementNode(pos), parent(parent), is_nested(false) {}
  explicit IfStatementNode(bool is_nested, BlockNode* const parent, size_t pos): StatementNode(pos), parent(parent), is_nested(is_nested) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class IncludeStatementNode : public StatementNode {
public:
  const std::string file;

  explicit IncludeStatementNode(const std::string& file, size_t pos): StatementNode(pos), file(file) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

class ExtendsStatementNode : public StatementNode {
public:
  const std::string file;

  explicit ExtendsStatementNode(const std::string& file, size_t pos): StatementNode(pos), file(file) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  };
};

class BlockStatementNode : public StatementNode {
public:
  const std::string name;
  BlockNode block;
  BlockNode* const parent;

  explicit BlockStatementNode(BlockNode* const parent, const std::string& name, size_t pos): StatementNode(pos), name(name), parent(parent) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  };
};

class SetStatementNode : public StatementNode {
public:
  const std::string key;
  ExpressionListNode expression;

  explicit SetStatementNode(const std::string& key, size_t pos): StatementNode(pos), key(key) {}

  void accept(NodeVisitor& v) const {
    v.visit(*this);
  }
};

} // namespace inja

#endif // INCLUDE_INJA_NODE_HPP_
