#ifndef INCLUDE_INJA_STATISTICS_HPP_
#define INCLUDE_INJA_STATISTICS_HPP_

#include "node.hpp"

namespace inja {

/*!
 * \brief A class for counting statistics on a Template.
 */
class StatisticsVisitor : public NodeVisitor {
  void visit(const BlockNode& node) {
    for (auto& n : node.nodes) {
      n->accept(*this);
    }
  }

  void visit(const TextNode&) {}
  void visit(const ExpressionNode&) {}
  void visit(const LiteralNode&) {}

  void visit(const DataNode&) {
    variable_counter += 1;
  }

  void visit(const FunctionNode& node) {
    for (auto& n : node.arguments) {
      n->accept(*this);
    }
  }

  void visit(const ExpressionListNode& node) {
    node.root->accept(*this);
  }

  void visit(const StatementNode&) {}
  void visit(const ForStatementNode&) {}

  void visit(const ForArrayStatementNode& node) {
    node.condition.accept(*this);
    node.body.accept(*this);
  }

  void visit(const ForObjectStatementNode& node) {
    node.condition.accept(*this);
    node.body.accept(*this);
  }

  void visit(const IfStatementNode& node) {
    node.condition.accept(*this);
    node.true_statement.accept(*this);
    node.false_statement.accept(*this);
  }

  void visit(const IncludeStatementNode&) {}

  void visit(const ExtendsStatementNode&) {}

  void visit(const BlockStatementNode& node) {
    node.block.accept(*this);
  }

  void visit(const SetStatementNode&) {}

public:
  unsigned int variable_counter;

  explicit StatisticsVisitor(): variable_counter(0) {}
};

} // namespace inja

#endif // INCLUDE_INJA_STATISTICS_HPP_
