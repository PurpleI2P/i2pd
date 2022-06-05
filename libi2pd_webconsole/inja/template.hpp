#ifndef INCLUDE_INJA_TEMPLATE_HPP_
#define INCLUDE_INJA_TEMPLATE_HPP_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "node.hpp"
#include "statistics.hpp"

namespace inja {

/*!
 * \brief The main inja Template.
 */
struct Template {
  BlockNode root;
  std::string content;
  std::map<std::string, std::shared_ptr<BlockStatementNode>> block_storage;

  explicit Template() {}
  explicit Template(const std::string& content): content(content) {}

  /// Return number of variables (total number, not distinct ones) in the template
  int count_variables() {
    auto statistic_visitor = StatisticsVisitor();
    root.accept(statistic_visitor);
    return statistic_visitor.variable_counter;
  }
};

using TemplateStorage = std::map<std::string, Template>;

} // namespace inja

#endif // INCLUDE_INJA_TEMPLATE_HPP_
