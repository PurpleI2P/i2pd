#ifndef INCLUDE_INJA_FUNCTION_STORAGE_HPP_
#define INCLUDE_INJA_FUNCTION_STORAGE_HPP_

#include <string_view>
#include <vector>

namespace inja {

using Arguments = std::vector<const json*>;
using CallbackFunction = std::function<json(Arguments& args)>;
using VoidCallbackFunction = std::function<void(Arguments& args)>;

/*!
 * \brief Class for builtin functions and user-defined callbacks.
 */
class FunctionStorage {
public:
  enum class Operation {
    Not,
    And,
    Or,
    In,
    Equal,
    NotEqual,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    Add,
    Subtract,
    Multiplication,
    Division,
    Power,
    Modulo,
    AtId,
    At,
    Default,
    DivisibleBy,
    Even,
    Exists,
    ExistsInObject,
    First,
    Float,
    Int,
    IsArray,
    IsBoolean,
    IsFloat,
    IsInteger,
    IsNumber,
    IsObject,
    IsString,
    Last,
    Length,
    Lower,
    Max,
    Min,
    Odd,
    Range,
    Round,
    Sort,
    Upper,
    Super,
    Join,
    Callback,
    ParenLeft,
    ParenRight,
    None,
  };

  struct FunctionData {
    explicit FunctionData(const Operation& op, const CallbackFunction& cb = CallbackFunction {}): operation(op), callback(cb) {}
    const Operation operation;
    const CallbackFunction callback;
  };

private:
  const int VARIADIC {-1};

  std::map<std::pair<std::string, int>, FunctionData> function_storage = {
      {std::make_pair("at", 2), FunctionData {Operation::At}},
      {std::make_pair("default", 2), FunctionData {Operation::Default}},
      {std::make_pair("divisibleBy", 2), FunctionData {Operation::DivisibleBy}},
      {std::make_pair("even", 1), FunctionData {Operation::Even}},
      {std::make_pair("exists", 1), FunctionData {Operation::Exists}},
      {std::make_pair("existsIn", 2), FunctionData {Operation::ExistsInObject}},
      {std::make_pair("first", 1), FunctionData {Operation::First}},
      {std::make_pair("float", 1), FunctionData {Operation::Float}},
      {std::make_pair("int", 1), FunctionData {Operation::Int}},
      {std::make_pair("isArray", 1), FunctionData {Operation::IsArray}},
      {std::make_pair("isBoolean", 1), FunctionData {Operation::IsBoolean}},
      {std::make_pair("isFloat", 1), FunctionData {Operation::IsFloat}},
      {std::make_pair("isInteger", 1), FunctionData {Operation::IsInteger}},
      {std::make_pair("isNumber", 1), FunctionData {Operation::IsNumber}},
      {std::make_pair("isObject", 1), FunctionData {Operation::IsObject}},
      {std::make_pair("isString", 1), FunctionData {Operation::IsString}},
      {std::make_pair("last", 1), FunctionData {Operation::Last}},
      {std::make_pair("length", 1), FunctionData {Operation::Length}},
      {std::make_pair("lower", 1), FunctionData {Operation::Lower}},
      {std::make_pair("max", 1), FunctionData {Operation::Max}},
      {std::make_pair("min", 1), FunctionData {Operation::Min}},
      {std::make_pair("odd", 1), FunctionData {Operation::Odd}},
      {std::make_pair("range", 1), FunctionData {Operation::Range}},
      {std::make_pair("round", 2), FunctionData {Operation::Round}},
      {std::make_pair("sort", 1), FunctionData {Operation::Sort}},
      {std::make_pair("upper", 1), FunctionData {Operation::Upper}},
      {std::make_pair("super", 0), FunctionData {Operation::Super}},
      {std::make_pair("super", 1), FunctionData {Operation::Super}},
      {std::make_pair("join", 2), FunctionData {Operation::Join}},
  };

public:
  void add_builtin(std::string_view name, int num_args, Operation op) {
    function_storage.emplace(std::make_pair(static_cast<std::string>(name), num_args), FunctionData {op});
  }

  void add_callback(std::string_view name, int num_args, const CallbackFunction& callback) {
    function_storage.emplace(std::make_pair(static_cast<std::string>(name), num_args), FunctionData {Operation::Callback, callback});
  }

  FunctionData find_function(std::string_view name, int num_args) const {
    auto it = function_storage.find(std::make_pair(static_cast<std::string>(name), num_args));
    if (it != function_storage.end()) {
      return it->second;

      // Find variadic function
    } else if (num_args > 0) {
      it = function_storage.find(std::make_pair(static_cast<std::string>(name), VARIADIC));
      if (it != function_storage.end()) {
        return it->second;
      }
    }

    return FunctionData {Operation::None};
  }
};

} // namespace inja

#endif // INCLUDE_INJA_FUNCTION_STORAGE_HPP_
