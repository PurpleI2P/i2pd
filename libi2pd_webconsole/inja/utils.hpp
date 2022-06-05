#ifndef INCLUDE_INJA_UTILS_HPP_
#define INCLUDE_INJA_UTILS_HPP_

#include <algorithm>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>

#include "exceptions.hpp"

namespace inja {

namespace string_view {
inline std::string_view slice(std::string_view view, size_t start, size_t end) {
  start = std::min(start, view.size());
  end = std::min(std::max(start, end), view.size());
  return view.substr(start, end - start);
}

inline std::pair<std::string_view, std::string_view> split(std::string_view view, char Separator) {
  size_t idx = view.find(Separator);
  if (idx == std::string_view::npos) {
    return std::make_pair(view, std::string_view());
  }
  return std::make_pair(slice(view, 0, idx), slice(view, idx + 1, std::string_view::npos));
}

inline bool starts_with(std::string_view view, std::string_view prefix) {
  return (view.size() >= prefix.size() && view.compare(0, prefix.size(), prefix) == 0);
}
} // namespace string_view

inline SourceLocation get_source_location(std::string_view content, size_t pos) {
  // Get line and offset position (starts at 1:1)
  auto sliced = string_view::slice(content, 0, pos);
  std::size_t last_newline = sliced.rfind("\n");

  if (last_newline == std::string_view::npos) {
    return {1, sliced.length() + 1};
  }

  // Count newlines
  size_t count_lines = 0;
  size_t search_start = 0;
  while (search_start <= sliced.size()) {
    search_start = sliced.find("\n", search_start) + 1;
    if (search_start == 0) {
      break;
    }
    count_lines += 1;
  }

  return {count_lines + 1, sliced.length() - last_newline};
}

inline void replace_substring(std::string& s, const std::string& f, const std::string& t) {
  if (f.empty()) {
    return;
  }
  for (auto pos = s.find(f);            // find first occurrence of f
       pos != std::string::npos;        // make sure f was found
       s.replace(pos, f.size(), t),     // replace with t, and
       pos = s.find(f, pos + t.size())) // find next occurrence of f
  {}
}

} // namespace inja

#endif // INCLUDE_INJA_UTILS_HPP_
