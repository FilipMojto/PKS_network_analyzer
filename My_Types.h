#pragma once
#include <vector>
#include <string>

namespace MyTypes {

	//template <typename T, typename G>
	class Dictionary {
	public:
		std::vector<std::pair<std::string, std::string>> mappings;

	public:
		void insert(const std::string key, const std::string value);
		std::string get(const std::string key) const;
		std::string get(const int index) const;
		void remove(const std::string key);
	};
}