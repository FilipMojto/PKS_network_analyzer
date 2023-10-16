#include "My_Types.h"

#include <string>

void MyTypes::Dictionary::insert(const std::string key, const std::string value) {
	this->mappings.push_back(std::make_pair(key, value));
}

std::string MyTypes::Dictionary::get(const std::string key) const {
	
	const int size = this->mappings.size();

	for (int i = 0; i < size; i++) {
		if (this->mappings.at(i).first == key) {
			return this->mappings.at(i).second;
		}
	}
	
	return "";
}

std::string MyTypes::Dictionary::get(const int index) const {
	return this->mappings.at(index).second;
}

void MyTypes::Dictionary::remove(const std::string key) {
	auto it = this->mappings.begin();

	while (it != this->mappings.end()) {
		if (it->first == key) {
			
			it = this->mappings.erase(it); // Remove the element and get the iterator to the next element
		}
		else {
			++it; // Move to the next element
		}
	}
}