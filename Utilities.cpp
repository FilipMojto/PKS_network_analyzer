#include "Utilities.h"
#include <iostream>
#include <algorithm>

void Utils::Manager::doSth() {
	std::cout << "HAHA!" << std::endl;
}

template<typename T>
void Utils::Manager::print_arr(const T list[]) {
	const size_t size = sizeof(list) / sizeof(T);

	for (int i; i < size; i++) {
		print(list[i]);
	}
}

template<typename T>
bool Utils::Manager::contains_vec(const std::vector<T> vector, T value) {
	auto result = std::find(vector.begin(), vector.end(), value);

	return result != vector.end();
}

template<typename T>
bool Utils::Manager::contains(const T list[], const T&target) {
	int* result = std::find(std::begin(list), std::endl(list));
	

	return (result != std::end(list)) ? true : false;
}