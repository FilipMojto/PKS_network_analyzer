#include "Network.h"
#include <stdexcept>
#include <iostream>

bool Network::IPv4::is_ipv4_octet(const uint8_t oct) {
	return oct >= OCTET_MIN_VAL and oct <= OCTET_MAX_VAL;
}

u_char* Network::Packet::extract_TCP_header(const u_char* packet) {

	//if () {

	//}

	return nullptr;
}


uint8_t Network::IPv4::get_oct(const IPv4_Octet_Index index) {
	if (index == IPv4_Octet_Index::I1) {
		return this->octets[0];
	}
	else if (index == IPv4_Octet_Index::I2) {
		return this->octets[1];
	}
	else if (index == IPv4_Octet_Index::I3) {
		return this->octets[2];
	}
	else if (index == IPv4_Octet_Index::I4) {
		return this->octets[3];
	}
}

void Network::IPv4::set_oct(const IPv4_Octet_Index index, const uint8_t oct) {
	if(!this->is_ipv4_octet(oct)){
		throw std::invalid_argument("Invalid IPv4 octet provided");
	}

	if (index == IPv4_Octet_Index::I1) {
		this->octets[0] = oct;
	}
	else if (index == IPv4_Octet_Index::I2) {
		this->octets[1] = oct;
	}
	else if (index == IPv4_Octet_Index::I3) {
		this->octets[2] = oct;
	}
	else if (index == IPv4_Octet_Index::I4) {
		this->octets[3] = oct;
	}
}

std::string Network::IPv4::get_str_rep() const{

	return std::to_string(this->octets[0]) + this->OCTET_DELIMITER + std::to_string(this->octets[1]) + this->OCTET_DELIMITER +
		std::to_string(this->octets[2]) + this->OCTET_DELIMITER + std::to_string(this->octets[3]);
}

Network::IPv4::IPv4(const uint8_t oct_1, const uint8_t oct_2, const uint8_t oct_3, const uint8_t oct_4) {
	if (!is_ipv4_octet(oct_1) or !is_ipv4_octet(oct_2) or !is_ipv4_octet(oct_3) or !is_ipv4_octet(oct_4)) {
		throw std::invalid_argument("Invalid IPv4 octet provided");
	}

	this->octets[0] = oct_1;
	this->octets[1] = oct_2;
	this->octets[2] = oct_3;
	this->octets[3] = oct_4;
}