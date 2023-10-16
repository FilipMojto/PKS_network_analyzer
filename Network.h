#pragma once
#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <pcap.h>

namespace Network {
	enum class NetworkLayer {
		L_1, L_2, L_3, IEEE_L_3
	};

	enum class Protocol {
		TCP, ARP, ICMP, TFTP
	};

	enum class IPv4_Octet_Index {
		I1, I2, I3, I4
	};

	class Packet {

	public:
		static u_char* extract_TCP_header(const u_char* packet);

	};


	class IPv4 {
	public:
		static constexpr uint8_t OCTET_COUNT = 4;

	private:
		uint8_t octets[Network::IPv4::OCTET_COUNT];
	
	public:
		static constexpr uint8_t OCTET_MIN_VAL = 0;
		static constexpr uint8_t OCTET_MAX_VAL = 255;
		static constexpr char OCTET_DELIMITER = '.';
		

		static bool is_ipv4_octet(const uint8_t oct);

		uint8_t get_oct(const IPv4_Octet_Index index);
		void set_oct(const IPv4_Octet_Index index, const uint8_t oct);
		std::string get_str_rep() const;

		IPv4(const uint8_t oct_1, const uint8_t oct_2, const uint8_t oct_3, const uint8_t oct_4);
	};
}