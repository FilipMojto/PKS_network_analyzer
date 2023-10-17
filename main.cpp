#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <vector>
#include <stdexcept>
#include <bitset>
#include <memory>

#include "pcap.h"
#include "Network.h"
#include "My_Types.h"

// ------------- EXTERNAL FILE PATHS ---------------

#define PCAP_FILE_PATH "Protocols\\samples\\trace-26.pcap"
#define PARSER_FILE_PATH "parser\\packet_parser.py"
#define SCRIPT_INPUT_FILE_PATH "parser\\resources\\input.txt"
#define SCRIPT_OUTPUT_FILE_PATH "parser\\resources\\output.yml"

#define LSAPS_FILE_PATH "Protocols\\lsaps.txt"
#define L_3_FILE_PATH "Protocols\\layer_3.txt"
#define L_2_FILE_PATH "Protocols\\layer_2.txt"
#define L_1_FILE_PATH "Protocols\\layer_1.txt"
#define ICMP_TYPES_FILE_PATH "Protocols\\icmp_types.txt"

// ----- INPUT FILE CONFIGURATION AND MAPPED DATA STRUCTURES -----

//General file config
#define FILE_DELIMITER ' '
#define TOKEN_COUNT 3
#define PACKET_DELIMITER '!'
#define IPv4_STAT_DELIMITER '%'
#define TOP_IPV4_SENDERS_DELIMITER '&'

//Counts of external file data (records)
#define ETH_TYPE_COUNT 22
#define LSAP_COUNT 16
#define L_2_PROTOCOL_COUNT 13
#define L_1_PROTOCOL_COUNT 35
#define ICMP_TYPES_COUNT 16

//Protocol record can either be a ethernet type (pid) or some kind os LSAP (LLC service access protocol)
struct ProtocolRecord {
	uint16_t hex_value = 0;
	uint16_t dec_value = 0;
	std::string type_label = "";
};

enum class TCP_Flags {
	A, S, F, P, R, U
};

struct Request {
	std::vector<TCP_Flags> flags;
	MyTypes::Dictionary packet;
	std::string id;

	std::unique_ptr<u_char[]> seq_num;
	std::unique_ptr<u_char[]> ack_num;
	Request* prev = nullptr;
};

struct ICMP_Request {
	std::vector<Request> fragments;

};

struct UDP_Request {
	MyTypes::Dictionary packet;
	UDP_Request* prev = nullptr;
};

enum class CommunicationState {
	UNITIATED, INITIATED, COMPLETED
};

struct TCP_Comm {
	std::string src_comm;
	std::string dst_comm;
	CommunicationState state = CommunicationState::UNITIATED;

	std::vector<Request> requests;
};

struct ARP_Base {
	std::vector<Request> unreplied;
	std::vector<std::pair<Request, Request>> replied;
};

struct ICMP_Comm {
	std::string src_comm;
	std::string dst_comm;
	std::string id;

	std::vector<ICMP_Request> unreplied;
	std::vector<std::pair<ICMP_Request, ICMP_Request>> replied;
};

struct ICMP_Base {
	std::vector<ICMP_Comm> comms;
};

struct UDP_Comm {
	CommunicationState state = CommunicationState::UNITIATED;
	std::vector<UDP_Request> requests;
};

std::vector<TCP_Comm> TCP_comms;
std::vector<ARP_Base> ARP_comms;
ICMP_Base ICMP_comms;
std::vector<UDP_Comm> UDP_comms;

//Structure to hold value-type pairs defined in the external files
ProtocolRecord l_3_protocols[ETH_TYPE_COUNT];
ProtocolRecord l_2_protocols[L_2_PROTOCOL_COUNT];
ProtocolRecord l_1_protocols[L_1_PROTOCOL_COUNT];
ProtocolRecord lsaps[LSAP_COUNT];
ProtocolRecord icmp_types[ICMP_TYPES_COUNT];

std::unordered_map < std::string, u_int > IPv4Records;
std::vector <std::string> top_IPv4_senders;

// ------------- PREDEFINED VALUES ---------------


#define ETHER_II_NAME "ETHERNET II"
#define NOVELL_NAME "IEEE 802.3 RAW"
#define IEEE_NAME "IEEE 802.3 LLC"
#define IEEE_SNAP_NAME "IEEE 802.3 LLC & SNAP"

#define FIRST_DMAC_BYTE_INDEX 0
#define FIRST_SMAC_BYTE_INDEX 6
#define ETHER_II_MIN_VALUE 1500
#define IEEE_RAW_VALUE 65535
#define SNAP_VALUE 170
#define MIN_PACKET_LEN 64
#define IHL_UNIT_WEIGHT 4
#define IP_ADDR_OCTET_COUNT 4

#define OUTPUT_NAME "PKS2023/24"

struct ProtocolFilter {
	Network::NetworkLayer layer;
	std::string label;
};

int packetNo = 0;
ProtocolFilter* protocol_filter = nullptr;

std::ofstream packet_pointer;
std::ofstream fileStream;

enum class Protocol {
	L_3, L_3_SAP, L_2, L_1, ICMP
};

template<typename T>
bool contains_vec(const std::vector<T> vector, T value) {
	auto result = std::find(vector.begin(), vector.end(), value);

	return result != vector.end();
}

template<typename T>
bool contains_arr(const T* list, T value, const size_t size) {
	
	for (int i = 0; i < size; i++) {
		if (list[i] == value) {
			return true;
		}
	}
	
	return false;
}

/*
	This function loads all file rows to a passed array (list parameter) from an external file (filePath).
	The file rows must have the following structure:

	<key><FILE_DELIMITER><value>

	The key is a hex representation of a file record and value its string name. Also the function is dependent on FILE_DELIMITER macro
	by which we can configure splitting the rows.

	@param filePath -> An absolute or realative path to the source file.
	@param list -> A static array to load data to.
	@returns 0: if file was opened, read and closed successfully,
			 1: if file was not opened successfully
*/
int load_protocols(const std::string filePath, ProtocolRecord* list) {
	std::ifstream inputFile(filePath);

	if (!inputFile.is_open()) {
		std::cerr << "Failed to open the file." << std::endl;
		return 1;
	}

	std::string line;
	std::stringstream str_stream;
	std::string tokens[TOKEN_COUNT];

	int line_index = 0;

	while (std::getline(inputFile, line)) {
		str_stream.clear();
		str_stream.str(line);

		std::getline(str_stream, tokens[0], FILE_DELIMITER);
		std::getline(str_stream, tokens[1], FILE_DELIMITER);
		std::getline(str_stream, tokens[2], FILE_DELIMITER);

		str_stream.clear();
		str_stream.str(tokens[0]);


		list[line_index] = ProtocolRecord();

		str_stream >> std::hex >> list[line_index].hex_value;
		list[line_index].dec_value = std::stoi(tokens[1]);
		list[line_index].type_label = tokens[2];

		line_index++;
	}
	
	inputFile.close();
	return 0;
}

bool handle_IPv4_src(const Network::IPv4& ipv4) {
	auto iterator = IPv4Records.find(ipv4.get_str_rep());
	const auto end = IPv4Records.end();

	if (iterator != end) {
		iterator->second++;
		return false;
	}
	
	IPv4Records.insert(std::pair<std::string, int>(ipv4.get_str_rep(), 1));
	return true;
}

bool process_IPv4_records(const std::unordered_map<std::string, u_int>& records, std::ofstream& file_stream) {
	if (records.empty()) {
		return false;
	}
	
	file_stream << IPv4_STAT_DELIMITER << std::endl;

	auto iterator = records.begin();
	const auto end = records.end();
	std::vector<std::string> max;

	while (iterator != end) {
		file_stream << "node: " << iterator->first << std::endl;
		file_stream << "number_of_sent_packets: " << iterator->second << std::endl;

		if (max.empty()) {
			max.push_back(iterator->first);
		}
		else {
			const size_t vec_size = max.size();

			for (int i = 0; i < vec_size; i++) {
				if (records.at(max.at(i)) < iterator->second) {
					max.clear();
					max.push_back(iterator->first);
				}
				else if (records.at(max.at(i)) == iterator->second and max.at(i) != iterator->first) {
					max.push_back(iterator->first);
				}
			}
		}

		if (++iterator != end) {
			file_stream << IPv4_STAT_DELIMITER << std::endl;
		}
	}

	for (int i = 0; i < max.size(); i++) {
		file_stream << '&' << std::endl << max.at(i) << std::endl;
	}

	return true;
}

bool process_top_IPv4_senders(const std::vector<std::string>& senders, std::ofstream& file_stream) {
	if (senders.empty()) {
		return false;
	}

	file_stream << TOP_IPV4_SENDERS_DELIMITER << std::endl;
	const size_t size = senders.size();


	for (int i = 0; i < size; i++) {
		file_stream << senders.at(i) << std::endl;
	}

	return true;
}

/*
	The function assigns the corresponding structure to a hex value according to the loaded data in the static arrays.

	@param hex_val -> A value in hexadecimal form which is compared to the loaded data structures to find one.
	@param type -> An enum which specifies whether to look for EtherTypes or for LSAPS.
	@returns A pointer to a FileRecord data structure or nullptr if none  was found
*/
ProtocolRecord* get_protocol(const u_int hex_val, const Protocol type) {

	if (type == Protocol::L_3) {
		for (int i = 0; i < ETH_TYPE_COUNT; i++) {
			if (l_3_protocols[i].hex_value == hex_val) {
				return  &l_3_protocols[i];
			}
		}
	}
	else if (type == Protocol::L_3_SAP) {
		for (int i = 0; i < LSAP_COUNT; i++) {
			if (lsaps[i].hex_value == hex_val) {
				return  &lsaps[i];
			}
		}
	}
	else if (type == Protocol::L_2) {
		for (int i = 0; i < L_2_PROTOCOL_COUNT; i++) {
			if (l_2_protocols[i].hex_value == hex_val) {
				return &l_2_protocols[i];
			}
		}
	}
	else if (type == Protocol::L_1) {
		for (int i = 0; i < L_1_PROTOCOL_COUNT; i++) {
			if (l_1_protocols[i].hex_value == hex_val) {
				return &l_1_protocols[i];
			}
		}
	}
	else if (type == Protocol::ICMP) {
		for (int i = 0; i < ICMP_TYPES_COUNT; i++) {
			if (icmp_types[i].hex_value == hex_val) {
				return &icmp_types[i];
			}
		}
	}

	return nullptr;
}

ProtocolRecord* get_protocol_by_label(const std::string label, const Protocol type) {

	if (type == Protocol::L_3) {
		for (int i = 0; i < ETH_TYPE_COUNT; i++) {
			if (l_3_protocols[i].type_label == label) {
				return  &l_3_protocols[i];
			}
		}
	}
	else if (type == Protocol::L_3_SAP) {
		for (int i = 0; i < LSAP_COUNT; i++) {
			if (lsaps[i].type_label == label) {
				return  &lsaps[i];
			}
		}
	}
	else if (type == Protocol::L_2) {
		for (int i = 0; i < L_2_PROTOCOL_COUNT; i++) {
			if (l_2_protocols[i].type_label == label) {
				return &l_2_protocols[i];
			}
		}
	}
	else if (type == Protocol::L_1) {
		for (int i = 0; i < L_1_PROTOCOL_COUNT; i++) {
			if (l_1_protocols[i].type_label == label) {
				return &l_1_protocols[i];
			}
		}
	}

	return nullptr;
}

enum class MAC {
	DMAC, SMAC
};

/*
	The function simply extracts a MAC address from the passed packet bytes depending on MAC type.

	@param bytes -> A byte array to be converted.
	@param type -> An enum type of MAC to extract (DMAC or SMAC).
	@returns Extracted MAC address in string form.
*/
std::string get_packet_MAC(const u_char* bytes, const MAC type) {
	std::ostringstream oss;

	// Based on the type of MAC we either start at 0th (DMAC) or 6th (SMAC) index of the byte array
	const int t = (type == MAC::DMAC) ? FIRST_DMAC_BYTE_INDEX : FIRST_SMAC_BYTE_INDEX;

	for (int i = t; i < t + 6; i++) {
		//Neccessary steps to extract the proper format of MAC
		//At times the casted integer value equals 0 which must be filled with another 0
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);

		if (i < 5 + t) {
			oss << ':';
		}
	}

	return oss.str();
}

enum class IP {
	IPv4_SRC, IPv4_DST, ARP_SRC, ARP_DST
};

std::string extract_IP_addr(const u_char* bytes, const int start_index, const size_t end_index) {
	std::ostringstream oss;

	for (int i = start_index; i < end_index; i++) {
		oss << static_cast<int>(bytes[i]);

		if (i < end_index - 1) {
			oss << '.';
		}
	}

	return oss.str();
}

std::string get_packet_IP(const u_char* bytes, const IP ip_type) {
	const size_t IPv4_size = 4;
	u_short start_index = 0;

	switch (ip_type) {
	case IP::IPv4_SRC:
		start_index = 26;

		return extract_IP_addr(bytes, start_index, start_index + IPv4_size);
	case IP::IPv4_DST:
		start_index = 30;

		return extract_IP_addr(bytes, start_index, start_index + IPv4_size);
	case IP::ARP_SRC:
		start_index = 14 + 14;
		
		return extract_IP_addr(bytes, start_index, start_index + IPv4_size);
	case IP::ARP_DST:
		start_index = 38;

		return extract_IP_addr(bytes, start_index, start_index + IPv4_size);
	}

	return "";
}


/*
	This function converts a byte into its hexadecimal form.

	@param bytes -> The input array to be converted.
	@param size -> The size of the array.
	
	@returns A string hexa form where each byte is delimited by ' ' and its lenght is fixed at 2.
*/
std::string get_hexa_frame(const u_char* bytes, const int size) {
	std::ostringstream oss;
	
	for (int i = 0; i < size; i++) {

		//Similar steps to extracting MAC address in the prev. method.
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);

		if (i < size - 1) {
			oss << ' ';
		}
	}

	return oss.str();
}

/*
	This function writes the base data of a packet to a file using the global file stream. It follows the desired data formatting.
*/
int insert_base(MyTypes::Dictionary& dictionary, const u_int packet_no, const u_int frame_len, const u_int len_medium, const std::string frame_type, const std::string srcMAC, const std::string dstMAC,
	const std::string hexaFrame) {
	
	dictionary.insert("frame_number", std::to_string(packet_no));
	dictionary.insert("len_frame_pcap", std::to_string(frame_len));
	dictionary.insert("len_frame_medium", std::to_string(len_medium));
	dictionary.insert("frame_type", frame_type);
	dictionary.insert("src_mac", srcMAC);
	dictionary.insert("dst_mac", dstMAC);
	dictionary.insert("hexaframe", hexaFrame);

	return 0;
}

int get_ip_header_size(const u_char*& bytes) {
	return (bytes[14] & 0x0F) * IHL_UNIT_WEIGHT;
}



void process_dictionary(const MyTypes::Dictionary& dictionary) {
	fileStream << PACKET_DELIMITER << std::endl;

	auto cur = dictionary.mappings.begin();
	const auto end = dictionary.mappings.end();

	while (cur != end) {
		fileStream << cur->first << ": " << cur->second << std::endl;
		cur++;
	}
}


void extract_seq_num(const u_char* bytes,  u_char* bytes2) {
	const unsigned int seq_num_i = 14 + get_ip_header_size(bytes) + 4;

	for (int i = 0; i < 4; i++) {
		bytes2[i];

		bytes2[i] = bytes[seq_num_i + i];
	}
}

void extract_ack_num(const u_char* bytes, u_char* bytes2) {
	//u_char ack_num[4];
	const unsigned int ack_num_i = 14 + get_ip_header_size(bytes) + 8;


	for (int i = 0; i < 4; i++) {
		bytes2[i] = bytes[ack_num_i + i];
	}
}

bool compare_bytes(const u_char* bytes_1, const u_char* bytes_2, const size_t& size) {

	for (int i = 0; i < size; i++) {
		if (bytes_1[i] != bytes_2[i]) {
			return false;
		}
	}

	return true;
}


int increment_bytes(u_char* bytes, const size_t size) {

	for (size_t i = size; i > 0; i--) {
		bytes[i - 1]++;

		if (bytes[i - 1] != 0x00) {
			return 0;
		}
	}

	return -1;
}

int inc_bytes(const u_char* bytes, u_char* new_bytes, const size_t size) {

	for (int i = 0; i < size; i++) {
		new_bytes[i] = bytes[i];
	}

	for (size_t i = size; i > 0; i--) {

		new_bytes[i - 1]++;

		if (new_bytes[i - 1] != 0x00) {
			return 0;
		}
	}

	return -1;
}

std::unique_ptr<u_char[]> dec_bytes(const u_char* bytes, const size_t size) {
	std::unique_ptr<u_char[]> new_bytes = std::make_unique<u_char[]>(4);

	for (int i = 0; i < size; i++) {
		new_bytes[i] = bytes[i];
	}

	for (size_t i = size; i > 0; i--) {

		if (new_bytes[i - 1] != 0x00) {
			new_bytes[i - 1]--;
			return new_bytes;
		}

		new_bytes[i - 1] = 0xff;
	}

	return nullptr;
}

boolean is_initiated(const TCP_Comm& comm) {
	if (comm.requests.size() >= 3 and contains_vec(comm.requests.at(0).flags, TCP_Flags::S) and
		contains_vec(comm.requests.at(1).flags, TCP_Flags::S) and
		contains_vec(comm.requests.at(1).flags, TCP_Flags::A) and
		contains_vec(comm.requests.at(2).flags, TCP_Flags::A)) {
		return true;
	}

	return false;
}

boolean is_complete(const TCP_Comm& comm) {

	if (is_initiated(comm) and (
		
		(comm.requests.size() >= 7 and contains_vec(comm.requests.at(3).flags, TCP_Flags::F) and contains_vec(
		comm.requests.at(4).flags, TCP_Flags::A) and contains_vec(comm.requests.at(5).flags, TCP_Flags::F) and contains_vec(
			comm.requests.at(6).flags, TCP_Flags::A))
		
		or
		
		(comm.requests.size() == 6 and contains_vec(comm.requests.at(3).flags, TCP_Flags::F) and contains_vec(
			comm.requests.at(4).flags, TCP_Flags::A) and contains_vec(comm.requests.at(4).flags, TCP_Flags::F) and (contains_vec(
				comm.requests.at(5).flags, TCP_Flags::A) or contains_vec(comm.requests.at(5).flags, TCP_Flags::R)))
		or

		contains_vec(comm.requests.back().flags, TCP_Flags::R))){

		return true;
	}

	return false;
}

boolean detect_state_change(TCP_Comm& communication) {
	const size_t size = communication.requests.size();

	if (communication.state == CommunicationState::UNITIATED and is_initiated(communication)) {
		communication.state = CommunicationState::INITIATED;
		return true;
	}
	else if (communication.state == CommunicationState::INITIATED and is_complete(communication)) {
		communication.state = CommunicationState::COMPLETED;
		return true;
	}

	return false;
}

void extract_tcp_flags(const u_char* bytes, bool* bits) {
	const unsigned int flags_index = 14 + get_ip_header_size(bytes) + 13;

	for (int i = CHAR_BIT - 1; i >= 0; i--) {
		u_char bit = (bytes[flags_index] & (1 << i)) != 0;
		bits[CHAR_BIT - 1 - i] = static_cast<bool>(bit);
	}
}

boolean is_req_acknowledged(Request& ack_request, Request& test_req) {
	const auto dec_ack_copy = dec_bytes(ack_request.ack_num.get(), 4);

	if (compare_bytes(dec_ack_copy.get(), test_req.seq_num.get(), 4) and
		ack_request.packet.get("src_ip") == test_req.packet.get("dst_ip") and
		ack_request.packet.get("src_port") == test_req.packet.get("dst_port")) {
		return true;
	}

	return false;
}

boolean attach_request( const u_char* bytes, Request& request, std::vector<TCP_Comm>& communications) {
	const size_t size = communications.size();
	
	for (size_t i = 0; i < size; i++) {
		
		if(is_req_acknowledged(request, communications.at(i).requests.back())){

			if (!communications.at(i).requests.empty()) {
				request.prev = &communications.at(i).requests.back();
			}

			communications.at(i).requests.push_back(std::move(request));
			detect_state_change(communications.at(i));
			return true;
		}

		//Attaching FIN requests
		else {
			bool bits[CHAR_BIT];
			extract_tcp_flags(bytes, bits);

			if ((bits[5] or bits[7]) and communications.at(i).state == CommunicationState::INITIATED) {

				if (((request.packet.get("src_ip") == communications.at(i).src_comm and request.packet.get("dst_ip") == communications.at(i).dst_comm) or
					(request.packet.get("src_ip") == communications.at(i).dst_comm and request.packet.get("dst_ip") == communications.at(i).src_comm))
					
					and ((request.packet.get("src_port") == communications.at(i).requests.at(0).packet.get("src_port")
					and	request.packet.get("dst_port") == communications.at(i).requests.at(0).packet.get("dst_port"))
						or
						((request.packet.get("src_port") == communications.at(i).requests.at(0).packet.get("dst_port")
							and request.packet.get("dst_port") == communications.at(i).requests.at(0).packet.get("src_port"))))
					){

						if (!communications.at(i).requests.empty()) {
							request.prev = &communications.at(i).requests.back();

						}

						communications.at(i).requests.push_back(std::move(request));
						detect_state_change(communications.at(i));
						return true;
				}
			}
		}
	}

	return false;
}

void make_request(const u_char* bytes, const MyTypes::Dictionary& dictionary, Request& request) {
	u_char seq[4], ack[4];

	extract_seq_num(bytes, seq);
	extract_ack_num(bytes, ack);
	
	request. seq_num = std::make_unique<u_char[]>(4);
	request.ack_num = std::make_unique<u_char[]>(4);

	memcpy(request.seq_num.get(), seq, sizeof(seq));
	memcpy(request.ack_num.get(), ack, sizeof(ack));

	request.packet = dictionary;
}

void add_new_arp_comm(std::vector<ARP_Base>& comms, Request& request) {
	ARP_Base base;

	base.unreplied.push_back(std::move(request));
	comms.push_back(std::move(base));
}

bool process_arp_req(std::vector<ARP_Base>& arp_comms, const MyTypes::Dictionary& dictionary) {
	Request request;
	request.packet = dictionary;

	if (arp_comms.empty()) {
		add_new_arp_comm(arp_comms, request);
		return true;
	}

	if (dictionary.get("arp_opcode") == "REQUEST") {
		const u_int size = arp_comms.size();

		for (u_int i = 0; i < size; i++) {
			if ((arp_comms.at(i).replied.empty() /* and arp_comms.at(i).unreplied.begin()->packet.get("src_ip") == dictionary.get("src_ip") */
				and arp_comms.at(i).unreplied.begin()->packet.get("dst_ip") == dictionary.get("dst_ip"))
				or
				(arp_comms.at(i).unreplied.empty() /* and arp_comms.at(i).replied.begin()->first.packet.get("src_ip") == dictionary.get("src_ip")*/
				and arp_comms.at(i).replied.begin()->first.packet.get("dst_ip") == dictionary.get("dst_ip"))) {

				arp_comms.at(i).unreplied.push_back(std::move(request));
				return true;
			}
		}

		add_new_arp_comm(arp_comms, request);
		return true;
	}
	else if (dictionary.get("arp_opcode") == "REPLY") {
		const u_int size = arp_comms.size();
		
		for (int i = 0; i < size; i++) {
			bool state = false;
			const u_int req_size = arp_comms.at(i).unreplied.size();

			Request request;
			request.packet = dictionary;

			auto cur_unreplied = arp_comms.at(i).unreplied.end();
			auto const un_start = arp_comms.at(i).unreplied.begin();

			while (cur_unreplied != un_start) {
				cur_unreplied--;

				if ((cur_unreplied->packet.get("src_ip") == dictionary.get("dst_ip") and cur_unreplied->packet.get("dst_ip") == dictionary.get("src_ip"))
					and cur_unreplied->packet.get("arp_opcode") == "REQUEST") {
					arp_comms.at(i).replied.push_back(std::make_pair(std::move(*cur_unreplied), std::move(request)));

					arp_comms.at(i).unreplied.erase(cur_unreplied);
					return true;
				}
				else if (cur_unreplied->packet.get("src_ip") == dictionary.get("src_ip") and cur_unreplied->packet.get("dst_ip") == dictionary.get("dst_ip")) {
					state = true;
				}
			}

			if (state) {
				arp_comms.at(i).unreplied.push_back(std::move(request));
				return true;
			}
		}
	
		add_new_arp_comm(arp_comms, request);
		return true;
	}
	else {
		std::cerr << "Invalid ARP opcode value!" << std::endl;
		return false;
	}

	return false;
}


bool is_part_of_icmp_comm(const MyTypes::Dictionary& dic, const ICMP_Comm& comm) {

	if ( (comm.src_comm == dic.get("src_ip") or (comm.dst_comm == dic.get("src_ip")) ) and dic.get("icmp_id") == comm.id) {
		return true;
	}

	return false;
}

ICMP_Comm create_new_icmp_comm(const MyTypes::Dictionary& dic) {
	ICMP_Request request;
	Request fragment;

	fragment.packet = dic;
	fragment.id = dic.get("id");

	request.fragments.push_back(std::move(fragment));

	ICMP_Comm comm;
	comm.id = dic.get("icmp_id");
	comm.src_comm = dic.get("src_ip");
	comm.dst_comm = dic.get("dst_ip");
	comm.unreplied.push_back(std::move(request));

	return comm;
}

bool attach_frag(std::vector<ICMP_Request>& comm, const MyTypes::Dictionary& dic) { 
	u_int cur_size = comm.size();

	for (u_int g = 0; g < cur_size; g++) {
		if (comm.at(g).fragments.back(). packet.get("src_ip") == dic.get("src_ip")
			and comm.at(g).fragments.back().packet.get("dst_ip") == dic.get("dst_ip")
			and comm.at(g).fragments.back().packet.get("id") == dic.get("id")) {

			Request request;
			request.packet = dic;
			request.id = dic.get("icmp_seq");
			
			comm.at(g).fragments.push_back(std::move(request));
			return true;
		}
	}

	return false;
}

bool attach_rep_frag(std::vector<std::pair<ICMP_Request, ICMP_Request>>& comm, const MyTypes::Dictionary& dic) {
	u_int cur_size = comm.size();

	for (u_int g = 0; g < cur_size; g++) {
		if (comm.at(g).second.fragments.back().packet.get("src_ip")
			== dic.get("src_ip")
			and comm.at(g).second.fragments.back().packet.get("dst_ip")
			== dic.get("dst_ip") and comm.at(g).second.fragments.back()
			.packet.get("id") == dic.get("id")) {

			Request request;
			request.packet = dic;
			request.id = dic.get("icmp_seq");

			comm.at(g).second.fragments.push_back(std::move(request));
			return true;
		}
	}

	return false;
}

bool process_icmp_req(ICMP_Base& icmp_base, const MyTypes::Dictionary& dictionary) {
	const u_int size = icmp_base.comms.size();

	if (dictionary.get("icmp_type") == "Destination_unreachable"){
		ICMP_Request request;
		Request fragment;

		fragment.packet = dictionary;
		fragment.id = dictionary.get("icmp_seq");

		request.fragments.push_back(std::move(fragment));

		for (u_int i = 0; i < size; i++) {
			if (is_part_of_icmp_comm(dictionary, icmp_base.comms.at(i))) {
				icmp_base.comms.at(i).unreplied.push_back(std::move(request));
				return true;
			}
		}

		auto new_comm = create_new_icmp_comm(dictionary);

		icmp_base.comms.push_back(std::move(new_comm));
		return true;
	}
	else if (dictionary.get("icmp_type") == "UNKNOWN") {

		for (u_int i = 0; i < size; i++) {
			
			if (attach_frag(icmp_base.comms.at(i).unreplied, dictionary)
				or
				attach_rep_frag(icmp_base.comms.at(i).replied, dictionary)) {
				return true;
			}
		}
	}
	else {
		int com_i = -1;

		for (u_int i = 0; i < size; i++) {
			const u_int req_size = icmp_base.comms.at(i).unreplied.size();

			if (is_part_of_icmp_comm(dictionary, icmp_base.comms.at(i))) {
				com_i = i;
			}
			
			auto cur = icmp_base.comms.at(i).unreplied.begin();
			auto const end = icmp_base.comms.at(i).unreplied.end();

			while (cur != end) {
				if (cur->fragments.begin()->packet.get("icmp_type") == "ECHO_REQUEST" and
					cur->fragments.begin()->packet.get("icmp_seq") == dictionary.get("icmp_seq")) {

					ICMP_Request request;

					Request fragment;
					fragment.id = dictionary.get("icmp_id");
					fragment.packet = dictionary;
					
					request.fragments.push_back(std::move(fragment));

					icmp_base.comms.at(i).replied.push_back(std::make_pair(std::move(*cur), std::move(request)));
					icmp_base.comms.at(i).unreplied.erase(cur);
					return true;
				}

				cur++;
			}
		}

		if (com_i > -1) {
			ICMP_Request request;
			Request fragment;

			fragment.packet = dictionary;
			fragment.id = dictionary.get("icmp_seq");

			request.fragments.push_back(std::move(fragment));

			icmp_base.comms.at(com_i).unreplied.push_back(std::move(request));
			return true;
		}
		else{
			ICMP_Comm comm = create_new_icmp_comm(dictionary);

			icmp_base.comms.push_back(std::move(comm));
			return true;
		}
	}

	return false;
}

bool equals(const u_char* arr, const u_char* arr2, const u_int size) {

	for (u_int i = 0; i < size; i++) {
		if (arr[i] != arr2[i]) {
			return false;
		}
	}

	return true;
}

bool is_req_present(const Request& request, const std::vector<TCP_Comm>& comms) {
	const u_int comms_size = comms.size();

	for (u_int i = 0; i < comms_size; i++) {

		const u_int req_size = comms.at(i).requests.size();

		for (u_int g = 0; g < req_size; g++) {
			if (equals(request.seq_num.get(), comms.at(i).requests.at(g).seq_num.get(), 4) and
				equals(request.ack_num.get(), comms.at(i).requests.at(g).ack_num.get(), 4) and
				request.packet.get("src_ip") == comms.at(i).requests.at(g).packet.get("src_ip") and
				request.packet.get("dst_ip") == comms.at(i).requests.at(g).packet.get("dst_ip") and
				request.packet.get("src_port") == comms.at(i).requests.at(g).packet.get("src_port") and
				request.packet.get("dst_port") == comms.at(i).requests.at(g).packet.get("dst_port")) {
				return true;
			}
		}
	}

	return false;
}

UDP_Request* find_prev_req(UDP_Comm& comm, const MyTypes::Dictionary& dic) {

	const u_int size = comm.requests.size();

	for (u_int i = size - 1; i > 0; i--) {

		if (dic.get("src_ip") == comm.requests.at(i).packet.get("src_ip")
			and dic.get("dst_ip") == comm.requests.at(i).packet.get("dst_ip")) {

			return &comm.requests.at(i);
		}
	}

	return nullptr;
}

void attach_tftp_req(UDP_Comm& comm, UDP_Request& request) {
	comm.requests.push_back(request);
	comm.requests.back().prev = &comm.requests.at(comm.requests.size() - 2);
}

bool process_tftp_req(std::vector<UDP_Comm>& comms, const MyTypes::Dictionary& packet) {
		
	if (packet.get("dst_port") == "69") {
		UDP_Request request;
		request.packet = packet;

		UDP_Comm new_comm;
		new_comm.requests.push_back(request);

		comms.push_back(new_comm);
		return true;
	}
	else {
		const u_int comm_size = comms.size();

		for (u_int i = 0; i < comm_size; i++) {

			if (comms.at(i).state != CommunicationState::COMPLETED and (( (comms.at(i).requests.back().packet.get("src_ip") == packet.get("dst_ip") and
				comms.at(i).requests.back().packet.get("dst_ip") == packet.get("src_ip")))
				or ((comms.at(i).requests.back().packet.get("src_ip") == packet.get("src_ip") and
					comms.at(i).requests.back().packet.get("dst_ip") == packet.get("dst_ip")) ))
				) {

				UDP_Request request;
				request.packet = packet;

				if (comms.at(i).requests.size() == 1 or comms.at(i).requests.size() == 2) {
					attach_tftp_req(comms.at(i), request);

					return true;
				}
				else if (comms.at(i).requests.size() > 2) {
					auto prev = find_prev_req(comms.at(i), packet);

					try {
						if (prev->packet.get("length") == packet.get("length")) {
							attach_tftp_req(comms.at(i), request);
							
							if (comms.at(i).state == CommunicationState::INITIATED) {
								comms.at(i).state = CommunicationState::COMPLETED;
							}

							return true;
						}
						else if (std::stoi(prev->packet.get("length")) > std::stoi(packet.get("length"))) {
							attach_tftp_req(comms.at(i), request);
							comms.at(i).state = CommunicationState::INITIATED;
							return true;
						}
						else if (std::stoi(prev->packet.get("length")) < std::stoi(packet.get("length"))) {
							attach_tftp_req(comms.at(i), request);
							comms.at(i).state = CommunicationState::COMPLETED;
							return true;
						}
					}
					catch (const std::out_of_range& e) {
						std::cerr << "Error: " << e.what() << std::endl;
					}
				}
			}
		}
	}

	return false;
}

bool is_part_of_tcp_comm(const TCP_Comm& comm, const MyTypes::Dictionary& dic) {
	if (
		comm.requests.at(0).packet.get("src_port") == dic.get("src_port") and
		comm.requests.at(0).packet.get("dst_port") == dic.get("dst_port") and
		(comm.src_comm == dic.get("src_ip") and comm.dst_comm == dic.get("dst_ip") || (
			comm.dst_comm == dic.get("src_ip") and comm.src_comm == dic.get("dst_ip")))
		and comm.state == CommunicationState::UNITIATED) {
		return true;
	}
		return false;
}

bool process_tcp_req(std::vector<TCP_Comm>& comms, const MyTypes::Dictionary& dic, const u_char* bytes) {
	std::string tcp_protocols[] = { "TCP", "HTTP", "HTTPS", "TELNET", "SSH", "FTP-CONTROL", "FTP-DATA" };

	if (!contains_arr(tcp_protocols, protocol_filter->label, 7)) {
		return false;
	}

	//const unsigned int flags_index = 14 + get_ip_header_size(bytes) + 13;
	bool bits[CHAR_BIT];

	extract_tcp_flags(bytes, bits);

	//Handling SYN
	if (bits[3] == 0 and bits[6] == 1) {
		Request request;
		request.flags.push_back(TCP_Flags::S);
		make_request(bytes, dic, request);

		if (is_req_present(request, TCP_comms)) {
			return false;
		}

		const int size = TCP_comms.size();
		TCP_Comm communication;

		communication.src_comm = get_packet_IP(bytes, IP::IPv4_SRC);
		communication.dst_comm = get_packet_IP(bytes, IP::IPv4_DST);

		bool repeat = false;

		//We must first check, if the SYN packet isnt already included in some of the communications
		if (!TCP_comms.empty()) {
			for (int i = 0; i < size; i++) {

				if (is_part_of_tcp_comm(TCP_comms.at(i), dic)) {
					communication = std::move(TCP_comms.at(i));
					repeat = true;
				}
			}
		}

		communication.requests.push_back(std::move(request));

		if (!repeat) {
			comms.push_back(std::move(communication));
		}
	}

	//Handling SYN+ACK
	else if (bits[3] == 1 and bits[6] == 1) {
		Request request;
		request.flags.push_back(TCP_Flags::S);
		request.flags.push_back(TCP_Flags::A);

		make_request(bytes, dic, request);

		if (!attach_request(bytes, request, TCP_comms)) {
			std::cout << "UNABLE TO FIND THE INITIALIZER!" << std::endl;
		}
	} //Handling ack

	else if (bits[3] == 1 and bits[5] == 0 and bits[7] == 0) {
		Request request;
		make_request(bytes, dic, request);
		request.flags.push_back(TCP_Flags::A);

		if (!attach_request(bytes, request, TCP_comms)) {
			std::cout << "UNABLE TO FIND THE INITIALIZER ACK!" << std::endl;
		}
	} // Handlings RST or FIN
	else if (bits[3] == 1 or bits[5] == 1 or bits[7] == 0) {
		Request request;

		make_request(bytes, dic, request);

		if (bits[3] == 1) {
			request.flags.push_back(TCP_Flags::A);
		}

		if (bits[5] == 1) {

			request.flags.push_back(TCP_Flags::R);
		}
		else if (bits[7] == 1) {
			request.flags.push_back(TCP_Flags::F);
		}

		if (!attach_request(bytes, request, TCP_comms)) {
			std::cout << "UNABLE TO FIND THE INITIALIZER ACK!" << std::endl;
		}
	}
}

bool process_request(std::vector<TCP_Comm>& comms,  MyTypes::Dictionary& dictionary, const u_char* bytes, const Network::Protocol& protocol) {

	if (protocol == Network::Protocol::TCP){
		process_tcp_req(TCP_comms, dictionary, bytes);
	}
	else if (protocol == Network::Protocol::ARP) {
		process_arp_req(ARP_comms, dictionary);
	}
	else if (protocol == Network::Protocol::ICMP) {
		process_icmp_req(ICMP_comms, dictionary);
	}
	else if (protocol == Network::Protocol::TFTP) {
		process_tftp_req(UDP_comms, dictionary);
	}

	auto b = 0;
	return false;
}

void process_dictionaries(const TCP_Comm& comm) {
	const int req_size = comm.requests.size();

	for (int g = 0; g < req_size; g++) {
		process_dictionary(comm.requests.at(g).packet);
	}
}


void process_comms(const Network::Protocol& protocol) {

	if (protocol == Network::Protocol::TCP) {

		const int size = TCP_comms.size();
		const TCP_Comm* incomplete = nullptr;

		for (int i = 0; i < size; i++) {

			if (TCP_comms.at(i).state == CommunicationState::COMPLETED) {

				fileStream << '?' << std::endl;
				fileStream << "number_comm: " << i + 1 << std::endl;
				fileStream << "src_com: " << TCP_comms.at(i).src_comm << std::endl;
				fileStream << "dst_com: " << TCP_comms.at(i).dst_comm << std::endl;

				process_dictionaries(TCP_comms.at(i));
			}
			else {
				if (incomplete == nullptr) {
					incomplete = &TCP_comms.at(i);
				}
			}
		}

		if (incomplete) {
			fileStream << '*' << std::endl;
			fileStream << "number_comm: 1" << std::endl;

			process_dictionaries((*incomplete));
		}
	}
	else if (protocol == Network::Protocol::ARP) {
		u_int size = ARP_comms.size();

		for (u_int i = 0; i < size; i++) {

			if (ARP_comms.at(i).replied.empty()) {
				continue;
			}

			fileStream << '?' << std::endl;
			fileStream << "number_comm: " << i + 1 << std::endl;

			u_int req_size = ARP_comms.at(i).replied.size();

			for (u_int g = 0; g < req_size; g++) {
				
				process_dictionary(ARP_comms.at(i).replied.at(g).first.packet);
				process_dictionary(ARP_comms.at(i).replied.at(g).second.packet);
			}
		}
		
		int present = 0;

		//fileStream << '*' << std::endl;

		for (u_int i = 0; i < size; i++) {
			if (ARP_comms.at(i).unreplied.empty()) {
				continue;
			}

			if (!present) {
				fileStream << '*' << std::endl;
			}
			present = 1;
			fileStream << '?' << std::endl;
			fileStream << "number_comm: " << i + 1 << std::endl;

			u_int req_size = ARP_comms.at(i).unreplied.size();

			for (u_int g = 0; g < req_size; g++) {
				process_dictionary(ARP_comms.at(i).unreplied.at(g).packet);
			}
		}
	}
	else if (protocol == Network::Protocol::ICMP) {
		const u_int size = ICMP_comms.comms.size();

		for (u_int i = 0; i < size; i++) {

			if (!ICMP_comms.comms.at(i).unreplied.empty()) {
				continue;
			}

			fileStream << '?' << std::endl;
			fileStream << "number_comm: " << i + 1 << std::endl;
			fileStream << "src_comm: " << ICMP_comms.comms.at(i).src_comm << std::endl;
			fileStream << "dst_comm: " << ICMP_comms.comms.at(i).dst_comm << std::endl;

			const u_int req_size = ICMP_comms.comms.at(i).replied.size();

			for (u_int g = 0; g < req_size; g++) {

				u_int frag_size = ICMP_comms.comms.at(i).replied.at(g).first.fragments.size();

				for (u_int j = 0; j < frag_size; j++) {
					process_dictionary(ICMP_comms.comms.at(i).replied.at(g).first.fragments.at(j).packet);
				}

				frag_size = ICMP_comms.comms.at(i).replied.at(g).second.fragments.size();

				for (u_int j = 0; j < frag_size; j++) {
					process_dictionary(ICMP_comms.comms.at(i).replied.at(g).second.fragments.at(j).packet);
				}
			}
		}
		
		bool unreplied = 0;

		for (u_int i = 0; i < size; i++) {
			if (!ICMP_comms.comms.at(i).unreplied.empty()) {
				unreplied = 1;
				break;
			}
		}

		if (!unreplied) {
			return;
		}

		fileStream << '*' << std::endl;

		for (u_int i = 0; i < size; i++) {
			if (ICMP_comms.comms.at(i).unreplied.empty()) {
				continue;
			}

			fileStream << '?' << std::endl;
			fileStream << "number_comm: " << i + 1 << std::endl;
			
			const u_int unreplied_size = ICMP_comms.comms.at(i).unreplied.size();

			for (u_int g = 0; g < unreplied_size; g++) {
				const u_int frag_size = ICMP_comms.comms.at(i).unreplied.at(g).fragments.size();

				for (u_int j = 0; j < frag_size; j++) {
					process_dictionary(ICMP_comms.comms.at(i).unreplied.at(g).fragments.at(j).packet);
				}
			}
		}
	}
	else if (protocol == Network::Protocol::TFTP) {
		const u_int size = UDP_comms.size();

		for (u_int i = 0; i < size; i++) {
			fileStream << '?' << std::endl;
			fileStream << "number_comm: " << i + 1 << std::endl;

			u_int req_size = UDP_comms.at(i).requests.size();

			for (u_int g = 0; g < req_size; g++) {
				process_dictionary(UDP_comms.at(i).requests.at(g).packet);
			}
		}
	}
}

std::string get_ARP_opcode(const u_char* bytes) {
	const unsigned int protocol_index = 20;
	
	u_int a = bytes[protocol_index + 1];

	if (a == 1) {
		return "REQUEST";
	}
	else if (a == 2) {
		return "REPLY";
	}
	
	return "";
}

u_int extract_icmp_identifier(const u_char* bytes) {
	const u_int id_i = 14 + get_ip_header_size(bytes) + 4;
	
	return ((bytes[id_i] << 8) | bytes[id_i + 1]);
}

u_int extract_icmp_seq(const u_char* bytes) {
	const u_int id_i = 14 + get_ip_header_size(bytes) + 6;

	return ((bytes[id_i] << 8) | bytes[id_i + 1]);
}

bool is_fragmented(const u_char* bytes) {
	const u_int id_i = 14 + 4, flags_i = 14 + 6;
	
	std::bitset<8> bits(bytes[flags_i]);
	std::bitset<8> bits2(bytes[flags_i + 1]);
	
	u_int off = ((bytes[id_i] << 8) | bytes[id_i + 1]);

	if (bits[6] == 1 or (bits[5] == 0 and bits2.to_ulong() == 0)) {
		return false;
	}

	return true;
}

/*
	This function is executed at every iteration of reading all packets captured in the file. It contains the logic of
	determining the packet frame and further data.

	@param temp1 Unneccessary parameter which is ignored
	@param header A header structure containing some information about obtained packet.
	@param pkt_bytes A byte sequence containing the captured bytes of the packet.
*/
void handlePacket(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_bytes) {
	(VOID)temp1;
	const u_int header_len = header->caplen, media_len = max(header_len + 4, MIN_PACKET_LEN);

	packetNo++;

	const u_int packetValue = ((pkt_bytes[12] << 8) | pkt_bytes[13]);

	MyTypes::Dictionary dictionary;
	int filter_i = (protocol_filter) ? 0 : -1;

	////The very logic of determining the packet type and writing the obligatory data to a text file
	////Handling Ether II packets
	if (packetValue >= ETHER_II_MIN_VALUE) {
		ProtocolRecord* rec_p = get_protocol(packetValue, Protocol::L_3);
	
		//We first must check whether there was any protocol found
		if (rec_p == nullptr) {
			std::cerr << "Unable to identify packet " << packetNo << '.' << std::endl;
			return;
		}

		if (filter_i == 0 and rec_p->type_label == protocol_filter->label) {
			filter_i = 1;
		}

		insert_base(dictionary, packetNo, header_len, media_len, ETHER_II_NAME, get_packet_MAC(pkt_bytes, MAC::SMAC), get_packet_MAC(pkt_bytes, MAC::DMAC), get_hexa_frame(pkt_bytes, header_len));
		
		dictionary.insert("ether_type", rec_p->type_label);


		if (rec_p->type_label == "IPv4") {

			if (filter_i == 0 and rec_p->type_label == protocol_filter->label) {
				filter_i = 1;
			}
	
			dictionary.insert("src_ip", get_packet_IP(pkt_bytes, IP::IPv4_SRC));
			dictionary.insert("dst_ip", get_packet_IP(pkt_bytes, IP::IPv4_DST));

			std::string protocol = get_protocol(pkt_bytes[23], Protocol::L_2)->type_label;
			dictionary.insert("protocol", protocol);
			if (protocol == "TCP" || protocol == "UDP") {

				if (filter_i == 0 and protocol == protocol_filter->label) {
					filter_i = 1;
				}

				const u_int ip_header_size = get_ip_header_size(pkt_bytes);
				const u_char src_port = ((pkt_bytes[14 + ip_header_size] << 8) | pkt_bytes[14 + ip_header_size + 1]),
					         dst_port = ((pkt_bytes[14 + ip_header_size + 2] << 8) | pkt_bytes[14 + ip_header_size + 3]);

				dictionary.insert("src_port", std::to_string(src_port));
				dictionary.insert("dst_port", std::to_string(dst_port));

				rec_p = get_protocol(src_port, Protocol::L_1);

				if (protocol_filter and protocol_filter->label == "TFTP") {
					filter_i = 1;
				}
				if (rec_p != nullptr) {
					dictionary.insert("app_protocol", rec_p->type_label);
				}
				else {
					rec_p = get_protocol(dst_port, Protocol::L_1);

					if (rec_p != nullptr) {
						dictionary.insert("app_protocol", rec_p->type_label);
					}
				}

				if (protocol == "UDP") {
					const u_short  len_i = 14 + get_ip_header_size(pkt_bytes) + 4;
					dictionary.insert("length", std::to_string(((pkt_bytes[len_i] << 8) | pkt_bytes[len_i + 1])));
				}
			}
			else if (protocol == "ICMP" and (protocol_filter == nullptr or protocol_filter->label == "ICMP")) {
				filter_i = 1;
				const u_int icmp_type_i = 14 + get_ip_header_size(pkt_bytes);


				rec_p = get_protocol(pkt_bytes[icmp_type_i], Protocol::ICMP);
				
				if (rec_p == nullptr) {
					dictionary.insert("icmp_type", "UNKNOWN");
				}
				else {
					dictionary.insert("icmp_type", rec_p->type_label);
				}
				
				dictionary.insert("icmp_id", std::to_string(extract_icmp_identifier(pkt_bytes)));
				dictionary.insert("icmp_seq", std::to_string(extract_icmp_seq(pkt_bytes)));

				if (is_fragmented(pkt_bytes)) {
					const u_int id_i = 14 + 4;

					dictionary.insert("id", std::to_string((pkt_bytes[id_i] << 8) | pkt_bytes[id_i + 1]));
					dictionary.insert("flags_mf", std::to_string(std::bitset<3>(pkt_bytes[id_i + 2] >> 5)[0]));
					dictionary.insert("frag_offset", std::to_string(std::bitset<13>(((pkt_bytes[id_i + 2] << 8) | pkt_bytes[id_i + 3]) & 0x1FFF)
						.to_ulong()));
				}
			}

			handle_IPv4_src(Network::IPv4(pkt_bytes[26], pkt_bytes[27], pkt_bytes[28], pkt_bytes[29]));
		}
		else if (rec_p->type_label == "ARP") {
			const std::string haah = "ARxP";

			if (filter_i == 0 and rec_p->type_label == protocol_filter->label) {
				filter_i = 1;
			}


			dictionary.insert("arp_opcode", get_ARP_opcode(pkt_bytes));
			dictionary.insert("src_ip", get_packet_IP(pkt_bytes, IP::ARP_SRC));
			dictionary.insert("dst_ip", get_packet_IP(pkt_bytes, IP::ARP_DST));
		}

	}
	else {
		const u_int dsap = pkt_bytes[14], ssap = pkt_bytes[15];

		//Handling RAW packets
		if (((dsap << 8) | ssap) == IEEE_RAW_VALUE) {

			insert_base(dictionary, packetNo, header_len, media_len, ETHER_II_NAME, get_packet_MAC(pkt_bytes, MAC::SMAC), get_packet_MAC(pkt_bytes, MAC::DMAC), get_hexa_frame(pkt_bytes, header_len));
		}
		//Handling SNAP packets
		else if (dsap == SNAP_VALUE && ssap == SNAP_VALUE) {
			ProtocolRecord* rec_p = get_protocol(((pkt_bytes[20] << 8) | pkt_bytes[21]), Protocol::L_3);

			if (rec_p == nullptr) {
				std::cerr << "Unable to identify packet " << packetNo << '.' << std::endl;
				return;
			}

			if (filter_i == 0 and rec_p->type_label == protocol_filter->label) {
				filter_i = 1;
			}

			insert_base(dictionary, packetNo, header_len, media_len, ETHER_II_NAME, get_packet_MAC(pkt_bytes, MAC::SMAC), get_packet_MAC(pkt_bytes, MAC::DMAC), get_hexa_frame(pkt_bytes, header_len));
			dictionary.insert("pid", rec_p->type_label);
		}
		//Handling IEEE LLC packets
		else {
			ProtocolRecord* rec_p = get_protocol(dsap, Protocol::L_3_SAP);
			
			if (rec_p == nullptr) {
				std::cerr << "Unable to identify packet " << packetNo << '.' << std::endl;
				return;
			}

			if (filter_i == 0 and rec_p->type_label == protocol_filter->label) {
				filter_i = 1;
			}
			
			insert_base(dictionary, packetNo, header_len, media_len, ETHER_II_NAME, get_packet_MAC(pkt_bytes, MAC::SMAC), get_packet_MAC(pkt_bytes, MAC::DMAC), get_hexa_frame(pkt_bytes, header_len));
			dictionary.insert("sap", rec_p->type_label);
		}
	}

	if (protocol_filter == nullptr) {
		process_dictionary(dictionary);
	}
	else if (filter_i == 1 and protocol_filter->label == "TCP") {
		process_request(TCP_comms, dictionary, pkt_bytes, Network::Protocol::TCP);
	}
	else if (filter_i == 1 and protocol_filter->label == "ARP") {
		process_request(TCP_comms, dictionary, pkt_bytes, Network::Protocol::ARP);
	}
	else if (filter_i == 1 and protocol_filter->label == "ICMP") {
		process_request(TCP_comms, dictionary, pkt_bytes, Network::Protocol::ICMP);
	}
	else if (filter_i == 1 and (protocol_filter->label == "UDP" or protocol_filter->label == "TFTP")) {
		process_request(TCP_comms, dictionary, pkt_bytes, Network::Protocol::TFTP);
	}
}

/*
	This function builds a source string configuring the network capture according to our assignment.
	@param source -> A char sequence representing the new source string.
	@buffer source -> A char sequence representing the potential error buffer.
	@returns 0: If the source string was successfully created; -1 if case of an error
*/
int get_src_str(char* source) {
	char err_buf[PCAP_ERRBUF_SIZE];

	if (pcap_createsrcstr(source, // variable that will keep the source string
		PCAP_SRC_FILE,  // we want to open a file
		NULL,      // remote hostname or address
		NULL,      // port on the remote host
		PCAP_FILE_PATH,    // name of the file we want to open
		err_buf      // error buffer
	) != 0){
		std::cerr << err_buf;
		return -1;
	}

	return 0;
}

/*This function opens a new session for packet capture according to the source parameter.
	@param handle -> A pointer representing a new packet capture session.
	@param source -> A source string according to which a new handle will be acquired.
	@param errorBuffer -> An error buffer for capturing potential errors.
	@return 0: if the session was successfully started, -1 otherwise
*/
int get_session_handle(pcap_t*& handle, const char* source) {
	char err_buf[PCAP_ERRBUF_SIZE];

	if ((handle = pcap_open(source, // name of the device
		65536, // portion of the packet to capture
			   // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode, we wanna capture all packets
		0, // read timeout
		NULL, // authentication on the remote machine
		err_buf // error buffer
	)) == NULL)
	{
		std::cerr << err_buf << std::endl;
		return -1;
	}

	return 0;
}

std::string get_file_name(const std::string file_path) {
	size_t found = file_path.find_last_of("/\\");

	if (found != std::string::npos) {
		return file_path.substr(found + 1);
	}
	else {
		std::cerr << "Invalid file path." << std::endl;
		return "";
	}
}


int process_param(int& argc, char* argv[]) {
	if (argc > 1) {
		if (argc > 3) {
			std::cerr << "Too many arguments!" << std::endl;
			return -1;
		}

		if ((std::string)argv[1] != "-p") {
			std::cerr << "Illegal parameter: " << argv[1] << ". Usage: main.cpp -p <procotol>" << std::endl;
			return -1;
		}
		protocol_filter = new ProtocolFilter();

		if (get_protocol_by_label(argv[2], Protocol::L_3)) {
			protocol_filter->layer = Network::NetworkLayer::L_3;
		}
		else if (get_protocol_by_label(argv[2], Protocol::L_2)) {
			protocol_filter->layer = Network::NetworkLayer::L_2;
		}
		else if (get_protocol_by_label(argv[2], Protocol::L_1)) {
			protocol_filter->layer = Network::NetworkLayer::L_1;
		}
		else if (get_protocol_by_label(argv[2], Protocol::L_3_SAP)) {
			protocol_filter->layer = Network::NetworkLayer::IEEE_L_3;
		}
		else {
			std::cerr << "Unknown protocol: " << argv[2] << std::endl;
			return -1;
		}

		protocol_filter->label = argv[2];
		return 0;
	}

	return 1;
}

void insert_header_data() {
	fileStream << "name: " << OUTPUT_NAME << std::endl;
	fileStream << "pcap_name: " << get_file_name(PCAP_FILE_PATH) << std::endl;

	if (protocol_filter) {
		fileStream << "filter_name: " << protocol_filter->label << std::endl;
		fileStream << "complete_coms: " << std::endl;
	}
	else {
		fileStream << "packets: " << std::endl;
	}
}

void call_parser_script() {
	std::ostringstream oss;

	if (!protocol_filter) {
		process_IPv4_records(IPv4Records, fileStream);
		process_top_IPv4_senders(top_IPv4_senders, fileStream);
		oss << "python " << PARSER_FILE_PATH << " --infile " << SCRIPT_INPUT_FILE_PATH << " --outfile " << SCRIPT_OUTPUT_FILE_PATH;
	}
	else if (protocol_filter->label == "TCP") {
		process_comms(Network::Protocol::TCP);
		oss << "python " << PARSER_FILE_PATH << " --infile " << SCRIPT_INPUT_FILE_PATH << " --outfile " << SCRIPT_OUTPUT_FILE_PATH << " -p TCP";
	}
	else if (protocol_filter->label == "ARP") {
		process_comms(Network::Protocol::ARP);
		oss << "python " << PARSER_FILE_PATH << " --infile " << SCRIPT_INPUT_FILE_PATH << " --outfile " << SCRIPT_OUTPUT_FILE_PATH << " -p ARP";
	}
	else if (protocol_filter->label == "ICMP") {
		process_comms(Network::Protocol::ICMP);
		oss << "python " << PARSER_FILE_PATH << " --infile " << SCRIPT_INPUT_FILE_PATH << " --outfile " << SCRIPT_OUTPUT_FILE_PATH << " -p ICMP";
	}
	else if (protocol_filter->label == "UDP" or protocol_filter->label == "TFTP") {
		process_comms(Network::Protocol::TFTP);
		oss << "python " << PARSER_FILE_PATH << " --infile " << SCRIPT_INPUT_FILE_PATH << " --outfile " << SCRIPT_OUTPUT_FILE_PATH << " -p TFTP";
	}

	system(oss.str().c_str());
}

int main(int argc, char* argv[]) {

	//Firstly, lets read all necessary data from external files to the respective arrays (etherTypes, lsaps)
	load_protocols(L_3_FILE_PATH, l_3_protocols);
	load_protocols(L_2_FILE_PATH, l_2_protocols);
	load_protocols(L_1_FILE_PATH, l_1_protocols);
	load_protocols(LSAPS_FILE_PATH, lsaps);
	load_protocols(ICMP_TYPES_FILE_PATH, icmp_types);

	//We process the input parameters here and create ProtocolFilter struct accordingly
	if (process_param(argc, argv) == -1) {
		return -1;
	}

	//Now, lets start launching a session for the input file
	char source[PCAP_BUF_SIZE];
	pcap_t* handle;

	if (get_src_str(source) != 0 || get_session_handle(handle, source) != 0) {
		return -1;
	}

	//After achieving the previous steps, we can now insert a header into the input file for a python script
	fileStream.open(SCRIPT_INPUT_FILE_PATH);
	insert_header_data();

	//Now, the main process of processing and analyzing packets begins
	pcap_loop(handle, 0, handlePacket, NULL);
	call_parser_script();

	////At the end, we close and dealloc some variables
	fileStream.close();
	pcap_close(handle);
	delete protocol_filter;

	return 0;
}