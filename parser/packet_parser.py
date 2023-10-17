import argparse, ruamel.yaml

#Predefined constants
INPUT_FILE_PATH = 'resources\\input.txt'
OUTPUT_FILE_PATH = 'resources\\output.yml'
KEY_VALUE_DELIMITER = ': '
PACKET_DELIMITER = '!'
IPV4_REC_DELIMITER = '%'

header_len = -1

#Script configuration
parser = argparse.ArgumentParser(description='Used for effective input-data-parsing into a yml file.')

yaml = ruamel.yaml.YAML()

class CheckFilterAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # Check if the protocol is valid
        valid_protocols = ['TCP', 'ARP', 'ICMP', 'TFTP']
        if values not in valid_protocols:
            raise argparse.ArgumentError(self, f"Invalid protocol: {values}. Choose from {', '.join(valid_protocols)}")
        
        # Set the valid protocol in the namespace
        setattr(namespace, self.dest, values)

def configure_argparse():
    global args

    parser.add_argument('-i', '--infile', nargs='?', default= INPUT_FILE_PATH, help='User can set a specific path to the input text file.')
    parser.add_argument('-o', '--outfile', nargs='?', default= OUTPUT_FILE_PATH, help='User can set specific path to the output yaml file.')
    parser.add_argument('-a', '--append', action='store_true', help='''Rather than parsing a new header with new packets it only appends new packets.')                       
                                                                    If this is selected, the input file should only contain packet dictionaries.''')
    parser.add_argument('-p', '--protocol', nargs='?', action=CheckFilterAction, help="User can specify a certain protocol as a filter.")
    args = parser.parse_args()

#Some helpful functions
def load_data(yaml):
    with open(args.outfile, 'r') as yaml_file:
        return yaml.load(yaml_file)

def save_data(data, yaml):
    with open(args.outfile, 'w') as yaml_file:
        yaml.dump(data, yaml_file)

def clear_data():
    #We clear all possible data from the output file
    if not args.append:
        with open(args.outfile, 'w') as yaml_file:
            yaml_file.truncate(0)

def set_header(data):

    #If the data contains no data we define the header and an empty packet list
    if not data and not args.protocol:
        save_data({
            'name': '',
            'pcap_name': '',
            'packets': [],
            'ipv4_senders': [],
            'max_send_packets_by': []
        }, yaml)
    elif not data and args.protocol in ["TCP", "ARP", "ICMP"]:
        save_data({
            'name': '',
            'pcap_name': '',
            'filter_name': '',
            'complete_comms': [],
            'partial_comms': []
        }, yaml)
    elif not data and args.protocol == "TFTP":
        save_data({
                'name': '',
                'pcap_name': '',
                'filter_name': '',
                'complete_comms': [],
        }, yaml) 
    
    return load_data(yaml)

#This functions skips the first 3 lines composing the header of the file
def skip_header():
    file_input = open(args.infile, 'r')

    for i in range(0, header_len):
        file_input.readline()

    return file_input

#This function parses data from the file into yaml format
def parse_header_data():
    file = open(args.infile, 'r')

    data['name'] = file.readline().split(KEY_VALUE_DELIMITER)[1].strip()
    data['pcap_name'] = file.readline().split(KEY_VALUE_DELIMITER)[1].strip()

    global header_len
    header_len = 3

    if args.protocol:
        header_len += 1
        data['filter_name'] = file.readline().split(KEY_VALUE_DELIMITER)[1].strip()


    file.close()

#This function parses data from the file into desired yaml format.
def insert_packet(file_input, dic, key):
    packet = {}
    line = file_input.readline()

    packet['frame_number'] = int(line.split(KEY_VALUE_DELIMITER)[1].strip())
    packet['len_frame_pcap'] = int(file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip())
    packet['len_frame_medium'] = int(file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip())
    packet['frame_type'] = file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip()
    packet['src_mac'] = file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip()
    packet['dst_mac'] =  file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip()

    hexas = file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip().split()
    hexa_frame_m = ""
    hexa_index = 1
    hexa_frame_len = len(hexas)
        
    for hex in hexas:
        hexa_frame_m += hex
        
        #The logic of inserting blank spaces between bytes
        if(hexa_index % 16 == 0):
            hexa_frame_m += '\n'
        elif (hexa_index < hexa_frame_len):
            hexa_frame_m += ' '
        
        hexa_index += 1

    #Last modifications of the scalar string, the first case is exceptional, happens only if the last line is fully filled with
    #data (contains 16 bytes). In this case we simply convert it into scalar string, otherwise we also append newline character.
    if (hexa_index - 1) % 16 == 0:
        packet['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame_m)
    else:
        packet['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame_m + '\n')

    
    line = file_input.readline()
    while line and line.strip() != PACKET_DELIMITER and line.strip() not in ['%', '?', '*']:
        splits = line.split(KEY_VALUE_DELIMITER)

        if splits[0].strip() in ['src_port', 'dst_port', 'icmp_id', 'icmp_seq', 'length',
                                 'id', 'flags_mf', 'frag_offset']:
            packet[splits[0].strip()] = int(splits[1].strip()) 
        else:
            packet[splits[0].strip()] = splits[1].strip()
            
        line = file_input.readline()

    dic[key].append(packet)

    if(line.strip() == PACKET_DELIMITER):
        return 1
    elif(line.strip() == '?'):
        return 2
    elif(line.strip() == '*'):
        return 3
    elif(line.strip() == '%'):
        return 4
    return 0

def insert_ipv4_rec(fileInput):
    rec = {}

    rec['node'] = file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip()
    rec['number_of_sent_packets'] = int(file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip())

    data['ipv4_senders'].append(rec)

def insert_communication(file_input):
    communication = {
        'number_comm': '',
        'src_comm': '',
        'dst_comm': '',
        'packets': []
    }
    
    line = file_input.readline()

    communication['number_comm'] = int(line.split(KEY_VALUE_DELIMITER)[1].strip())
    communication['src_comm'] = file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip()
    communication['dst_comm'] = file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip()

    file_input.readline()
    result = insert_packet(file_input, communication, 'packets')

    while(result == 1):
        result = insert_packet(file_input, communication, 'packets')

    data['complete_comms'].append(communication)

    if result == 2:
        return 1
    elif result == 3:
        return 2

    return 0

def insert_partial_comm(file_input):
    communication = {
        'number_comm': '',
        'packets': []
    }

    line = file_input.readline()
    communication['number_comm'] = int(line.split(KEY_VALUE_DELIMITER)[1].strip())

    file_input.readline()
    result = insert_packet(file_input, communication, 'packets')

    while(result == 1):
        result = insert_packet(file_input, communication, 'packets')
    
   
    data['partial_comms'].append(communication)

    if result == 2:
        return 1

def insert_arp_comm(file_input):
    communication = {
        'number_comm': '',
        'packets': []
    }

    communication['number_comm'] = int(file_input.readline().split(KEY_VALUE_DELIMITER)[1].strip())

    file_input.readline()

    result = insert_packet(file_input, communication, 'packets')

    while(result == 1):
        result = insert_packet(file_input, communication, 'packets')
    
    data['complete_comms'].append(communication)

    if result == 2:
        return 1

    elif result == 3:
        return 2
    
    return 0


def process_input(file_input):
    start = file_input.readline().strip()

    if args.protocol in ["TCP", "ICMP"] and start == '?':
        result = 1

        while(result == 1):
            result = insert_communication(file_input)

        if(result == 2):
            if(args.protocol == "ICMP"):
                file_input.readline()

            result = 1
            while(result == 1):
                result =  insert_partial_comm(file_input)
    elif start == '*':
        result = 1
        while(result == 1):
            result = insert_partial_comm(file_input)

    elif args.protocol in ["ARP", "TFTP"]  and start == '?':
        result = 1

        while(result == 1):
            result = insert_arp_comm(file_input)
        
        file_input.readline()
        if(result == 2):
            result = 1
            while(result == 1):
                result =  insert_partial_comm(file_input)    

    elif(start == PACKET_DELIMITER):
        while(insert_packet(file_input, data, 'packets') != 4): pass

        insert_ipv4_rec(file_input)

        line = file_input.readline()

        while(line.strip() == IPV4_REC_DELIMITER):
            insert_ipv4_rec(file_input)
            line = file_input.readline()

        if(line.strip() == '&'):
            data['max_send_packets_by'].append(file_input.readline().strip())
    
    return file_input


if __name__ == "__main__":
    configure_argparse()

    if not args.append:
        clear_data()

    data = load_data(yaml)
    data = set_header(data)
    
    #Managing header in case of '-a' parameter
    if not args.append:
        parse_header_data()
        file_input = skip_header()
    
    file_input = process_input(file_input)
    save_data(data, yaml)
