import json
import sys
import re
from common import *

# Maximum possible headers within a packet, hyperparameter with default value as 10
MAX_PATH_LENGTH = 10

# global variables for common header types detection
ETHER_DETECT = False
IPv4_DETECT = False
IPv6_DETECT = False
TCP_DETECT = False
UDP_DETECT = False

DEBUG = False

# multi-headers stores headers that appear in the form of array
# array_match is the regex to match for arrays
multi_headers = []
array_match = re.compile('[a-z A-Z 0-9 _ -]+''[''[0-9]+'']')

# open file to load json data
# standardize destination path
data = read_jsondata(sys.argv[1])
DESTINATION = sys.argv[2]
if (DESTINATION[-1] != '/'):
    DESTINATION += '/'

# check if max path length has been set
if (len(sys.argv) > 3):
    try:
        MAX_PATH_LENGTH = int(sys.argv[3])
    except ValueError:
        pass

# check if debug mode activated or not
if (len(sys.argv) > 3):
    if (sys.argv[-2] == '-d'):
        DEBUG = True

start_with_eth = sys.argv[-1].lower()


def possible_paths(init, control_graph, length_till_now, rmv_headers):
    '''find all possible header orderings that are valid'''
    if (init == 'final'):
        return [['final']]
    if (length_till_now == MAX_PATH_LENGTH):
        return []
    if (init in rmv_headers):
        return[]
    temp = []
    possible_stops = [i[-1] for i in control_graph if i[0] == init]
    paths = []
    for i in possible_stops:
        temp += (possible_paths(i, control_graph,
                                length_till_now+1, rmv_headers))
    for i in temp:
        paths.append([init] + i)
    return paths


def correct_name(s):
    '''correct names in case the header is of array form (instead of [X] replaces it with _X)'''
    if (array_match.match(s) != None):
        multi_headers.append(s[:s.find('[')])
        s = s[:s.find('[')] + "_" + s[s.find('[')+1:s.rfind(']')]
    return s


def capitalise(s):
    '''capitalise the first letter of name'''
    s = correct_name(s)
    return (s[:1].upper() + s[1:])


def check_checksum_fields(checksums, calculations, name):
    '''check if there any checksums fields, returns a tuple
    (whether a checksum field exists, the target fields, fields over which checksum has to be calculated, checksum algorithm to use)'''
    for chksum in (checksums):
        if (chksum["target"][0] == name):
            for calc in (calculations):
                if (calc["name"] == chksum["calculation"]):
                    fields = []
                    for i in calc["input"]:
                        try:
                            fields.append(i["value"])
                        except KeyError:
                            fields.append(i["type"])
                    return(True, chksum["target"][1], fields, calc["algo"])
    return(False, None, None, None)


def detect_field_type(field):
    if (field[1] == 8):
        return ("XByteField('"+field[0]+"', 0)")
    elif (field[1] == 16):
        return ("XShortField('"+field[0]+"', 0)")
    elif (field[1] == 32):
        return ("XIntField('"+field[0]+"', 0)")
    elif (field[1] == 64):
        return ("XLongField('"+field[0]+"', 0)")
    else:
        return ("XBitField('"+field[0]+"', 0, " + str(field[1])+")")


def detect_builtin_hdr(headers):
    global ETHER_DETECT
    global IPv4_DETECT
    global IPv6_DETECT
    global TCP_DETECT
    global UDP_DETECT
    for header_id in range(len(headers)):
        global input
        try:
            input = raw_input
        except NameError:
            pass
        if (headers[header_id]['metadata']) == False:
            if (headers[header_id]['name'] == 'ethernet'):
                temp = input(
                    "\nEthernet header detected, would you like the standard ethernet header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    ETHER_DETECT = True
            elif (headers[header_id]['name'] == 'ipv4'):
                temp = input(
                    "\nIPv4 header detected, would you like the standard IPv4 header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    IPv4_DETECT = True
            elif (headers[header_id]['name'] == 'ipv6'):
                temp = input(
                    "\nIPv6 header detected, would you like the standard IPv6 header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    IPv6_DETECT = True
            elif (headers[header_id]['name'] == 'tcp'):
                temp = input(
                    "\nTCP header detected, would you like the standard TCP header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    TCP_DETECT = True
            elif (headers[header_id]['name'] == 'udp'):
                temp = input(
                    "\nUDP header detected, would you like the standard UDP header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    UDP_DETECT = True
    return


def make_header(headers, header_ports, header_types, header_id, checksums, calculations, control_graph, fout):
    fout.write("class %s(Packet):\n" %
               (capitalise(headers[header_id]['name'])))
    fout.write(spaces(4) + "name = '%s'\n" % (headers[header_id]['name']))
    fout.write(spaces(4) + "fields_desc = [\n")
    header_type = search_header_type(
        header_types, headers[header_id]["header_type"])
    for field in header_type['fields'][:-1]:
        if field[1] != "*":
            fout.write(spaces(8) + "%s,\n" % (detect_field_type(field)))
        else:
            field[1] = int(input('Variable length field "' + field[0] +
                                 '" detected in "' + header_type['name'] + '". Enter its length\n'))
            fout.write(spaces(8) + "%s,\n" % (detect_field_type(field)))

    if (len(header_type['fields']) > 0):
        if header_type['fields'][-1][1] != "*":
            fout.write(spaces(8) + "%s,\n" %
                       (detect_field_type(header_type['fields'][-1])))
        else:
            header_type['fields'][-1][1] = int(input('Variable length field "' + header_type['fields']
                                                     [-1][0] + '" detected in "' + header_type['name'] + '". Enter its length\n'))
            fout.write(spaces(8) + "%s,\n" %
                       (detect_field_type(header_type['fields'][-1])))

    fout.write(spaces(4) + "]\n")

    # bind layers
    header = header_ports[header_id]
    make_parsers(control_graph, header_type, header, fout)

    chksum, target, fields, algo = check_checksum_fields(
        checksums, calculations, data["headers"][header_id]['name'])
    if (chksum):
        fout.write(spaces(
            4) + "#update %s over %s using %s in post_build method\n\n" % (target, fields, algo))


def remove_number(headers):
    unique_headers = {}
    for header in headers:
        if header['metadata']:
            continue
        name = header['name']
        if name.find('[') != (-1):
            header['name'] = name[:name.find('[')]
        unique_headers[header['name']] = header
    return unique_headers.keys(), unique_headers.values()


def make_classes(data, control_graph, header_ports, headers, rmv_headers, fout):
    global ETHER_DETECT
    global IPv4_DETECT
    global IPv6_DETECT
    global TCP_DETECT
    global UDP_DETECT

    header_types = data["header_types"]
    checksums = data["checksums"]
    calculations = data["calculations"]

    for header_id in range(len(headers)):
        global input
        try:
            input = raw_input
        except NameError:
            pass

        if (headers[header_id]['metadata']) == False:
            if (headers[header_id]['name'] == 'ethernet'):
                if (ETHER_DETECT == False):
                    if start_with_eth == 'true':
                        if headers[header_id]['name'] not in rmv_headers:
                            make_header(headers, header_ports, header_types, header_id,
                                        checksums, calculations, control_graph, fout)
                    else:
                        make_header(headers, header_ports, header_types, header_id,
                                    checksums, calculations, control_graph, fout)
            elif (headers[header_id]['name'] == 'ipv4'):
                if (IPv4_DETECT == False):
                    if start_with_eth == 'true':
                        if headers[header_id]['name'] not in rmv_headers:
                            make_header(headers, header_ports, header_types, header_id,
                                        checksums, calculations, control_graph, fout)
                    else:
                        make_header(headers, header_ports, header_types, header_id,
                                    checksums, calculations, control_graph, fout)
            elif (headers[header_id]['name'] == 'ipv6'):
                if (IPv6_DETECT == False):
                    if start_with_eth == 'true':
                        if headers[header_id]['name'] not in rmv_headers:
                            make_header(headers, header_ports, header_types, header_id,
                                        checksums, calculations, control_graph, fout)
                    else:
                        make_header(headers, header_ports, header_types, header_id,
                                    checksums, calculations, control_graph, fout)
            elif (headers[header_id]['name'] == 'tcp'):
                if (TCP_DETECT == False):
                    if start_with_eth == 'true':
                        if headers[header_id]['name'] not in rmv_headers:
                            make_header(headers, header_ports, header_types, header_id,
                                        checksums, calculations, control_graph, fout)
                    else:
                        make_header(headers, header_ports, header_types, header_id,
                                    checksums, calculations, control_graph, fout)
            elif (headers[header_id]['name'] == 'udp'):
                if (UDP_DETECT == False):
                    if start_with_eth == 'true':
                        if headers[header_id]['name'] not in rmv_headers:
                            make_header(headers, header_ports, header_types, header_id,
                                        checksums, calculations, control_graph, fout)
                    else:
                        make_header(headers, header_ports, header_types, header_id,
                                    checksums, calculations, control_graph, fout)
            else:
                if start_with_eth == 'true':
                    if headers[header_id]['name'] not in rmv_headers:
                        make_header(headers, header_ports, header_types, header_id,
                                    checksums, calculations, control_graph, fout)
                else:
                    make_header(headers, header_ports, header_types, header_id,
                                checksums, calculations, control_graph, fout)
    return


def correct_graph(graph):
    '''correct graph for inbuilt headers'''
    for i in range(len(graph)):
        edge = graph[i]
        if (edge[0] == 'ethernet' and ETHER_DETECT):
            edge[1] = 'type'
        elif (edge[0] == 'ipv4' and IPv4_DETECT):
            edge[1] = 'proto'
        elif (edge[0] == 'ipv6' and IPv6_DETECT):
            edge[1] = 'nh'
        elif (edge[0] == 'tcp' and TCP_DETECT):
            edge[1] = 'dport'
        elif (edge[0] == 'udp' and UDP_DETECT):
            edge[1] = 'dport'
        graph[i] = edge
    return graph


def make_parsers(control_graph, header_type, header, fout):
    '''defines bindings based on control graph'''
    transition_key = None
    next_transitions = []

    for edge in control_graph:
        if (header == edge[0]):
            if (edge[1] != None):
                transition_key = edge[1]
                next_transitions.append((edge[-1], edge[-2]))
            else:
                default_next_transition = edge[-1]

    if (len(next_transitions) > 0):
        fout.write("\n" + spaces(4) +
                   "def guess_payload_class(self, payload):\n" + spaces(8) + "")
        transition_dict = {}
        for tk in transition_key:
            for field in header_type['fields']:
                if (field[0] == tk):
                    transition_dict[field[0]] = nibble(field[1])
                    break
        for transition in next_transitions[:-1]:
            init_idx = 2
            fout.write("if (self.%s == 0x%s" % (
                transition_key[0], transition[1][init_idx:init_idx+transition_dict[transition_key[0]]]))
            for idx in range(1, len(transition_key)):
                init_idx += transition_dict[transition_key[idx-1]]
                fout.write(" and self.%s == 0x%s" % (
                    transition_key[idx], transition[1][init_idx:init_idx+transition_dict[transition_key[idx]]]))
            fout.write("):\n" + spaces(4))
            fout.write(spaces(8) + "return %s\n" %
                       (transition[0].capitalize()))
            fout.write(spaces(8) + "el")
        transition = next_transitions[-1]
        init_idx = 2
        fout.write("if (self.%s == 0x%s" % (
            transition_key[0], transition[1][init_idx:init_idx+transition_dict[transition_key[0]]]))
        for idx in range(1, len(transition_key)):
            init_idx += transition_dict[transition_key[idx-1]]
            fout.write(" and self.%s == 0x%s" % (
                transition_key[idx], transition[1][init_idx:init_idx+transition_dict[transition_key[idx]]]))
        fout.write("):\n" + spaces(4))
        fout.write(spaces(8) + "return %s\n" % (transition[0].capitalize()))
        fout.write(spaces(8) + "else:\n" + spaces(12) +
                   "return Packet.guess_payload_class(self, payload)\n\n")


def string_packet(header_ports, packet):
    '''creates a string of the headers in a packet in a way that Scapy expects'''
    s = ""
    for i in packet:
        if i in header_ports:
            s += capitalise(i) + "()/"
    return s[:-2]


def rectify_paths(paths):
    '''rectifies header names which are of array form'''
    for path_id in range(len(paths)):
        path = paths[path_id]
        distinct_state = set(path)
        multi_headers_loc = list(set(multi_headers))
        for i in distinct_state:
            if i in multi_headers_loc:
                count = 0
                for j in range(len(path)):
                    if (path[j] == i):
                        path[j] = path[j]+"_"+str(count)
                        count += 1
        paths[path_id] = path
    paths.sort(key=len)
    return paths


def make_packets(header_ports, init_states, control_graph, rmv_headers, fout):
    '''prints the possible packet list into the file'''
    paths = []
    for i in init_states:
        paths += possible_paths(i, control_graph, 0, rmv_headers)

    paths = set(map(tuple, paths))
    paths = list(map(list, paths))

    paths = rectify_paths(paths)

    if (DEBUG):
        print("\nPossible paths from start to accept state\n")
        for i in paths:
            print(i)
    if (len(paths) == 0):
        fout.write(
            "\n#No possible packets which can be parsed to the final state")
        return
    fout.write("possible_packets_ = [\n")
    for i in paths[:-1]:
        fout.write(spaces(4) + "(%s)),\n" % (string_packet(header_ports, i)))
    fout.write(spaces(4) + "(%s))\n" %
               (string_packet(header_ports, paths[-1])))
    fout.write("]\n")


def change_names(header_ports, control_graph, init_states, old, new):
    '''rectifies array names for inbuilt header types'''
    for i in range(len(header_ports)):
        if (header_ports[i] == old):
            header_ports[i] = new
    for i in range(len(control_graph)):
        if (control_graph[i][0] == old):
            control_graph[i][0] = new
        if (control_graph[i][-1] == old):
            control_graph[i][-1] = new
    for i in range(len(init_states)):
        if (init_states[i] == old):
            init_states[i] = new
    return (header_ports, control_graph, init_states)


def correct_metadata(header_ports, control_graph, init_states):
    if (ETHER_DETECT):
        (header_ports, control_graph, init_states) = change_names(
            header_ports, control_graph, init_states, "ethernet", "Ether")
    if (IPv4_DETECT):
        (header_ports, control_graph, init_states) = change_names(
            header_ports, control_graph, init_states, "ipv4", "IP")
    if (IPv6_DETECT):
        (header_ports, control_graph, init_states) = change_names(
            header_ports, control_graph, init_states, "ipv6", "IPv6")
    if (TCP_DETECT):
        (header_ports, control_graph, init_states) = change_names(
            header_ports, control_graph, init_states, "tcp", "TCP")
    if (UDP_DETECT):
        (header_ports, control_graph, init_states) = change_names(
            header_ports, control_graph, init_states, "udp", "UDP")
    return (header_ports, control_graph, init_states)


def make_template(json_data, destination):
    '''top level module that calls other functions, accepts the json_data and the file destination as input'''
    global ETHER_DETECT
    global IPv4_DETECT
    global IPv6_DETECT
    global TCP_DETECT
    global UDP_DETECT

    try:
        fout = open(destination, 'w')
        fout.write("from scapy.all import *\n")
        header_ports, headers = remove_number(data["headers"])
        detect_builtin_hdr(headers)

        fout.write("\n##class definitions\n")

        # building metadata
        control_graph = correct_graph(
            make_control_graph_multi(json_data["parsers"], DEBUG))
        init_states = []
        for parser in json_data["parsers"]:
            init_states.append(search_state(parser, parser["init_state"]))
        (header_ports, control_graph, init_states) = correct_metadata(
            header_ports, control_graph, init_states)

        copy_of_graph = control_graph[:]
        paths = make_tree(copy_of_graph)
        rmv_headers = []
        sub_headers = []
        for path in paths:
            find_ethernet(path, rmv_headers, sub_headers, ETHER_DETECT)
            print("rmv_headers = ", rmv_headers)
            print("sub_headers = ", sub_headers)
            # search for ethernet
            rmv_headers = set(rmv_headers)
            sub_headers = set(sub_headers)
            for item in sub_headers:
                if item in rmv_headers:
                    rmv_headers.remove(item)

        make_classes(json_data, control_graph, header_ports,
                     headers, rmv_headers, fout)
        print('rmv_headers 517: ', rmv_headers)

        if (DEBUG):
            print("\nHeaders \n")
            for i in header_ports:
                print (i)
            print("\nHeader arrays\n")
            for i in set(multi_headers):
                print (i)

        fout.write("\n## remaining bindings\n")
        for edge in control_graph:
            if start_with_eth == 'true':
                if (edge[0] in header_ports) and (edge[-1] in header_ports) and edge[0] not in rmv_headers and edge[-1] not in rmv_headers:
                    if (ETHER_DETECT or IPv4_DETECT or IPv6_DETECT or TCP_DETECT or UDP_DETECT):
                        if (edge[0] in ["Ether", "IP", "IPv6", "UDP", "TCP"]):
                            if (edge[2] != 'default') and (edge[1] != None) and (edge[2] != None):
                                fout.write("bind_layers(%s, %s, %s=%s)\n" % (
                                    capitalise(edge[0]), capitalise(edge[-1]), edge[1], edge[2]))
                            else:
                                fout.write("bind_layers(%s, %s)\n" % (
                                    capitalise(edge[0]), capitalise(edge[-1])))
            else:
                if (edge[0] in header_ports) and (edge[-1] in header_ports):
                    if (ETHER_DETECT or IPv4_DETECT or IPv6_DETECT or TCP_DETECT or UDP_DETECT):
                        if (edge[0] in ["Ether", "IP", "IPv6", "UDP", "TCP"]):
                            if (edge[2] != 'default') and (edge[1] != None) and (edge[2] != None):
                                fout.write("bind_layers(%s, %s, %s=%s)\n" % (
                                    capitalise(edge[0]), capitalise(edge[-1]), edge[1], edge[2]))
                            else:
                                fout.write("bind_layers(%s, %s)\n" % (
                                    capitalise(edge[0]), capitalise(edge[-1])))

        fout.write("\n##packet_list\n")
        make_packets(header_ports, init_states,
                     control_graph, rmv_headers, fout)

    except IOError:
        print("Destination file cannot be created\n")
        exit(0)


try:
    local_name = data["program"]
except KeyError:
    local_name = sys.argv[1]
local_name = local_name[local_name.rfind('/')+1:local_name.rfind('.')]

make_template(data, DESTINATION+local_name+".py")
