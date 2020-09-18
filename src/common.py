#!/usr/bin/python
import json


# global variables for common header types detection
ETHER_DETECT = False
IPv4_DETECT = False
IPv6_DETECT = False
TCP_DETECT = False
UDP_DETECT = False

global input
try:
    input = raw_input
except NameError:
    pass


def read_jsondata(filename):
    '''open file to load json data'''
    try:
        data = json.load(open(filename))
    except IOError:
        print ("Incorrect JSON file specification")
        exit(0)
    return data


def merge_padding(data):
    '''merges padding field with the next field'''
    for header_type in data["header_types"]:
        # try except added to prevent falling into error when scalars_0 has 0 fields
        try:
            temp_list = [header_type["fields"][0]]
            for i in range(1, len(header_type["fields"])):
                if (temp_list[-1][0][:4] == "_pad"):
                    temp_list = temp_list[:-1]
                    temp_list.append(
                        [header_type["fields"][i][0], header_type["fields"][i-1][1]+header_type["fields"][i][1]])
                else:
                    temp_list.append(header_type["fields"][i])
            header_type["fields"] = temp_list
        except:
            pass

    return data


def nibble(size):
    if (size <= 8):
        return 2
    if (size <= 16):
        return 4
    if (size <= 24):
        return 6
    if (size <= 32):
        return 8
    if (size <= 40):
        return 10
    if (size <= 48):
        return 12
    if (size <= 56):
        return 14
    if (size <= 64):
        return 16
    return "-- fill blank here"


def delete_obj(del_list, orig_list):
    for item in del_list:
        orig_list.remove(item)


def sanitize_headers(headers):
    unique_header_names, unique_headers = [], []
    for header in headers:
        if header['metadata']:
            continue

        header['name'] = header['name'].split('[')[0]
        unique_header_names.append(header['name'])
        unique_headers.append(header)
    return unique_header_names, unique_headers


def detect_builtin_hdr(headers):
    global ETHER_DETECT
    global IPv4_DETECT
    global IPv6_DETECT
    global TCP_DETECT
    global UDP_DETECT

    for header in headers:
        if (header['name'] == 'ethernet'):
            temp = input(
                "\nEthernet header detected, would you like the standard ethernet header to be used(y/n) : ").strip()
            if (temp == 'y'):
                ETHER_DETECT = True
        elif (header['name'] == 'ipv4'):
            temp = input(
                "\nIPv4 header detected, would you like the standard IPv4 header to be used(y/n) : ").strip()
            if (temp == 'y'):
                IPv4_DETECT = True
        elif (header['name'] == 'ipv6'):
            temp = input(
                "\nIPv6 header detected, would you like the standard IPv6 header to be used(y/n) : ").strip()
            if (temp == 'y'):
                IPv6_DETECT = True
        elif (header['name'] == 'tcp'):
            temp = input(
                "\nTCP header detected, would you like the standard TCP header to be used(y/n) : ").strip()
            if (temp == 'y'):
                TCP_DETECT = True
        elif (header['name'] == 'udp'):
            temp = input(
                "\nUDP header detected, would you like the standard UDP header to be used(y/n) : ").strip()
            if (temp == 'y'):
                UDP_DETECT = True
    return


class State:
    def __init__(self, name):
        self.name = name
        self.children = []

    def print_state(self):
        print("node's name: ", self.name)
        print("node's children: ", [
              self.children[i].name for i in range(len(self.children))])


def find_children(root, nodes):
    if len(nodes) == 0:
        return
    else:
        children = []
        del_list = []
        for node in nodes:
            if node[0] == root.name:
                children.append(node[-1])
                del_list.append(node)
        delete_obj(del_list, nodes)
        children = set(children)
        for child in children:
            state = State(child)
            find_children(state, nodes)
            root.children.append(state)
        return


def make_tree(graph):
    paths = []
    state_names = [edge[0] for edge in graph]
    state_names = set(state_names)
    non_roots = [edge[-1] for edge in graph]
    non_roots = set(non_roots)
    for name in state_names:
        if name not in non_roots:
            root = State(name)
            find_children(root, graph)
            paths.append(root)
            root.print_state()
    return paths


def find_eth_subhdr(node, sub_headers):
    if len(node.children) == 0:
        if node.name != "final":
            sub_headers.append(node.name)
        return
    else:
        for child in node.children:
            if child.name != "final":
                sub_headers.append(child.name)
            find_eth_subhdr(child, sub_headers)
        return


def find_ethernet(node, rmv_headers, sub_headers, ehter_detect):
    if (node.name == "ethernet" or node.name == "Ether") and ehter_detect:
        find_eth_subhdr(node, sub_headers)
        return
    elif len(node.children) == 0:
        if node.name != "final":
            rmv_headers.append(node.name)
        return
    else:
        if node.name != "scalars" and node.name != "final":
            rmv_headers.append(node.name)
        for child in node.children:
            find_ethernet(child, rmv_headers, sub_headers, ehter_detect)
        return


def gen_hex_mask(zeroes_len, ones_len):
    return hex(int('0b' + '1'*ones_len + '0'*zeroes_len, 2))


def valid_state_name(state):
    '''assign valid name to state depending on which header it extracts'''
    if len(state["parser_ops"]) > 0:
        if type(state["parser_ops"][0]["parameters"][0]["value"]) is list:
            return state["parser_ops"][0]["parameters"][0]["value"][0]
        else:
            return state["parser_ops"][0]["parameters"][0]["value"]
    else:
        return state["name"]


def search_state(parser, name):
    '''search for valid state name in the parse states'''
    for state in parser["parse_states"]:
        if (state["name"] == name):
            return valid_state_name(state)


def search_header_type(header_types, name):
    '''search for header type given the header_type_name specified in header definition'''
    for header_type in header_types:
        if (header_type["name"] == name):
            return header_type


def make_control_graph(parsers, DEBUG):
    '''make a control graph for all possible state transitions
    returns the list of edges in graph'''
    graph = []
    for parser in parsers:
        for state in parser["parse_states"]:
            name = valid_state_name(state)
            if len(state["transition_key"]) > 0:
                for transition in state["transitions"]:
                    if transition["next_state"] != None:
                        graph.append([name,
                                      state["transition_key"][0]["value"][1],
                                      transition["value"],
                                      search_state(
                                          parser, transition["next_state"])
                                      ])
                    else:
                        graph.append([name, None, None, "final"])
            else:
                if state["transitions"][0]["next_state"] != None:
                    graph.append([name, None, None, search_state(
                        parser, state["transitions"][0]["next_state"])])
                else:
                    graph.append([name, None, None, "final"])
    if (DEBUG):
        print("\nEdges in the control_graph\n")
        for i in graph:
            print(i)
    return graph


def make_control_graph_multi(parsers, DEBUG):
    graph = []
    for parser in parsers:
        for state in parser["parse_states"]:
            name = valid_state_name(state)
            if len(state["transition_key"]) > 0:
                for transition in state["transitions"]:
                    if transition["next_state"] != None:
                        # extract the headers which the transition is based on one of their fields
                        originHdr = [d["value"][0]
                                     for d in state["transition_key"]]
                        if(len(set(originHdr)) != 1):
                            print(
                                "Error: Header transitions based on multiple fields from different headers are not supported.")
                            exit(1)
                        # extract the fields which the transition is based on
                        transition_fields = [d["value"][1]
                                             for d in state["transition_key"]]
                        graph.append([name,
                                      transition_fields,
                                      transition["value"],
                                      search_state(
                                          parser, transition["next_state"])
                                      ])
                    else:
                        graph.append([name, None, None, "final"])
            else:
                if state["transitions"][0]["next_state"] != None:
                    graph.append([name, None, None, search_state(
                        parser, state["transitions"][0]["next_state"])])
                else:
                    graph.append([name, None, None, "final"])
    if (DEBUG):
        print("\nEdges in the control_graph\n")
        for i in graph:
            print(i)
    return graph


def spaces(count):
    return (" " * count)
