#!/usr/bin/python
import json


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
