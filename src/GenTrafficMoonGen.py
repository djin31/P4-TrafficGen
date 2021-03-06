import json
import sys
import os
from tabulate import tabulate
import config
from common import *


# open file to load json data
# standardize destination path
data = merge_padding(read_jsondata(sys.argv[1]))
DESTINATION = sys.argv[2]

# check if debug mode activated or not
if (len(sys.argv) > 3):
    if (sys.argv[-2] == '-d'):
        config.DEBUG = True

start_with_eth = sys.argv[-1]


def find_data_headers(headers, header_types):
    '''find headers and their types which appear within a packet i.e. are not metadata'''
    header_ports = []
    header_dict = {}

    for header_id in range(len(headers)):
        if (headers[header_id]['metadata']) == False:
            name = headers[header_id]['name']
            if (name.find('[') != (-1)):
                name = name[:name.find('[')]
            header_ports.append(name)
            header_dict[name] = search_header_type(
                header_types, headers[header_id]["header_type"])

            # functionality to use common headers to be added
            if (name == 'ethernet'):
                temp = input(
                    "\nEthernet header detected, would you like the standard ethernet header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    config.ETHER_DETECT = True
            elif (name == 'ipv4'):
                temp = input(
                    "\nIPv4 header detected, would you like the standard IPv4 header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    config.IPv4_DETECT = True
            elif (name == 'ipv6'):
                temp = input(
                    "\nIPv6 header detected, would you like the standard IPv6 header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    config.IPv6_DETECT = True
            elif (name == 'tcp'):
                temp = input(
                    "\nTCP header detected, would you like the standard TCP header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    config.TCP_DETECT = True
            elif (name == 'udp'):
                temp = input(
                    "\nUDP header detected, would you like the standard UDP header to be used(y/n) : ").strip()
                if (temp == 'y'):
                    config.UDP_DETECT = True
    header_ports = list(set(header_ports))

    header_types = []
    for i in header_ports:
        header_types.append(header_dict[i])

    if (config.DEBUG):
        print("\nHeaders \n")
        for i in range(len(header_ports)):
            print (header_ports[i], header_types[i]["name"])

    require_correction = []
    for i in range(len(header_types)):
        if is_builtin_header(header_ports[i]):
            continue
        else:
            header_type = header_types[i]
            corrected_data = {"name": header_type["name"], "fields": []}
            for field in header_type["fields"]:
                try:
                    if (field[1] % 8 != 0):
                        corrected_data["fields"].append(field[0])
                except:
                    pass
            if len(corrected_data["fields"]) > 0:
                require_correction.append(corrected_data)
    if len(require_correction) > 0:
        for incorrect_header in require_correction:
            print("ERROR : Non byte-aligned fields found in %s" %
                  (str(incorrect_header["name"])))
            print("Correct the following fields to make them byte-aligned:")
            print(list(map(str, incorrect_header["fields"])))
        exit(1)
    return (header_ports, header_types)


# copies template file contents
def copy_template(fout):
    fin = open("/usr/share/p4-traffictool/templates/templateMoonGen.lua", "r")
    l = fin.readlines()
    for i in l:
        fout.write(i)


def predict_type(field):
    if (field[1] <= 8):
        return "uint8_t"
    if (field[1] <= 16):
        return "uint16_t"
    if (field[1] <= 24):
        return "union bitfield_24"
    if (field[1] <= 32):
        return "uint32_t"
    if (field[1] <= 40):
        return "union bitfield_40"
    if (field[1] <= 48):
        return "union bitfield_48"
    if (field[1] <= 64):
        return "uint64_t"
    return "-- fill blank here " + str(field[1])


def network_host_conversion(field):
    if (field[1] <= 8):
        return ""
    if (field[1] <= 16):
        return "ntoh16"
    if (field[1] <= 24):
        return ""
    if (field[1] <= 32):
        return "ntoh"
    if (field[1] <= 40):
        return ""
    if (field[1] <= 48):
        return ""
    if (field[1] <= 64):
        return "hton64"
    return "-- fill blank here"


def host_network_conversion(field):
    if (field[1] <= 8):
        return ""
    if (field[1] <= 16):
        return "hton16"
    if (field[1] <= 24):
        return ""
    if (field[1] <= 32):
        return "hton"
    if (field[1] <= 40):
        return ""
    if (field[1] <= 48):
        return ""
    if (field[1] <= 64):
        return "hton64"
    return "-- fill blank here"


def make_template(control_graph, header, header_type, destination, header_ports, local_name):
    '''makes the actual lua script given the relevant header type and next and previous state transition information'''
    headerUpper = local_name + header.lower()
    fout = open(destination, "w")
    fout.write("--Template for addition of new protocol '%s'\n\n" % (header))
    copy_template(fout)
    fout.write("\n\n-----------------------------------------------------\n")
    fout.write("---- %s header and constants \n" % (headerUpper))
    fout.write("-----------------------------------------------------\n")
    fout.write("local %s = {}\n\n" % (headerUpper))

    variable_fields = []
    fout.write("%s.headerFormat = [[\n" % (headerUpper))
    for field in header_type["fields"][:-1]:
        try:
            fout.write(spaces(4) + "%s " % (predict_type(field)) + spaces(4) + " %s;\n" %
                       (field[0]))
        except TypeError:
            variable_fields.append(field[0])
    field = header_type["fields"][-1]
    try:
        fout.write(spaces(4) + "%s " % (predict_type(field)) + spaces(4) + " %s;\n" %
                   (field[0]))
    except TypeError:
        variable_fields.append(field[0])
    fout.write("]]\n")
    fout.write("\n\n-- variable length fields\n")
    for variable_field in variable_fields:
        fout.write("%s.headerVariableMember = '%s'\n" %
                   (headerUpper, variable_field))
    if len(variable_fields) == 0:
        fout.write("%s.headerVariableMember = nil\n" % (headerUpper))

    fout.write("\n-- Module for %s_address struct\n" % (headerUpper))
    fout.write("local %sHeader = initHeader()\n" % (headerUpper))
    fout.write("%sHeader.__index = %sHeader\n\n" % (headerUpper, headerUpper))
    fout.write("\n-----------------------------------------------------\n")
    fout.write("---- Getters, Setters and String functions for fields")
    fout.write("\n-----------------------------------------------------\n")

    for field in header_type["fields"]:
        if (not(predict_type(field).startswith("union")) and field[1] < 65):
            fout.write("function %sHeader:get%s()\n" %
                       (headerUpper, field[0].upper()))
            fout.write(spaces(4) + "return %s(self.%s)\n" %
                       (host_network_conversion(field), field[0]))
            fout.write("end\n\n")

            fout.write("function %sHeader:get%sstring()\n" %
                       (headerUpper, field[0].upper()))
            fout.write(spaces(4) + "return self:get%s()\n" %
                       (field[0].upper()))
            fout.write("end\n\n")

            fout.write("function %sHeader:set%s(int)\n" %
                       (headerUpper, field[0].upper()))
            fout.write(spaces(4) + "int = int or 0\n")
            fout.write(spaces(4) + "self.%s = %s(int)\n" %
                       (field[0], host_network_conversion(field)))
            fout.write("end\n\n\n")
        else:
            fout.write("function %sHeader:get%s()\n" %
                       (headerUpper, field[0].upper()))
            fout.write(spaces(4) + "return (self.%s:get())\n" % (field[0]))
            fout.write("end\n\n")

            fout.write("function %sHeader:get%sstring()\n" %
                       (headerUpper, field[0].upper()))
            fout.write(spaces(4) + "return self:get%s()\n" %
                       (field[0].upper()))
            fout.write("end\n\n")

            fout.write("function %sHeader:set%s(int)\n" %
                       (headerUpper, field[0].upper()))
            fout.write(spaces(4) + "int = int or 0\n")
            fout.write(spaces(4) + "self.%s:set(int)\n" % (field[0]))
            fout.write("end\n\n\n")

    fout.write("\n-----------------------------------------------------\n")
    fout.write("---- Functions for full header")
    fout.write("\n-----------------------------------------------------\n")
    fout.write("-- Set all members of the PROTO header\n")
    fout.write("function %sHeader:fill(args,pre)\n" % (headerUpper))
    fout.write(spaces(4) + "args = args or {}\n")
    fout.write(spaces(4) + "pre = pre or '%s'\n\n" % (headerUpper))

    for field in header_type["fields"]:
        fout.write(spaces(
            4) + "self:set%s(args[pre .. '%s'])\n" % (field[0].upper(), field[0].upper()))
    fout.write("end\n\n")

    fout.write("-- Retrieve the values of all members\n")
    fout.write("function %sHeader:get(pre)\n" % (headerUpper))
    fout.write(spaces(4) + "pre = pre or '%s'\n\n" % (headerUpper))
    fout.write(spaces(4) + "local args = {}\n")
    for field in header_type["fields"]:
        fout.write(spaces(4) + "args[pre .. '%s'] = self:get%s()\n" %
                   (field[0].upper(), field[0].upper()))
    fout.write("\n" + spaces(4) + "return args\nend\n\n")

    fout.write("function %sHeader:getString()\n" % (headerUpper))
    fout.write(spaces(4) + "return '%s \\n'\n" % (headerUpper))
    for field in header_type["fields"]:
        fout.write(spaces(8) + ".. '%s' .. self:get%sString() .. '\\n'\n" %
                   (field[0].upper(), field[0].upper()))
    fout.write("end\n\n")

    default_next_transition = None
    transition_key = None
    next_transitions = []
    for edge in control_graph:
        if (header == edge[0]):
            if (edge[1] != None):
                transition_key = edge[1]
                next_transitions.append((edge[-1], edge[-2]))
            elif (str(edge[-1]) != 'final'):
                default_next_transition = edge[-1]
    fout.write("-- Dictionary for next level headers\n")
    fout.write("local nextHeaderResolve = {\n")
    for transition in next_transitions:
        fout.write(spaces(4) + "%s = %s,\n" %
                   ((local_name + transition[0]).lower(), transition[1]))
    fout.write("}\n")

    fout.write("function %sHeader:resolveNextHeader()\n" % (headerUpper))
    if (len(next_transitions) > 0):
        transition_dict = {}
        offset = 1
        for tk in transition_key:
            for field in header_type["fields"]:
                if(field[0] == tk):
                    if len(transition_key) == 1:
                        fout.write(
                            spaces(4) + "local key = self:get%s()\n" % (tk.upper()))
                    else:
                        fout.write(
                            spaces(4) + "local key%s = self:get%s()\n" % (offset, tk.upper()))
                        offset += 1
                        transition_dict[field[0]] = nibble(field[1])
                    break

        fout.write(spaces(4) + "for name, value in pairs(nextHeaderResolve) do\n")
        if len(transition_key) == 1:
            fout.write(spaces(8) + "if key == value then\n" + spaces(12) +
                       "return name\n" + spaces(8) + "end\n" + spaces(4) + "end\n")
        elif len(transition_key) > 1:
            vals = transition_dict.values()
            rbit_num = sum(vals) - transition_dict[transition_key[0]]
            offset = 1
            mask = gen_hex_mask(rbit_num, transition_dict[transition_key[0]])
            fout.write(spaces(
                8) + "if key%s == rshift(band(value, %sULL), %s)" % (offset, mask, rbit_num))
            offset += 1
            for i in range(1, len(transition_key[:-1])):
                rbit_num -= transition_dict[transition_key[i]]
                mask = gen_hex_mask(
                    rbit_num, transition_dict[transition_key[i]])
                fout.write(" and key%s == rshift(band(value, %sULL), %s)" %
                           (offset, mask, rbit_num))
                offset += 1
            rbit_num -= transition_dict[transition_key[-1]]
            mask = gen_hex_mask(rbit_num, transition_dict[transition_key[-1]])
            fout.write(" and key%s == band(value, %sULL) then\n" % (offset, mask) + spaces(12) +
                       "return name\n" + spaces(8) + "end\n" + spaces(4) + "end\n")

    if (default_next_transition != None):
        fout.write(spaces(4) + "return %s\n" % (default_next_transition))
    else:
        fout.write(spaces(4) + "return nil\n")
    fout.write("end\n\n")

    fout.write(
        "function %sHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)\n" % (headerUpper))
    if (len(next_transitions) > 0):
        vals = transition_dict.values()
        rbit_num = sum(vals)
        for tk in transition_key:
            fout.write(
                spaces(4) + "if not namedArgs[pre .. '%s'] then\n" % (tk.upper()))
            fout.write(
                spaces(8) + "for name, _port in pairs(nextHeaderResolve) do\n")
            fout.write(spaces(12) + "if nextHeader == name then\n")
            if len(transition_key) == 1:
                fout.write(
                    spaces(16) + "namedArgs[pre .. '%s'] = _port\n" % (tk.upper()))
                break
            elif len(transition_key) > 1:
                rbit_num -= transition_dict[tk]
                mask = gen_hex_mask(rbit_num, transition_dict[tk])
                if rbit_num > 0:
                    fout.write(spaces(
                        16) + "namedArgs[pre .. '%s'] = rshift(band(_port, %sULL), %s)\n" % (tk.upper(), mask, rbit_num))
                else:
                    fout.write(spaces(
                        16) + "namedArgs[pre .. '%s'] = band(_port, %sULL)\n" % (tk.upper(), mask))
            fout.write(spaces(16) + "break\n")
            fout.write(spaces(12) + "end\n" + spaces(8) +
                       "end\n" + spaces(4) + "end\n")
    fout.write(spaces(4) + "return namedArgs\n")
    fout.write("end\n")

    fout.write("\n-----------------------------------------------------\n")
    fout.write("---- Metatypes")
    fout.write("\n-----------------------------------------------------\n")
    fout.write("%s.metatype = %sHeader\n" % (headerUpper, headerUpper))
    fout.write("\nreturn %s" % (headerUpper))

    fout.close()


control_graph = make_control_graph_multi(data["parsers"])
header_ports, header_types = find_data_headers(
    data["headers"], data["header_types"])
try:
    local_name = data["program"]
except KeyError:
    local_name = sys.argv[1]
local_name = local_name[local_name.rfind('/')+1:local_name.rfind('.')]

copy_of_graph = control_graph[:]
paths = make_tree(copy_of_graph)
rmv_headers = []
sub_headers = []
for path in paths:
    find_ethernet(path, rmv_headers, sub_headers)
    print("rmv_headers = ", rmv_headers)
    print("sub_headers = ", sub_headers)
rmv_headers = set(rmv_headers)
sub_headers = set(sub_headers)
for item in sub_headers:
    if item in rmv_headers:
        rmv_headers.remove(item)

# iterates over the headers which are relevant to packet generation, filters out standard headers
for i in range(len(header_ports)):
    if is_builtin_header(header_ports[i]):
        continue

    if start_with_eth != 'true' or header_ports[i] not in rmv_headers:
        destination = os.path.join(DESTINATION, local_name + "_" + \
            header_ports[i] + ".lua")
        make_template(
            control_graph, header_ports[i], header_types[i], destination, header_ports, local_name+"_")

# next header addition info
d = {'ethernet': [],
     'ipv4': [],
     'ipv6': [],
     'tcp': [],
     'udp': []
     }

file_map = {
    'ethernet': 'MoonGen/libmoon/lua/proto/ethernet.lua',
    'ipv4': 'MoonGen/libmoon/lua/proto/ip4.lua',
            'ipv6': 'MoonGen/libmoon/lua/proto/ip6.lua',
            'tcp': 'MoonGen/libmoon/lua/proto/tcp.lua',
            'udp': 'MoonGen/libmoon/lua/proto/udp.lua'

}

for i in range(len(control_graph)):
    edge = control_graph[i]
    if ((edge[0] == 'ethernet' and config.ETHER_DETECT) or (edge[0] == 'ipv4' and config.IPv4_DETECT) or (edge[0] == 'ipv6' and config.IPv6_DETECT) or (edge[0] == 'tcp' and config.TCP_DETECT) or (edge[0] == 'udp' and config.UDP_DETECT)):
        d[edge[0]].append(edge[-1])


def remove_headers(l):
    l_dash = []
    for i in l:
        if ((i == 'final') or (i == 'ethernet' and config.ETHER_DETECT) or (i == 'ipv4' and config.IPv4_DETECT) or (i == 'ipv6' and config.IPv6_DETECT) or (i == 'tcp' and config.TCP_DETECT) or (i == 'udp' and config.UDP_DETECT)) == False:
            l_dash.append(str(i))
    return l_dash


for k, v in d.items():
    d[k] = remove_headers(d[k])
table = [[file_map[k], v] for k, v in d.items() if len(v) > 0]
print ("---------------------------------------------------------------------")
print (tabulate(table, headers=[
       'Standard headers\' src file to be modified', 'Headers to be added in resolveNextHeader']))
