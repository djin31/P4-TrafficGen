import json
import sys
import os
import math
from tabulate import tabulate
from common import *

# global variables for common header types
ETHER_DETECT = False
IPv4_DETECT = False
IPv6_DETECT = False
TCP_DETECT = False
UDP_DETECT = False

DEBUG = False

# open file to load json data
# standardize destination path
data = merge_padding(read_jsondata(sys.argv[1]))
DESTINATION = sys.argv[2]
if (DESTINATION[-1] != '/'):
    DESTINATION += '/'

# check if debug mode activated or not
if (len(sys.argv) > 3):
    if (sys.argv[-2] == '-d'):
        DEBUG = True

# variable to store the list of tables created by the scripts
tables_created = []


# find headers and their types which appear within a packet i.e. are not metadata
def find_data_headers(headers, header_types):
    global ETHER_DETECT
    global IPv4_DETECT
    global IPv6_DETECT
    global TCP_DETECT
    global UDP_DETECT

    header_ports = []
    header_dict = {}

    for header_id in range(len(headers)):
        global input
        try:
            input = raw_input
        except NameError:
            pass
        if not (headers[header_id]['metadata']):
            name = headers[header_id]['name']
            if name.find('[') != (-1):
                name = name[:name.find('[')]
            header_ports.append(name)
            header_dict[name] = search_header_type(
                header_types, headers[header_id]["header_type"])

            # functionality to use common headers to be added
            if name == 'ethernet':
                temp = input(
                    "\nEthernet header detected, would you like the standard ethernet header to be used(y/n) : ").strip()
                if temp == 'y':
                    ETHER_DETECT = True
            elif name == 'ipv4':
                temp = input(
                    "\nIPv4 header detected, would you like the standard IPv4 header to be used(y/n) : ").strip()
                if temp == 'y':
                    IPv4_DETECT = True
            elif name == 'ipv6':
                temp = input(
                    "\nIPv6 header detected, would you like the standard IPv6 header to be used(y/n) : ").strip()
                if temp == 'y':
                    IPv6_DETECT = True
            elif name == 'tcp':
                temp = input(
                    "\nTCP header detected, would you like the standard TCP header to be used(y/n) : ").strip()
                if temp == 'y':
                    TCP_DETECT = True
            elif name == 'udp':
                temp = input(
                    "\nUDP header detected, would you like the standard UDP header to be used(y/n) : ").strip()
                if temp == 'y':
                    UDP_DETECT = True

    header_ports = list(set(header_ports))

    header_types = []
    for i in header_ports:
        header_types.append(header_dict[i])

    if DEBUG:
        print("\nHeaders \n")
        for i in range(len(header_ports)):
            print(header_ports[i], header_types[i]["name"])

    for i in range(len(header_types)):
        if ETHER_DETECT and header_ports[i] == 'ethernet' or IPv4_DETECT and header_ports[
                i] == 'ipv4' or IPv6_DETECT and header_ports[i] == 'ipv6' or TCP_DETECT and header_ports[
                i] == 'tcp' or UDP_DETECT and header_ports[i] == 'udp':
            continue
        else:
            header_type = header_types[i]
            total_hdr_length = 0
            hdr_field_cnt = 0
            for field in header_type['fields']:
                try:
                    total_hdr_length += field[1]
                    hdr_field_cnt += 1
                except:
                    pass

    return header_ports, header_types


# returns suitable datatype for the field
# currently promoting all fields to 8, 16, 32, or 64 bit fields
def predict_type(field):
    if (field <= 8):
        return "uint8_t"
    if (field <= 16):
        return "uint16_t"
    if (field <= 24):
        return "uint24_t"
    if (field <= 32):
        return "uint32_t"
    if (field <= 40):
        return "uint40_t"
    if (field <= 48):
        return "uint48_t"
    if (field <= 64):
        return "uint64_t"
    return "-- fill blank here " + str(field)


def predict_input_type(field):
    if (field <= 8):
        return "uint8_t"
    if (field <= 16):
        return "uint16_t"
    if (field <= 32):
        return "uint32_t"
    if (field <= 64):
        return "uint64_t"


def host_network_conversion(field):
    if (field[1] <= 8):
        return ""
    if (field[1] <= 16):
        return "htons"
    if (field[1] <= 32):
        return "htonl"
    if (field[1] <= 64):
        return "htobe64"
    return "-- fill blank here"


def field_segmenter(fout_header, field, cap, size, field_parts, tmp_list, field_sgmnt_lst):
    if (size - cap) <= 0:
        fout_header.write(",\n" + spaces(12) + " " +
                          spaces(4) + " %s : %s" % (field[0], field[1]))
        tmp_list.extend([(field[0], field[1])])
        field_sgmnt_lst[field[0]] = [field[1]]
        if (size - cap) == 0:
            cap = 8
            field_parts.append(tmp_list)
            tmp_list = []
        else:
            cap = cap - size
    else:
        offset = 1
        fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                          " %s_%s : %s" % (field[0], offset, cap))
        field_sgmnt_lst[field[0]] = [cap]
        tmp_list.extend([(field[0]+("_%s" % (offset)), cap)])
        field_parts.append(tmp_list)
        tmp_list = []
        size = size - cap
        cap = 8
        offset += 1
        while(size >= cap):
            fout_header.write(",\n" + spaces(12) + " " +
                              spaces(4) + " %s_%s : %s" % (field[0], offset, cap))
            field_sgmnt_lst[field[0]].extend([cap])
            tmp_list.extend([(field[0]+("_%s" % (offset)), cap)])
            field_parts.append(tmp_list)
            tmp_list = []
            size = size - cap
        offset += 1
        if size > 0:
            fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                              " %s_%s : %s" % (field[0], offset, size))
            field_sgmnt_lst[field[0]].extend([size])
            tmp_list.extend([(field[0]+("_%s" % (offset)), size)])
            cap = cap - size
    return cap


def handle_special_len(fout_header, field_sgmnt_lst, l, fields, init_idx, end_idx):
    if l == 24:
        s = (16, 8)
    elif l == 40:
        s = (32, 8)
    elif l == 48:
        s = (32, 16)

    tmp_list = []
    field_parts = []

    break_point = end_idx
    accum = 0
    till_full = s[0]
    for i in range(init_idx, end_idx+1):
        accum += fields[i][1]
        if accum > s[0]:
            break_point = i
            break
    if break_point == init_idx:
        offset = 1
        fout_header.write(spaces(8) + "%s " + spaces(4) + " " %
                          (predict_type(s[0])))
        fout_header.write("%s_%s : 8" % (fields[init_idx][0], offset))
        field_sgmnt_lst[fields[init_idx][0]] = [8]
        till_full -= 8
        size = fields[init_idx][1] - 8
        offset += 1
        while till_full > 0:
            fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                              " %s_%s : 8" % (fields[init_idx][0], offset))
            field_sgmnt_lst[fields[init_idx][0]].extend([8])
            till_full -= 8
            offset += 1
            size -= 8
        fout_header.write(";\n")
    else:
        size = fields[init_idx][1]
        offset = 1
        cap = 8
        fout_header.write("#if (BYTE_ORDER == BIG_ENDIAN)\n")
        fout_header.write(spaces(8) + "%s " + spaces(4) + " " %
                          (predict_type(s[0])))
        if (size - 8) <= 0:
            fout_header.write("%s : %s" %
                              (fields[init_idx][0], fields[init_idx][1]))
            tmp_list.extend([(fields[init_idx][0], fields[init_idx][1])])
            field_sgmnt_lst[fields[init_idx][0]] = [fields[init_idx][1]]
            if (size - cap) == 0:
                cap = 8
                field_parts.append(tmp_list)
                tmp_list = []
            else:
                cap -= size
            till_full -= fields[init_idx][1]
        else:
            fout_header.write("%s_%s : 8" % (fields[init_idx][0], offset))
            field_sgmnt_lst[fields[init_idx][0]].extend([8])
            tmp_list.extend([(fields[init_idx][0]+("_%s" % (offset)), 8)])
            field_parts.append(tmp_list)
            tmp_list = []
            offset += 1
            till_full -= 8
            while size >= 8:
                fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                                  " %s_%s : 8" % (fields[init_idx][0], offset))
                field_sgmnt_lst[fields[init_idx][0]].extend([8])
                tmp_list.extend(	[(fields[init_idx][0]+("_%s" % (offset)), 8)])
                field_parts.append(tmp_list)
                tmp_list = []
                size = size - 8
                till_full -= 8
                offset += 1
            if size > 0:
                fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                                  " %s_%s : %s" % (fields[init_idx][0], offset, size))
                field_sgmnt_lst[fields[init_idx][0]].extend([size])
                tmp_list.extend(
                    [(fields[init_idx][0]+("_%s" % (offset)), size)])
                till_full -= size
                cap -= size
        for i in range(init_idx+1, break_point):
            size = fields[i][1]
            cap = field_segmenter(fout_header, fields[i], cap,
                                  size, field_parts, tmp_list, field_sgmnt_lst)
            till_full -= fields[i][1]
        size = fields[break_point][1]
        offset = 1

        # it is not possible for till_full to be less than cap unless it is zero and cap is 8
        if till_full >= cap:
            fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                              " %s_%s : %s" % (fields[break_point][0], offset, cap))
            field_sgmnt_lst[fields[break_point][0]] = [cap]
            tmp_list.extend([(fields[break_point][0]+("_%s" % (offset)), cap)])
            field_parts.append(tmp_list)
            tmp_list = []
            till_full -= cap
            size -= cap
            offset += 1
            cap = 8
        while till_full > 0:
            fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                              " %s_%s : 8" % (fields[break_point][0], offset))
            field_sgmnt_lst[fields[break_point][0]].extend([8])
            field_parts.append(
                [(fields[break_point][0]+("_%s" % (offset)), 8)])
            offset += 1
            till_full -= 8
            size -= cap
        fout_header.write(";\n")
        fout_header.write("#elif (BYTE_ORDER == LITTLE_ENDIAN)\n")
        fout_header.write(spaces(8) + "%s " + spaces(4) + " " %
                          (predict_type(s[0])))
        for k in range(len(field_parts)):
            segment = field_parts[k]
            for j in reversed(range(len(segment))):
                if k == 0 and j == (len(segment)-1):
                    fout_header.write("%s : %s" %
                                      (segment[j][0], segment[j][1]))
                else:
                    fout_header.write(
                        ",\n" + spaces(12) + " " + spaces(4) + " %s : %s" % (segment[j][0], segment[j][1]))
        fout_header.write(";\n")
        fout_header.write("#endif\n")
    field_parts = []
    if break_point != (end_idx - 1):
        fout_header.write("#if (BYTE_ORDER == BIG_ENDIAN)\n")
    fout_header.write(spaces(8) + "%s " + spaces(4) + " " %
                      (predict_type(s[1])))

    cap = 8

    if size < 8:
        fout_header.write("%s_%s : %s" %
                          (fields[break_point][0], offset, size))
        field_sgmnt_lst[fields[break_point][0]].extend([size])
        tmp_list.extend([(fields[break_point][0]+("_%s" % (offset)), size)])
        cap -= size
    else:
        fout_header.write("%s_%s : 8" % (fields[break_point][0], offset))
        field_sgmnt_lst[fields[break_point][0]].extend([8])
        tmp_list.extend([(fields[break_point][0]+("_%s" % (offset)), 8)])
        field_parts.append(tmp_list)
        tmp_list = []
        size -= 8
        offset += 1
        while size >= 8:
            fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                              " %s_%s : 8" % (fields[break_point][0], offset))
            field_sgmnt_lst[fields[break_point][0]].extend([8])
            tmp_list.extend([(fields[break_point][0]+("_%s" % (offset)), 8)])
            field_parts.append(tmp_list)
            tmp_list = []
            size = size - 8
            offset += 1
        if size > 0:
            fout_header.write(",\n" + spaces(12) + " " + spaces(4) +
                              " %s_%s : %s" % (fields[init_idx][0], offset, size))
            field_sgmnt_lst[fields[break_point][0]].extend([size])
            tmp_list.extend(
                [(fields[break_point][0]+("_%s" % (offset)), size)])
            cap -= size
    for i in range(break_point+1, end_idx):
        size = fields[i][1]
        cap = field_segmenter(
            fout_header, fields[i], cap, size, field_parts, tmp_list, field_sgmnt_lst)
    fout_header.write(";\n")
    if break_point != (end_idx - 1):
        fout_header.write("#elif (BYTE_ORDER == LITTLE_ENDIAN)\n")
        fout_header.write(spaces(8) + "%s " + spaces(4) + " " %
                          (predict_type(s[1])))
        for k in range(len(field_parts)):
            segment = field_parts[k]
            for j in reversed(range(len(segment))):
                if k == 0 and j == (len(segment)-1):
                    fout_header.write("%s : %s" %
                                      (segment[j][0], segment[j][1]))
                else:
                    fout_header.write(
                        ",\n" + spaces(12) + " " + spaces(4) + " %s : %s" % (segment[j][0], segment[j][1]))
        fout_header.write(";\n")
        fout_header.write("#endif\n")
    field_parts = []
    return


def make_header_struct(fout_header, check_points, cumulative_hdr_len, header_type):
    init_idx = 0
    bias = 0
    cap = 8
    fields = []
    field_sgmnt_lst = {}
    for i in range(len(check_points)):
        if i == 0:
            if check_points[i] == 0:
                fout_header.write(spaces(
                    8) + "%s " % (predict_type(cumulative_hdr_len[check_points[i]]-bias)) + spaces(4) + " ")
                fout_header.write("%s;\n" %
                                  (header_type["fields"][init_idx][0]))
                fields.append([(header_type["fields"][init_idx][0], predict_type(
                    cumulative_hdr_len[check_points[i]]-bias))])
                field_sgmnt_lst[header_type["fields"][init_idx][0]] = [
                    header_type["fields"][init_idx][1]]
            elif (cumulative_hdr_len[check_points[i]] == 24) or (cumulative_hdr_len[check_points[i]] == 40) or (cumulative_hdr_len[check_points[i]] == 48):
                handle_special_len(fout_header, field_sgmnt_lst,
                                   cumulative_hdr_len[check_points[i]], header_type["fields"], init_idx, check_points[i]+1)
            else:
                field_parts = []
                tmp_list = []
                fout_header.write("#if (BYTE_ORDER == BIG_ENDIAN)\n")
                fout_header.write(spaces(
                    8) + "%s " % (predict_type(cumulative_hdr_len[check_points[i]]-bias)) + spaces(4) + " ")
                size = header_type["fields"][init_idx][1]
                if (size - cap) <= 0:
                    fout_header.write("%s : %s" % (
                        header_type["fields"][init_idx][0], header_type["fields"][init_idx][1]))
                    tmp_list.extend(
                        [(header_type["fields"][init_idx][0], header_type["fields"][init_idx][1])])
                    field_sgmnt_lst[header_type["fields"][init_idx][0]] = [
                        header_type["fields"][init_idx][1]]
                    if (size - cap) == 0:
                        cap = 8
                        field_parts.append(tmp_list)
                        tmp_list = []
                    else:
                        cap = cap - size
                else:
                    offset = 1
                    fout_header.write("%s_%s : %s" % (
                        header_type["fields"][init_idx][0], offset, cap))
                    field_sgmnt_lst[header_type["fields"][init_idx][0]] = [cap]
                    tmp_list.extend(
                        [(header_type["fields"][init_idx][0]+("_%s" % (offset)), cap)])
                    field_parts.append(tmp_list)
                    tmp_list = []
                    size = size - cap
                    cap = 8
                    offset += 1
                    while(size >= cap):
                        fout_header.write(",\n" + spaces(12) + " " + spaces(4) + " %s_%s : %s" % (
                            header_type["fields"][init_idx][0], offset, cap))
                        field_sgmnt_lst[header_type["fields"][init_idx][0]].extend([
                                                                                   cap])
                        tmp_list.extend(
                            [(header_type["fields"][init_idx][0]+("_%s" % (offset)), cap)])
                        field_parts.append(tmp_list)
                        tmp_list = []
                        size = size - cap
                        offset += 1
                    if size > 0:
                        fout_header.write(",\n" + spaces(12) + " " + spaces(4) + " %s_%s : %s" % (
                            header_type["fields"][init_idx][0], offset, size))
                        field_sgmnt_lst[header_type["fields"]
                                        [init_idx][0]].extend([size])
                        tmp_list.extend(
                            [(header_type["fields"][init_idx][0]+("_%s" % (offset)), size)])
                        cap = cap - size
                for field in header_type["fields"][init_idx+1: check_points[i]+1]:
                    size = field[1]
                    cap = field_segmenter(
                        fout_header, field, cap, size, field_parts, tmp_list, field_sgmnt_lst)
                fout_header.write(";\n")
                fields.append(field_parts)
                fout_header.write("#elif (BYTE_ORDER == LITTLE_ENDIAN)\n")
                fout_header.write(spaces(
                    8) + "%s " % (predict_type(cumulative_hdr_len[check_points[i]]-bias)) + spaces(4) + " ")
                for k in range(len(field_parts)):
                    segment = field_parts[k]
                    for j in reversed(range(len(segment))):
                        if k == 0 and j == (len(segment)-1):
                            fout_header.write("%s : %s" %
                                              (segment[j][0], segment[j][1]))
                        else:
                            fout_header.write(
                                ",\n" + spaces(12) + " " + spaces(4) + " %s : %s" % (segment[j][0], segment[j][1]))
                fout_header.write(";\n")
                fout_header.write("#endif\n")
                field_parts = []
        elif i > 0:
            if check_points[i] - check_points[i-1] == 1:
                fout_header.write(spaces(
                    8) + "%s " % (predict_type(cumulative_hdr_len[check_points[i]]-bias)) + spaces(4) + " ")
                fout_header.write("%s;\n" %
                                  (header_type["fields"][init_idx][0]))
                fields.append((header_type["fields"][init_idx][0], predict_type(
                    cumulative_hdr_len[check_points[i]]-bias)))
                field_sgmnt_lst[header_type["fields"][init_idx][0]] = [
                    header_type["fields"][init_idx][1]]
            elif (cumulative_hdr_len[check_points[i]]-bias == 24) or (cumulative_hdr_len[check_points[i]]-bias) == 40 or (cumulative_hdr_len[check_points[i]]-bias == 48):
                handle_special_len(fout_header, field_sgmnt_lst,
                                   cumulative_hdr_len[check_points[i]]-bias, header_type["fields"], init_idx, check_points[i]+1)
            else:
                field_parts = []
                tmp_list = []
                fout_header.write("#if (BYTE_ORDER == BIG_ENDIAN)\n")
                fout_header.write(spaces(
                    8) + "%s " % (predict_type(cumulative_hdr_len[check_points[i]]-bias)) + spaces(4) + " ")
                size = header_type["fields"][init_idx][1]
                if (size - cap) <= 0:
                    fout_header.write("%s : %s" % (
                        header_type["fields"][init_idx][0], header_type["fields"][init_idx][1]))
                    tmp_list.extend(
                        [(header_type["fields"][init_idx][0], header_type["fields"][init_idx][1])])
                    field_sgmnt_lst[header_type["fields"][init_idx][0]] = [
                        header_type["fields"][init_idx][1]]
                    if (size - cap) == 0:
                        cap = 8
                        field_parts.append(tmp_list)
                        tmp_list = []
                    else:
                        cap = cap - size
                else:
                    offset = 1
                    fout_header.write("%s_%s : %s" % (
                        header_type["fields"][init_idx][0], offset, cap))
                    field_sgmnt_lst[header_type["fields"][init_idx][0]] = [cap]
                    tmp_list.extend(
                        [(header_type["fields"][init_idx][0]+("_%s" % (offset)), cap)])
                    field_parts.append(tmp_list)
                    tmp_list = []
                    size = size - cap
                    cap = 8
                    offset += 1
                    while(size >= cap):
                        fout_header.write(",\n" + spaces(12) + " " + spaces(4) + " %s%s : %s" %
                                          (header_type["fields"][init_idx][0], offset, cap))
                        field_sgmnt_lst[header_type["fields"][init_idx][0]].extend([
                                                                                   cap])
                        tmp_list.extend(
                            [(header_type["fields"][init_idx][0]+("_%s" % (offset)), cap)])
                        field_parts.append(tmp_list)
                        tmp_list = []
                        size = size - cap
                        offset += 1
                    if size > 0:
                        fout_header.write(",\n" + spaces(12) + " " + spaces(4) + " %s%s : %s" %
                                          (header_type["fields"][init_idx][0], offset, size))
                        field_sgmnt_lst[header_type["fields"]
                                        [init_idx][0]].extend([size])
                        tmp_list.extend(
                            [(header_type["fields"][init_idx][0]+("_%s" % (offset)), size)])
                        cap = cap - size
                for field in header_type["fields"][init_idx+1: check_points[i]+1]:
                    size = field[1]
                    cap = field_segmenter(
                        fout_header, field, cap, size, field_parts, tmp_list, field_sgmnt_lst)
                fout_header.write(";\n")
                fields.append(field_parts)
                fout_header.write("#elif (BYTE_ORDER == LITTLE_ENDIAN)\n")
                fout_header.write(spaces(
                    8) + "%s " % (predict_type(cumulative_hdr_len[check_points[i]]-bias)) + spaces(4) + " ")
                for k in range(len(field_parts)):
                    segment = field_parts[k]
                    for j in reversed(range(len(segment))):
                        if k == 0 and j == (len(segment)-1):
                            fout_header.write("%s : %s" %
                                              (segment[j][0], segment[j][1]))
                        else:
                            fout_header.write(
                                ",\n" + spaces(12) + " " + spaces(4) + " %s : %s" % (segment[j][0], segment[j][1]))
                fout_header.write(";\n")
                fout_header.write("#endif\n")
                field_parts = []
                #fout_header.write("%s : %s" %(header_type["fields"][init_idx][0], header_type["fields"][init_idx][1]))
                # for field in header_type["fields"][init_idx+1 : check_points[i]+1]:
                #    fout_header.write(",\n" + spaces(12) + " " + spaces(4) + " %s : %s" %(field[0],field[1]))
                # fout_header.write(";\n")
        init_idx = check_points[i] + 1
        bias = cumulative_hdr_len[check_points[i]]
    return field_sgmnt_lst


def gen_hex_mask_cumulative(field_segments, total_len):
    hex_mask = []
    init_val = 0
    for idx in range(len(field_segments)):
        init_val += field_segments[idx]
        hex_mask.append(gen_hex_mask(total_len - init_val, field_segments[idx]))
    return hex_mask


def make_template(control_graph, header, header_type, destination, header_ports):
    '''makes the actual lua script given the relevant header type and next and previous state transition information'''
    fout_header = open(destination + ".h", "w")
    fout_source = open(destination + ".cpp", "w")

    fout_header.write(
        "//Template for addition of new protocol '%s'\n\n" % header)
    fout_header.write("#ifndef %s\n" % ("P4_" + header.upper() + "_LAYER"))
    fout_header.write("#define %s\n\n" % ("P4_" + header.upper() + "_LAYER"))
    fout_header.write("#include <cstring>\n")
    fout_header.write("#include \"Layer.h\"\n")
    fout_header.write(
        '#include "uint24_t.h"\n#include "uint40_t.h"\n#include "uint48_t.h"\n')
    fout_header.write(
        "#if defined(WIN32) || defined(WINx64)\n#include <winsock2.h>\n#elif LINUX\n#include <in.h>\n#endif\n\n")
    fout_header.write("namespace pcpp{\n" +
                      spaces(4) + "#pragma pack(push,1)\n")
    fout_header.write(spaces(4) + "struct %s{\n" % (header.lower() + "hdr"))

    cumulative_hdr_len = [None] * len(header_type["fields"])
    check_points = []
    total_len = 0
    i = 0
    for field in header_type["fields"]:
        try:
            total_len += field[1]
            cumulative_hdr_len[i] = total_len
            if total_len % 8 == 0:
                check_points.append(i)
            i += 1
        except TypeError:
            field[1] = int(input('Variable length field "' + field[0] +
                                 '" detected in "' + header + '". Enter its length\n'))
            total_len += field[1]
            cumulative_hdr_len[i] = total_len
            if total_len % 8 == 0:
                check_points.append(i)
            i += 1

    field_sgmnt_lst = make_header_struct(
        fout_header, check_points, cumulative_hdr_len, header_type)

    '''
    for field in header_type["fields"]:
        try:
            fout_header.write(spaces(8) + "%s " + spaces(4) + " %s;\n" %(predict_type(field[1]),field[0]))
        except TypeError:
            field[1] = int(input('Variable length field "' + field[0] + '" detected in "' + header + '". Enter its length\n'))
            fout_header.write(spaces(8) + "%s " + spaces(4) + " %s;\n" %(predict_type(field[1]),field[0]))
    '''

    fout_header.write(spaces(4) + "};\n\n")

    fout_header.write(spaces(4) + "#pragma pack(pop)\n")
    fout_header.write(
        spaces(4) + "class %sLayer: public Layer{\n" % (header.capitalize()))
    fout_header.write(spaces(8) + "public:\n")

    # constructor to constuct packet from raw data
    fout_header.write(
        spaces(8) + "%sLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet): Layer(data, dataLen, prevLayer, packet) {m_Protocol = P4_%s;}\n" % (
            header.capitalize(), header.upper()))

    # default constructor for packet with empty raw data
    fout_header.write(
        spaces(8) + "%sLayer(){\n" % (header.capitalize()) + spaces(12) + "m_DataLen = sizeof(%shdr);\n" % (header.lower()) + spaces(12) + "m_Data = new uint8_t[m_DataLen];\n" + spaces(12) + "memset(m_Data, 0, m_DataLen);\n" + spaces(12) + "m_Protocol = P4_%s;\n" % (header.upper()) + spaces(8) + "}\n")

    fout_header.write("\n" + spaces(8) +
                      " // Getters and Setters for fields\n")

    for field in header_type["fields"]:
        fout_header.write(spaces(8) + " %s get%s();\n" %
                          (predict_input_type(field[1]), str(field[0]).capitalize()))
        fout_header.write(spaces(8) + " void set%s(%s value);\n" %
                          (str(field[0]).capitalize(), predict_input_type(field[1])))

    fout_header.write("\n" + spaces(8) + " inline %shdr* get%sHeader() { return (%shdr*)m_Data; }\n\n" % (
        header.lower(), header.capitalize(), header.lower()))
    fout_header.write(spaces(8) + " void parseNextLayer();\n\n")
    fout_header.write(spaces(
        8) + " inline size_t getHeaderLen() { return sizeof(%shdr); }\n\n" % (header.lower()))
    fout_header.write(spaces(8) + " void computeCalculateFields() {}\n\n")
    fout_header.write(spaces(8) + " std::string toString();\n\n")
    fout_header.write(spaces(
        8) + " OsiModelLayer getOsiModelLayer() { return OsiModelApplicationLayer; }\n\n")
    fout_header.write(spaces(4) + "};\n")
    fout_header.write("}\n#endif")
    fout_header.close()

    default_next_transition = None
    transition_key = None
    next_transitions = []
    for edge in control_graph:
        if (header == edge[0]):
            if (edge[1] != None):
                transition_key = edge[1]
                next_transitions.append((edge[-1], edge[-2]))
            else:
                default_next_transition = edge[-1]

    fout_source.write(
        "#define LOG_MODULE PacketLogModule%sLayer\n\n" % (header.capitalize()))
    fout_source.write("#include \"%s.h\"\n" %
                      (destination[destination.rfind('/') + 1:]))

    if (len(next_transitions) > 0):
        for transition in next_transitions:
            fout_source.write("#include \"%s.h\"\n" %
                              (local_name+'_'+transition[0]))

    fout_source.write(
        "#include \"PayloadLayer.h\"\n#include \"IpUtils.h\"\n#include \"Logger.h\"\n")
    fout_source.write(
        "#include <string.h>\n#include <sstream>\n#include <endian.h>\n\n")
    fout_source.write("namespace pcpp{\n")

    for field in header_type["fields"]:
        field_segments = field_sgmnt_lst[field[0]]
        fout_source.write(spaces(4) + "%s %sLayer::get%s(){\n" % (
            predict_input_type(field[1]), header.capitalize(), str(field[0]).capitalize()))
        if len(field_segments) == 1:
            fout_source.write(spaces(8) + "%s %s;\n" %
                              (predict_type(field[1]), field[0]))
            fout_source.write(spaces(
                8) + "%shdr* hdrdata = (%shdr*)m_Data;\n" % (header.lower(), header.lower()))
            if (field[1] == 24 or field[1] == 40 or field[1] == 48):
                fout_source.write(
                    spaces(8) + "UINT%d_HTON(%s,hdrdata->%s);\n" % (field[1], field[0], field[0]))
                fout_source.write(
                    spaces(8) + "%s return_val = UINT%d_GET(%s);\n" % (predict_input_type(field[1]), field[1], field[0]))
                fout_source.write(
                    spaces(8) + "return return_val;\n" + spaces(4) + "}\n\n")
            else:
                fout_source.write(spaces(8) + "%s = %s(hdrdata->%s);\n" %
                                  (field[0], host_network_conversion(field), field[0]))
                fout_source.write(spaces(8) + "return %s;\n" %
                                  (field[0]) + spaces(4) + "}\n\n")
        elif len(field_segments) > 1:
            fout_source.write(spaces(8) + "%s %s;\n" %
                              (predict_input_type(field[1]), field[0]))
            fout_source.write(spaces(
                8) + "%shdr* hdrdata = (%shdr*)m_Data;\n" % (header.lower(), header.lower()))
            offset = 1
            init_val = field_segments[0]
            fout_source.write(spaces(8) + "%s = ((hdrdata->%s) << %s)" %
                              (field[0], field[0]+"_"+str(offset), field[1] - init_val))
            offset += 1
            for i in range(1, len(field_segments[:-1])):
                init_val += field_segments[i]
                fout_source.write(" + ((hdrdata->%s) << %s)" %
                                  (field[0]+"_"+str(offset), field[1] - init_val))
                offset += 1
            fout_source.write(" + (hdrdata->%s);\n" %
                              (field[0]+"_"+str(offset)))
            fout_source.write(spaces(8) + "return %s;\n" %
                              (field[0]) + spaces(4) + "}\n\n")
        fout_source.write(spaces(4) + "void %sLayer::set%s(%s value){\n" % (
            header.capitalize(), str(field[0]).capitalize(), predict_input_type(field[1])))
        fout_source.write(spaces(
            8) + "%shdr* hdrdata = (%shdr*)m_Data;\n" % (header.lower(), header.lower()))
        if len(field_segments) == 1:
            if (field[1] == 24 or field[1] == 40 or field[1] == 48):
                fout_source.write(
                    spaces(8) + "uint%d_t value_set;\n" % (field[1]))
                fout_source.write(
                    spaces(8) + "UINT%d_SET(value_set, value);\n" % (field[1]))
                fout_source.write(
                    spaces(8) + "UINT%d_HTON(hdrdata->%s, value_set);\n" % (field[1], field[0]))
            else:
                fout_source.write(spaces(8) + "hdrdata->%s = %s(value);\n" %
                                  (field[0], host_network_conversion(field)))
        elif len(field_segments) > 1:
            hex_mask = gen_hex_mask_cumulative(field_segments, field[1])
            offset = 1
            init_val = 0
            for i in range(len(field_segments[:-1])):
                init_val += field_segments[i]
                fout_source.write(spaces(8) + "hdrdata->%s_%s = (value & %s) >> %s;\n" %
                                  (field[0], offset, hex_mask[i], field[1] - init_val))
                offset += 1
            fout_source.write(spaces(
                8) + "hdrdata->%s_%s = (value & %s);\n" % (field[0], offset, hex_mask[-1]))
        fout_source.write(spaces(4) + "}\n")

    fout_source.write(
        spaces(4) + "void %sLayer::parseNextLayer(){\n" % (header.capitalize()))
    fout_source.write(
        spaces(8) + "if (m_DataLen <= sizeof(%shdr))\n" % (header.lower()))
    fout_source.write(spaces(12) + "return;\n\n")

    if (len(next_transitions) > 0):
        transition_dict = {}
        for tk in transition_key:
            for field in header_type["fields"]:
                if (field[0] == tk):
                    fout_source.write(spaces(8) + "%s %s = %sLayer::get%s();\n" % (
                        predict_input_type(field[1]), tk, header.capitalize(), str(field[0]).capitalize()))
                    transition_dict[field[0]] = nibble(field[1])
                    break
        for transition in next_transitions[:-1]:
            init_idx = 2
            fout_source.write(spaces(8) + "if (%s == 0x%s" % (
                transition_key[0], transition[1][init_idx:init_idx+transition_dict[transition_key[0]]]))
            for idx in range(1, len(transition_key)):
                init_idx += transition_dict[transition_key[idx-1]]
                fout_source.write(" && %s == 0x%s" % (
                    transition_key[idx], transition[1][init_idx:init_idx+transition_dict[transition_key[idx]]]))
            fout_source.write(")\n")
        fout_source.write(
            spaces(12) + "m_NextLayer = new %sLayer(m_Data+sizeof(%shdr), m_DataLen - sizeof(%shdr), this, m_Packet);\n" % (
                transition[0].capitalize(), header.lower(), header.lower()))
        fout_source.write(spaces(8) + "else ")
        transition = next_transitions[-1]
        init_idx = 2
        fout_source.write("if (%s == 0x%s" % (
            transition_key[0], transition[1][init_idx:init_idx+transition_dict[transition_key[0]]]))
        for idx in range(1, len(transition_key)):
            init_idx += transition_dict[transition_key[idx-1]]
            fout_source.write(" && %s == 0x%s" % (
                transition_key[idx], transition[1][init_idx:init_idx+transition_dict[transition_key[idx]]]))
        fout_source.write(")\n")
        fout_source.write(
            spaces(12) + "m_NextLayer = new %sLayer(m_Data+sizeof(%shdr), m_DataLen - sizeof(%shdr), this, m_Packet);\n" % (
                transition[0].capitalize(), header.lower(), header.lower()))

        if (default_next_transition != None):
            fout_source.write(spaces(8) + "else\n")
            if (default_next_transition == "final"):
                fout_source.write(
                    spaces(12) + "m_NextLayer = new PayloadLayer(m_Data + sizeof(%shdr), m_DataLen - sizeof(%shdr), this, m_Packet);\n" % (
                        header.lower(), header.lower()))
            else:
                fout_source.write(
                    spaces(12) + "m_NextLayer = new default_next_transition(m_Data + sizeof(%shdr), m_DataLen - sizeof(%shdr), this, m_Packet);\n" % (
                        header.lower(), header.lower()))
        else:
            fout_source.write(
                spaces(8) + "m_NextLayer = new PayloadLayer(m_Data + sizeof(%shdr), m_DataLen - sizeof(%shdr), this, m_Packet);\n" % (
                    header.lower(), header.lower()))

    fout_source.write(spaces(4) + "}\n")

    fout_source.write(
        "\n" + spaces(4) + "std::string %sLayer::toString(){ return \"\"; }\n\n" % (header.capitalize()))
    fout_source.write("}")


control_graph = make_control_graph_multi(data["parsers"], DEBUG)
header_ports, header_types = find_data_headers(
    data["headers"], data["header_types"])

try:
    local_name = data["program"]
except KeyError:
    local_name = sys.argv[1]
local_name = local_name[local_name.rfind('/') + 1:local_name.rfind('.')]
start_with_eth = sys.argv[-1].lower()

copy_of_graph = control_graph[:]
paths = make_tree(copy_of_graph)
rmv_headers = []
sub_headers = []
for path in paths:
    find_ethernet(path, rmv_headers, sub_headers, ETHER_DETECT)
    print("rmv_headers = ", rmv_headers)
    print("sub_headers = ", sub_headers)
rmv_headers = set(rmv_headers)
sub_headers = set(sub_headers)
for item in sub_headers:
    if item in rmv_headers:
        rmv_headers.remove(item)


for i in range(len(header_ports)):
    if ((ETHER_DETECT and header_ports[i] == 'ethernet') or (IPv4_DETECT and header_ports[i] == 'ipv4') or (
            IPv6_DETECT and header_ports[i] == 'ipv6') or (TCP_DETECT and header_ports[i] == 'tcp') or (
            UDP_DETECT and header_ports[i] == 'udp')):
        continue

    if start_with_eth == 'true':
        if header_ports[i] not in rmv_headers:
            destination = DESTINATION + local_name + "_" + header_ports[i]
            make_template(
                control_graph, header_ports[i], header_types[i], destination, header_ports)
    else:
        destination = DESTINATION + local_name + "_" + header_ports[i]
        make_template(
            control_graph, header_ports[i], header_types[i], destination, header_ports)
