import json
import sys
import os
from common import *

DEBUG = False
MAX_PATH_LENGTH = 10

# to maintain compatibility
global input
try:
    input = raw_input
except NameError:
    pass

# open file to load json data
# standardize destination path
data = read_jsondata(sys.argv[1])
DESTINATION = sys.argv[2]
if (DESTINATION[-1] != '/'):
    DESTINATION += '/'

# debug mode activated or not 
if (len(sys.argv) > 3):
    if (sys.argv[-1] == '-d'):
        DEBUG = True

# variable to store the tables created in the script
tables_created = []

# to remove duplicates while maintaining the same list order
def remove_duplicates(li):
    my_set = set()
    res = []
    for e in li:
        if e not in my_set:
            res.append(e)
            my_set.add(e)
            
    return res


# finds headers that are not part of metadata and return a pair of 
# a. List of headers in the order in which they are defined
# b. dictionary of header names and their types
def find_data_headers(headers, header_types):
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
    

    header_types = []
    for i in header_ports:
        header_types.append(header_dict[i])

    if (DEBUG):
        print("\nHeaders \n")
        for i in range(len(header_ports)):
            print (header_ports[i], header_types[i]["name"])
    return (header_ports, header_types)


# find all possible header orderings that are valid
def possible_paths(init, control_graph, length_till_now):
    if (init == 'final'):
        return [['final']]
    if (length_till_now == MAX_PATH_LENGTH):
        return []
    temp = []
    possible_stops = [i[-1] for i in control_graph if i[0] == init]
    paths = []
    for i in possible_stops:
        temp += (possible_paths(i, control_graph, length_till_now+1))
    for i in temp:
        paths.append([init] + i)
    return paths

def topo_sort_headers(control_graph, header_ports, header_types):
    paths = possible_paths('ethernet', control_graph, 0)
    h_ports={}
    for i in range(len(header_ports)):
        h_ports[header_ports[i]]=header_types[i]
    mega_path = []
    for path in paths:
        mega_path+=path
    mega_path=remove_duplicates(mega_path)
    
    sorted_header_ports = []
    sorted_header_types = []
    for i in mega_path:
        if i in h_ports:
            sorted_header_ports.append(i)
            sorted_header_types.append(h_ports[i])
    return (sorted_header_ports,sorted_header_types)
    
# makes the actual lua script given the relevant header type and next and previous state transition information
def make_template(control_graph, header, header_type, destination, header_ports):
    fout = open(destination, 'w')
    header_lower = "p4_"+header.lower()
    fout.write("-- protocol naming\n")
    fout.write("%s = Proto('%s','%s')\n" %
               (header_lower,header_lower, "P4_"+header.upper() + "Protocol"))

    fout.write("\n-- protocol fields\n")
    
    for field in header_type["fields"]:
        fout.write("local %s_%s = ProtoField.string('%s.%s','%s')\n" %(header_lower, field[0], header_lower, field[0], field[0]))

    fout.write("%s.fields = {"%(header_lower))
    for field in header_type["fields"][:-1]:
        fout.write(header_lower+"_"+field[0]+", ")
    fout.write(header_lower+"_"+header_type["fields"][-1][0]+"}\n\n")


    fout.write("\n-- protocol dissector function\n")
    fout.write("function %s.dissector(buffer,pinfo,tree)\n"%(header_lower))
    fout.write("\tpinfo.cols.protocol = '%s'\n" % ("P4_" + header.upper()))
    fout.write("\tlocal subtree = tree:add(%s,buffer(),'%s Protocol Data')\n" % (header_lower,
        "P4_" + header.upper()))

    next_state_key = ''
    transition_param = []
    for entry in control_graph:
        if (header == entry[0] and entry[1] != None):
            next_state_key = entry[1]
            break

    bit_count = 0
    byte_count = 0
    for field in header_type["fields"]:
        try:
            bitfield1, bitfield2 = bit_count, field[1]      
            bytefield1, bytefield2 = byte_count, int((bit_count + field[1])/8)
            if ((bit_count + field[1])%8!=0):
                bytefield2+=1
            if (field[0]==next_state_key):
                transition_param += [bytefield1,bytefield2,bitfield1,bitfield2]
            byte_count += int((bit_count + field[1])/8)
            
            bit_count = (bit_count + field[1])%8

            fout.write("\t\tsubtree:add(%s_%s,tostring(buffer(%d,%d):bitfield(%d,%d)))\n" %(header_lower,field[0],bytefield1,bytefield2,bitfield1,bitfield2))
        except TypeError:
            field[1] = int(input('Variable length field "' + field[0] + '" detected in "' + header + '". Enter its length\n'))
            bitfield1, bitfield2 = bit_count, field[1]      
            bytefield1, bytefield2 = byte_count, int((bit_count + field[1])/8)
            if ((bit_count + field[1])%8!=0):
                bytefield2+=1
            if (field[0]==next_state_key):
                transition_param += [bytefield1,bytefield2,bitfield1,bitfield2]
            byte_count += int((bit_count + field[1])/8)
            
            bit_count = (bit_count + field[1])%8
            if (bytefield2>((field[1])/8+1)):
                bytefield2=(field[1])/8+1

            fout.write("\t\tsubtree:add(%s_%s,tostring(buffer(%d,%d):bitfield(%d,%d)))\n" %(header_lower,field[0],bytefield1,bytefield2,bitfield1,bitfield2))
            
    if (DEBUG):
        print (header,header_type["name"], next_state_key, transition_param)

    if (next_state_key!='' and next_state_key!=None):
        try:
            fout.write("\tlocal mydissectortable = DissectorTable.get('%s.%s')\n" %("p4_"+header, next_state_key))
            fout.write("\tmydissectortable:try(buffer(%d,%d):bitfield(%d,%d), buffer:range(%d):tvb(),pinfo,tree)\n" % (transition_param[0], transition_param[1], transition_param[2], transition_param[3], byte_count))
        except IndexError:
            fout.write("\t Could not detect suitable parameters\n")
            print ("Parameter error in %s, Please update the file to call next dissector with suitably\n" % (destination))
    fout.write("\nend\n")
    
    fout.write("\nprint( (require 'debug').getinfo(1).source )\n")

    fout.write("\n-- creation of table for next layer(if required)\n")
    if (next_state_key!='' and next_state_key!=None):
        fout.write("local newdissectortable = DissectorTable.new('%s.%s','%s.%s',ftypes.STRING)" %("p4_"+header, next_state_key,"P4_"+header.upper(), next_state_key.upper()))
        tables_created.append((header,next_state_key))
    else:
        fout.write("\n-- No table required")

    fout.write("\n\n-- protocol registration\n")
    for entry in control_graph:
        if (header==entry[-1] and entry[0] in header_ports and entry[1]!=None):
            if (entry[0]!='ethernet'):
                if (entry[2]=='default'):
                    entry[2]='0x0'
                fout.write("my_table = DissectorTable.get('%s.%s')\n" %("p4_"+entry[0], entry[1]))
                fout.write("my_table:add(%s,%s)\n" %(entry[2],header_lower))
            else:
                if (entry[2]=='default'):
                    entry[2]='0x0'
                fout.write("my_table = DissectorTable.get('ethertype')\n")
                fout.write("my_table:add(%s,%s)\n" %(entry[2],header_lower))

    

control_graph = make_control_graph(data["parsers"], DEBUG)
header_ports, header_types = find_data_headers(data["headers"], data["header_types"])
header_ports, header_types = topo_sort_headers(control_graph, header_ports, header_types)
fout = open(DESTINATION+"init.lua",'w')
try:
	local_name = data["program"]
except KeyError:
	local_name = sys.argv[1]
local_name = local_name[local_name.rfind('/')+1:local_name.rfind('.')]

for i in range(len(header_ports)):
    if (header_ports[i]=='ethernet'):
        continue
    destination = DESTINATION + local_name + "_" + str(i) + "_" + header_ports[i] + ".lua"
    fout.write("dofile('%s')\n" %(os.path.abspath(destination)))
    make_template(control_graph, header_ports[i], header_types[i], destination, header_ports)

if (DEBUG):
    print ("\nTables created are\n")
    for i in tables_created:
        print (i)