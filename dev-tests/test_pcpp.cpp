#include "stdlib.h"
#include "PcapFileDevice.h"
#include "EthLayer.h"
#include "basic2_ipv4c.h"
#include "basic2_nona.h"
#include "basic2_parsa.h" 
#include "Packet.h"
#include "iostream"
#include <in.h>
#include <string.h>

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
	switch (protocolType)
	{
	case pcpp::Ethernet:
		return "Ethernet";
	case pcpp::IPv4:
		return "IPv4";
	case pcpp::TCP:
		return "TCP";
	case pcpp::HTTPRequest:
	case pcpp::HTTPResponse:
		return "HTTP";
	case pcpp::P4_ETHERNET:
		return "P4_ETHERNET";
	case pcpp::P4_IPV4C:
		return "P4_IPV4C";
	case pcpp::P4_NONA:
		return "P4_NONA";
	case pcpp::P4_PARSA:
		return "P4_PARSA";
	default:
		return "Unknown";
	}
}

int main(int argc, char* argv[])
{

	pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("aa:bb:cc:dd:ee"), 0x0803);

	pcpp::Ipv4cLayer newIpv4Layer;
	newIpv4Layer.setVersion(0x4);
        newIpv4Layer.setIhl(0x5);
	newIpv4Layer.setDiffserv(0x7);
	newIpv4Layer.setTotallen(0x5);
	newIpv4Layer.setIdentification(0x7511);
	newIpv4Layer.setFlags(0x5);
	newIpv4Layer.setFragoffset(0x1387);
        newIpv4Layer.setIptype(0x23);
	newIpv4Layer.setIptype2(0x75);
        newIpv4Layer.setTtl(0xa);
        newIpv4Layer.setProtocol(0x89);
	newIpv4Layer.setSrcaddr(0x8c527119);
	newIpv4Layer.setDstaddr(0xac1962ab);

	pcpp::NonaLayer newNonaLayer;
	newNonaLayer.setFn1(0x3);
	newNonaLayer.setFn2(0x1);
	newNonaLayer.setFn3(0xB);

	pcpp::Packet newPacket(100);

	newPacket.addLayer(&newEthernetLayer);
	newPacket.addLayer(&newIpv4Layer);
	newPacket.addLayer(&newNonaLayer);

        newPacket.computeCalculateFields();

	pcpp::PcapFileWriterDevice writer2("1_new_packet.pcap");
	writer2.open();
	writer2.writePacket(*(newPacket.getRawPacket()));
	writer2.close();

	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("1_new_packet.pcap");
	if (reader == NULL)
	{
		printf("Cannot determine reader for file type\n");
		exit(1);
	}
	if (!reader->open())
	{
		printf("Cannot open input.pcap for reading\n");
		exit(1);
	}
	pcpp::RawPacket rawPacket;
	if (!reader->getNextPacket(rawPacket))
	{
		printf("Couldn't read the first packet in the file\n");
		return 1;
	}
	reader->close();

	std::cout<<"Raw Packet = "<< rawPacket.getRawData()<<std::endl;

	pcpp::Packet parsedPacket(&rawPacket);
	
	std::cout<<"Parsed Packet = "<<parsedPacket.toString()<<std::endl;

	// first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
	for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
	{
		printf("Layer type: %s; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
				getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
				(int)curLayer->getDataLen(),                              // get total length of the layer
				(int)curLayer->getHeaderLen(),                            // get the header length of the layer
				(int)curLayer->getLayerPayloadSize());                    // get the payload length of the layer (equals total length minus header length)
		
	}

	pcpp::Ipv4cLayer* ipcLayer = parsedPacket.getLayerOfType<pcpp::Ipv4cLayer>();
        if (ipcLayer == NULL)
	{
	    printf("Something went wrong, couldn't find IPv4 layer\n");
	    exit(1);
	}
	
	std::cout << "\nSource IP address: " << std::hex << ipcLayer->getSrcaddr() << std::endl;
	std::cout << "fragOffset: " << std::hex << ipcLayer->getFragoffset() << std::endl;
        std::cout << "flags: " << (int)ipcLayer->getFlags() << std::endl;
	std::cout << "IpType: " << (int)ipcLayer->getIptype() << std::endl;
	

	pcpp::NonaLayer* nonaLayer = parsedPacket.getLayerOfType<pcpp::NonaLayer>();
        if (nonaLayer == NULL)
	{
	    printf("Something went wrong, couldn't find nona layer\n");
	    exit(1);
	}
	
	std::cout << "\nfn1: " << (int)nonaLayer->getFn1() << std::endl;
	std::cout << "fn2: " << (int)nonaLayer->getFn2() << std::endl;
        std::cout << "fn3: " << (int)nonaLayer->getFn3() << std::endl;

}
