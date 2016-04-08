package edu.gatech.sjpcap;

import java.io.DataInputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/*  Spark Function -- Returns Strings when used with the BinaryFile loader */
public class DecodePcap implements Serializable {
    public List<String> decode(DataInputStream dis) {
        List<String> v = new ArrayList<String>();
        PcapParser pcapParser = new PcapParser();
        pcapParser.fis = dis;
        Packet packet = pcapParser.getPacket();
        while (packet != Packet.EOF) {
            if (!(packet instanceof IPPacket)) {
                packet = pcapParser.getPacket();
                continue;
            }
            StringBuilder o = new StringBuilder();
            IPPacket ipPacket = (IPPacket) packet;
            if (ipPacket instanceof UDPPacket) {
                UDPPacket udpPacket = (UDPPacket) ipPacket;
                o.append(ipPacket.timestamp / 1000 + ",");
                o.append(ipPacket.src_ip.getHostAddress() + ",");
                o.append(ipPacket.dst_ip.getHostAddress() + ",");
                o.append(udpPacket.src_port + ",");
                o.append(udpPacket.dst_port + ",");
                o.append("UDP,");
                o.append(udpPacket.data.length);
            }
            if (ipPacket instanceof TCPPacket) {
                TCPPacket tcpPacket = (TCPPacket) ipPacket;
                o.append(ipPacket.timestamp / 1000 + ",");
                o.append(ipPacket.src_ip.getHostAddress() + ",");
                o.append(ipPacket.dst_ip.getHostAddress() + ",");
                o.append(tcpPacket.src_port + ",");
                o.append(tcpPacket.dst_port + ",");
                o.append("TCP,");
                o.append(tcpPacket.data.length);
            }
            v.add(o.toString());
            packet = pcapParser.getPacket();
        }
        return v;
    }
}

