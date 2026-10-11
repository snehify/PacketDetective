package dpi;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

/** Java conversion of main.cpp: prints packet-by-packet protocol summaries. */
public final class MainPacketSummary {
    private MainPacketSummary() {}
    private static void print(PacketParser.ParsedPacket p, int n, byte[] data) {
        LocalDateTime t = LocalDateTime.ofInstant(Instant.ofEpochSecond(p.timestampSec()), ZoneId.systemDefault());
        System.out.printf("\n========== Packet #%d ==========%n", n);
        System.out.printf("Time: %s.%06d%n", t.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), p.timestampUsec());
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + p.srcMac());
        System.out.println("  Destination MAC: " + p.destMac());
        System.out.printf("  EtherType:       0x%04x", p.etherType());
        if (p.etherType()==PacketParser.IPV4) System.out.print(" (IPv4)");
        else if (p.etherType()==PacketParser.IPV6) System.out.print(" (IPv6)");
        else if (p.etherType()==PacketParser.ARP) System.out.print(" (ARP)");
        System.out.println();
        if (p.hasIp()) {
            System.out.printf("\n[IPv%d]%n  Source IP:      %s%n  Destination IP: %s%n  Protocol:       %s%n  TTL:            %d%n",p.ipVersion(),p.srcIp(),p.destIp(),PacketParser.protocolToString(p.protocol()),p.ttl());
        }
        if (p.hasTcp()) System.out.printf("\n[TCP]\n  Source Port:      %d\n  Destination Port: %d\n  Sequence Number:  %d\n  Ack Number:       %d\n  Flags:            %s%n",p.srcPort(),p.destPort(),p.seqNumber(),p.ackNumber(),PacketParser.tcpFlagsToString(p.tcpFlags()));
        if (p.hasUdp()) System.out.printf("\n[UDP]\n  Source Port:      %d\n  Destination Port: %d%n",p.srcPort(),p.destPort());
        if (p.payloadLength()>0) {
            System.out.printf("\n[Payload]\n  Length: %d bytes\n  Preview: ",p.payloadLength());
            int len=Math.min(p.payloadLength(),32), start=Math.min(p.payloadOffset(),data.length);
            for(int i=0;i<len && start+i<data.length;i++)System.out.printf("%02x ",data[start+i]&255);
            if(p.payloadLength()>32)System.out.print("..."); System.out.println();
        }
    }
    public static void main(String[] args) {
        if(args.length<1){System.out.println("Usage: java dpi.MainPacketSummary <pcap_file> [max_packets]");return;}
        int max=Integer.MAX_VALUE;
        if(args.length>1)try{max=Integer.parseInt(args[1]);}catch(NumberFormatException e){System.err.println("Invalid max_packets");return;}
        try(PcapReader r=new PcapReader()) { r.open(args[0]); int count=0; PcapReader.RawPacket raw;
            while(count<max && (raw=r.readNextPacket())!=null){count++;Optional<PacketParser.ParsedPacket> p=PacketParser.parse(raw);if(p.isPresent())print(p.get(),count,raw.data());else System.out.println("Packet #"+count+": malformed packet");}
            System.out.println("\nDisplayed packets: "+count);
        } catch(Exception e){System.err.println("Error: "+e.getMessage());}
    }
}
