package dpi;

import java.util.*;

/** Java conversion of main_simple.cpp: single-threaded packet/SNI inspection. */
public final class MainSimple {
    private MainSimple() {}
    public static void main(String[] args) {
        if(args.length<1){System.err.println("Usage: java dpi.MainSimple <pcap_file>");return;}
        int count=0,tls=0;
        try(PcapReader reader=new PcapReader()){
            reader.open(args[0]); System.out.println("Processing packets..."); PcapReader.RawPacket raw;
            while((raw=reader.readNextPacket())!=null){count++;Optional<PacketParser.ParsedPacket> op=PacketParser.parse(raw);if(op.isEmpty())continue;
                PacketParser.ParsedPacket p=op.get();if(!p.hasIp())continue;
                System.out.printf("Packet %d: %s:%d -> %s:%d",count,p.srcIp(),p.srcPort(),p.destIp(),p.destPort());
                if(p.hasTcp()&&p.destPort()==443&&p.payloadLength()>0&&p.payloadOffset()<raw.data().length){byte[] payload=Arrays.copyOfRange(raw.data(),p.payloadOffset(),Math.min(raw.data().length,p.payloadOffset()+p.payloadLength()));Optional<String>sni=SNIExtractor.extract(payload);if(sni.isPresent()){System.out.print(" [SNI: "+sni.get()+"]");tls++;}}
                System.out.println();
            }
            System.out.println("\nTotal packets: "+count+"\nSNI extracted: "+tls);
        }catch(Exception e){System.err.println("Error: "+e.getMessage());}
    }
}
