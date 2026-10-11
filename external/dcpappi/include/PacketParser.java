package dpi;

import java.util.*;

public final class PacketParser {
    public static final int TCP=6, UDP=17, ICMP=1, IPV4=0x0800, IPV6=0x86dd, ARP=0x0806;
    public record ParsedPacket(long timestampSec,long timestampUsec,String srcMac,String destMac,int etherType,
        boolean hasIp,int ipVersion,String srcIp,String destIp,int protocol,int ttl,boolean hasTcp,boolean hasUdp,
        int srcPort,int destPort,int tcpFlags,long seqNumber,long ackNumber,int payloadLength,int payloadOffset) {}
    private PacketParser(){}
    private static int u8(byte[]d,int i){return d[i]&255;}
    private static int u16(byte[]d,int i){return (u8(d,i)<<8)|u8(d,i+1);}
    private static long u32(byte[]d,int i){return ((long)u8(d,i)<<24)|((long)u8(d,i+1)<<16)|((long)u8(d,i+2)<<8)|u8(d,i+3);}
    public static String macToString(byte[] d,int o){return String.format(Locale.ROOT,"%02x:%02x:%02x:%02x:%02x:%02x",u8(d,o),u8(d,o+1),u8(d,o+2),u8(d,o+3),u8(d,o+4),u8(d,o+5));}
    public static String ipToString(long ip){return Types.FiveTuple.ipToString(ip);}
    public static String protocolToString(int p){return switch(p){case TCP->"TCP";case UDP->"UDP";case ICMP->"ICMP";default->"OTHER("+p+")";};}
    public static String tcpFlagsToString(int f){StringJoiner j=new StringJoiner(",");if((f&1)!=0)j.add("FIN");if((f&2)!=0)j.add("SYN");if((f&4)!=0)j.add("RST");if((f&8)!=0)j.add("PSH");if((f&16)!=0)j.add("ACK");if((f&32)!=0)j.add("URG");return j.toString();}
    public static Optional<ParsedPacket> parse(PcapReader.RawPacket raw) {
        byte[] d=raw.data(); if(d.length<14)return Optional.empty();
        String dstMac=macToString(d,0),srcMac=macToString(d,6); int type=u16(d,12),off=14;
        if(type==0x8100||type==0x88a8){if(d.length<18)return Optional.empty();type=u16(d,16);off=18;}
        if(type!=IPV4||d.length<off+20)return Optional.of(new ParsedPacket(raw.header().tsSec(),raw.header().tsUsec(),srcMac,dstMac,type,false,0,"","",0,0,false,false,0,0,0,0,0,0,0));
        int vihl=u8(d,off),ihl=(vihl&15)*4;if((vihl>>>4)!=4||ihl<20||d.length<off+ihl)return Optional.empty();
        int total=u16(d,off+2),proto=u8(d,off+9);long src=u32(d,off+12),dst=u32(d,off+16);int ttl=u8(d,off+8);
        int tr=off+ihl,sp=0,dp=0,flags=0;long seq=0,ack=0;boolean tcp=false,udp=false;int payload=tr;
        if(proto==TCP){if(d.length<tr+20)return Optional.empty();sp=u16(d,tr);dp=u16(d,tr+2);seq=u32(d,tr+4);ack=u32(d,tr+8);int th=(u8(d,tr+12)>>>4)*4;if(th<20||d.length<tr+th)return Optional.empty();flags=u8(d,tr+13);payload=tr+th;tcp=true;}
        else if(proto==UDP){if(d.length<tr+8)return Optional.empty();sp=u16(d,tr);dp=u16(d,tr+2);payload=tr+8;udp=true;}
        int end=Math.min(d.length,off+Math.max(ihl,total));int plen=Math.max(0,end-payload);
        return Optional.of(new ParsedPacket(raw.header().tsSec(),raw.header().tsUsec(),srcMac,dstMac,type,true,4,ipToString(src),ipToString(dst),proto,ttl,tcp,udp,sp,dp,flags,seq,ack,plen,payload));
    }
    public static Types.PacketJob toJob(PcapReader.RawPacket raw,ParsedPacket p,int id){
        long src=0,dst=0;try{src=Types.FiveTuple.parseIp(p.srcIp());dst=Types.FiveTuple.parseIp(p.destIp());}catch(Exception ignored){}
        Types.FiveTuple tuple=new Types.FiveTuple(src,dst,p.srcPort(),p.destPort(),p.protocol());
        int transport=p.hasIp()?14+((raw.data()[14]&15)*4):0;
        return new Types.PacketJob(id,tuple,raw.data(),0,p.hasIp()?14:0,transport,p.payloadOffset(),p.payloadLength(),p.tcpFlags(),p.timestampSec(),p.timestampUsec());
    }
}
