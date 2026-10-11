package dpi;

import java.io.*;
import java.nio.*;
import java.nio.file.*;

public final class PcapReader implements Closeable {
    public record PcapGlobalHeader(long magicNumber, int versionMajor, int versionMinor, int thisZone, long sigFigs, long snapLen, long network) {}
    public record PcapPacketHeader(long tsSec, long tsUsec, long inclLen, long origLen) {}
    public record RawPacket(PcapPacketHeader header, byte[] data) {}
    private DataInputStream in;
    private PcapGlobalHeader globalHeader;
    private boolean littleEndian;
    public void open(String filename) throws IOException {
        close();
        in=new DataInputStream(new BufferedInputStream(Files.newInputStream(Path.of(filename))));
        byte[] h=in.readNBytes(24);
        if(h.length!=24) throw new EOFException("Truncated PCAP global header");
        int magicBE=ByteBuffer.wrap(h,0,4).order(ByteOrder.BIG_ENDIAN).getInt();
        if(magicBE==0xa1b2c3d4) littleEndian=false;
        else if(magicBE==0xd4c3b2a1) littleEndian=true;
        else if(magicBE==0xa1b23c4d || magicBE==0x4d3cb2a1) throw new IOException("Nanosecond PCAP is not supported by this reader");
        else throw new IOException("Not a classic PCAP file (magic 0x"+Integer.toHexString(magicBE)+")");
        ByteOrder order=littleEndian?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN;
        ByteBuffer b=ByteBuffer.wrap(h).order(order);
        long magic=Integer.toUnsignedLong(b.getInt()); int major=Short.toUnsignedInt(b.getShort()), minor=Short.toUnsignedInt(b.getShort());
        int zone=b.getInt(); long sig=Integer.toUnsignedLong(b.getInt()), snap=Integer.toUnsignedLong(b.getInt()), network=Integer.toUnsignedLong(b.getInt());
        globalHeader=new PcapGlobalHeader(magic,major,minor,zone,sig,snap,network);
    }
    public RawPacket readNextPacket() throws IOException {
        if(in==null)return null;
        byte[] h=in.readNBytes(16);
        if(h.length==0)return null;
        if(h.length!=16)throw new EOFException("Truncated PCAP packet header");
        ByteBuffer b=ByteBuffer.wrap(h).order(littleEndian?ByteOrder.LITTLE_ENDIAN:ByteOrder.BIG_ENDIAN);
        long sec=Integer.toUnsignedLong(b.getInt()), usec=Integer.toUnsignedLong(b.getInt()), incl=Integer.toUnsignedLong(b.getInt()), orig=Integer.toUnsignedLong(b.getInt());
        if(incl>64*1024*1024L)throw new IOException("Unreasonable packet size: "+incl);
        byte[] data=in.readNBytes((int)incl); if(data.length!=incl)throw new EOFException("Truncated packet data");
        return new RawPacket(new PcapPacketHeader(sec,usec,incl,orig),data);
    }
    public PcapGlobalHeader getGlobalHeader(){return globalHeader;}
    public boolean isOpen(){return in!=null;}
    public boolean needsByteSwap(){return littleEndian;}
    @Override public void close() throws IOException {if(in!=null){in.close();in=null;}}
}
