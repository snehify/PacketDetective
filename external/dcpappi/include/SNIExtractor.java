package dpi;

import java.nio.charset.StandardCharsets;
import java.util.*;

public final class SNIExtractor {
    private SNIExtractor(){}
    private static int u8(byte[]d,int i){return d[i]&255;}
    private static int u16(byte[]d,int i){return (u8(d,i)<<8)|u8(d,i+1);}
    private static int u24(byte[]d,int i){return (u8(d,i)<<16)|(u8(d,i+1)<<8)|u8(d,i+2);}
    public static boolean isTLSClientHello(byte[] d){return d!=null&&d.length>=6&&u8(d,0)==0x16&&u8(d,5)==1;}
    public static Optional<String> extract(byte[] d){
        if(!isTLSClientHello(d))return Optional.empty();
        try{
            int end=Math.min(d.length,5+u16(d,3));int p=5;
            if(p+4>end||u8(d,p++)!=1)return Optional.empty();
            int hsEnd=Math.min(end,p+u24(d,p));p+=3;
            p+=2+32;if(p>=hsEnd)return Optional.empty();
            int sid=u8(d,p++);p+=sid;if(p+2>hsEnd)return Optional.empty();
            int c=u16(d,p);p+=2+c;if(p>=hsEnd)return Optional.empty();
            int comp=u8(d,p++);p+=comp;if(p+2>hsEnd)return Optional.empty();
            int extLen=u16(d,p);p+=2;int extEnd=Math.min(hsEnd,p+extLen);
            while(p+4<=extEnd){int type=u16(d,p),len=u16(d,p+2);p+=4;if(p+len>extEnd)return Optional.empty();
                if(type==0&&len>=5){int listLen=u16(d,p),q=p+2,listEnd=Math.min(p+len,q+listLen);
                    while(q+3<=listEnd){int nameType=u8(d,q++),n=u16(d,q);q+=2;if(q+n>listEnd)return Optional.empty();if(nameType==0)return Optional.of(new String(d,q,n,StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT));q+=n;}
                }p+=len;
            }
        }catch(IndexOutOfBoundsException ignored){}
        return Optional.empty();
    }
    public static boolean isQUICInitial(byte[]d){return d!=null&&d.length>=1&&(d[0]&0xc0)==0xc0&&(d[0]&0x30)==0;}
    public static Optional<String> extractQUIC(byte[]d){return Optional.empty();} // QUIC Initial requires decryption and CRYPTO-frame reassembly.
    public static boolean isHTTPRequest(byte[]d){
        if(d==null)return false;String s=new String(d,0,Math.min(d.length,16),StandardCharsets.US_ASCII);
        return s.matches("(?s)^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) .*");
    }
    public static Optional<String> extractHTTPHost(byte[]d){
        if(!isHTTPRequest(d))return Optional.empty();String s=new String(d,StandardCharsets.ISO_8859_1);
        for(String line:s.split("\\r?\\n")){int c=line.indexOf(':');if(c>0&&line.substring(0,c).trim().equalsIgnoreCase("Host"))return Optional.of(line.substring(c+1).trim().toLowerCase(Locale.ROOT));}
        return Optional.empty();
    }
    public static boolean isDNSQuery(byte[]d){return d!=null&&d.length>=12&&(d[2]&0x80)==0&&((d[4]&255)|(d[5]&255))>0;}
    public static Optional<String> extractDNSQuery(byte[]d){
        if(!isDNSQuery(d))return Optional.empty();
        try{int p=12;StringJoiner name=new StringJoiner(".");while(p<d.length){int n=d[p++]&255;if(n==0)break;if((n&0xc0)!=0||p+n>d.length)return Optional.empty();name.add(new String(d,p,n,StandardCharsets.US_ASCII));p+=n;}String s=name.toString();return s.isEmpty()?Optional.empty():Optional.of(s.toLowerCase(Locale.ROOT));}
        catch(Exception e){return Optional.empty();}
    }
}
