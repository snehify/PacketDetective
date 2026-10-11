package dpi;

import java.net.InetAddress;
import java.util.Locale;
import java.util.concurrent.atomic.LongAdder;

public final class Types {
    private Types() {}
    public enum AppType { UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC, GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM, NETFLIX, AMAZON, MICROSOFT, APPLE, WHATSAPP, TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE, APP_COUNT }
    public enum ConnectionState { NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED }
    public enum PacketAction { FORWARD, DROP, INSPECT, LOG_ONLY }

    public record FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        public FiveTuple reverse() { return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol); }
        @Override public String toString() { return ipToString(srcIp)+":"+srcPort+" -> "+ipToString(dstIp)+":"+dstPort+" / "+protocol; }
        public static long parseIp(String s) {
            try {
                byte[] b = InetAddress.getByName(s).getAddress();
                if (b.length != 4) throw new IllegalArgumentException("IPv4 required");
                return ((b[0]&255L)<<24)|((b[1]&255L)<<16)|((b[2]&255L)<<8)|(b[3]&255L);
            } catch (Exception e) { throw new IllegalArgumentException("Invalid IPv4 address: "+s, e); }
        }
        public static String ipToString(long ip) {
            return String.format(Locale.ROOT, "%d.%d.%d.%d", (ip>>>24)&255, (ip>>>16)&255, (ip>>>8)&255, ip&255);
        }
    }
    public static AppType sniToAppType(String sni) {
        if (sni == null) return AppType.UNKNOWN;
        String s = sni.toLowerCase(Locale.ROOT);
        if (s.contains("google")) return AppType.GOOGLE;
        if (s.contains("facebook") || s.contains("fb.com")) return AppType.FACEBOOK;
        if (s.contains("youtube") || s.contains("youtu.be")) return AppType.YOUTUBE;
        if (s.contains("twitter") || s.contains("x.com")) return AppType.TWITTER;
        if (s.contains("instagram")) return AppType.INSTAGRAM;
        if (s.contains("netflix")) return AppType.NETFLIX;
        if (s.contains("amazon") || s.contains("amazonaws")) return AppType.AMAZON;
        if (s.contains("microsoft") || s.contains("live.com")) return AppType.MICROSOFT;
        if (s.contains("apple")) return AppType.APPLE;
        if (s.contains("whatsapp")) return AppType.WHATSAPP;
        if (s.contains("telegram")) return AppType.TELEGRAM;
        if (s.contains("tiktok")) return AppType.TIKTOK;
        if (s.contains("spotify")) return AppType.SPOTIFY;
        if (s.contains("zoom")) return AppType.ZOOM;
        if (s.contains("discord")) return AppType.DISCORD;
        if (s.contains("github")) return AppType.GITHUB;
        if (s.contains("cloudflare")) return AppType.CLOUDFLARE;
        return AppType.UNKNOWN;
    }
    public static String appTypeToString(AppType app) { return app.name(); }

    public static final class Connection {
        public final FiveTuple tuple;
        public volatile ConnectionState state = ConnectionState.NEW;
        public volatile AppType appType = AppType.UNKNOWN;
        public volatile String sni = "";
        public long packetsIn, packetsOut, bytesIn, bytesOut;
        public final long firstSeenNanos = System.nanoTime();
        public volatile long lastSeenNanos = firstSeenNanos;
        public volatile PacketAction action = PacketAction.FORWARD;
        public volatile boolean synSeen, synAckSeen, finSeen;
        public Connection(FiveTuple tuple) { this.tuple = tuple; }
    }

    public static final class PacketJob {
        public final int packetId;
        public final FiveTuple tuple;
        public final byte[] data;
        public final int ethOffset, ipOffset, transportOffset, payloadOffset, payloadLength;
        public final int tcpFlags;
        public final long tsSec, tsUsec;
        public volatile AppType appType = AppType.UNKNOWN;
        public volatile String domain = "";
        public PacketJob(int id, FiveTuple tuple, byte[] data, int eth, int ip, int transport, int payload, int payloadLen, int flags, long sec, long usec) {
            this.packetId=id; this.tuple=tuple; this.data=data; this.ethOffset=eth; this.ipOffset=ip;
            this.transportOffset=transport; this.payloadOffset=payload; this.payloadLength=payloadLen;
            this.tcpFlags=flags; this.tsSec=sec; this.tsUsec=usec;
        }
        public byte[] payload() {
            int start=Math.max(0, Math.min(payloadOffset, data.length));
            int len=Math.max(0, Math.min(payloadLength, data.length-start));
            return java.util.Arrays.copyOfRange(data,start,start+len);
        }
    }

    public static final class DPIStats {
        public final LongAdder totalPackets=new LongAdder(), totalBytes=new LongAdder(), forwardedPackets=new LongAdder(),
            droppedPackets=new LongAdder(), tcpPackets=new LongAdder(), udpPackets=new LongAdder(), otherPackets=new LongAdder(),
            activeConnections=new LongAdder();
    }
}
