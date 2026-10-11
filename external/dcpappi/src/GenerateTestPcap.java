import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Java conversion of generate_test_pcap.py.
 * Creates a classic PCAP file containing synthetic TLS/SNI, HTTP, DNS, and blocked-IP traffic.
 */
public class GenerateTestPcap {
    private static final Random RANDOM = new Random();

    private static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] a : arrays) length += a.length;
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    private static byte[] u8(int v) { return new byte[]{(byte) v}; }
    private static byte[] u16be(int v) {
        return ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort((short) v).array();
    }
    private static byte[] u32be(long v) {
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt((int) v).array();
    }
    private static byte[] u32le(long v) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) v).array();
    }
    private static byte[] u16le(int v) {
        return ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) v).array();
    }

    private static int randomBetween(int low, int high) {
        return low + RANDOM.nextInt(high - low + 1);
    }

    private static byte[] macBytes(String mac) {
        String[] parts = mac.split(":");
        byte[] b = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) b[i] = (byte) Integer.parseInt(parts[i], 16);
        return b;
    }

    private static byte[] ipBytes(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            int n = Integer.parseInt(parts[i]);
            if (n < 0 || n > 255) throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
            b[i] = (byte) n;
        }
        return b;
    }

    static final class PcapWriter implements AutoCloseable {
        private final DataOutputStream out;
        private long timestamp = 1_700_000_000L;

        PcapWriter(String filename) throws IOException {
            out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
            // Classic PCAP little-endian global header: magic, version 2.4, timezone, sigfigs, snaplen, Ethernet.
            out.write(u32le(0xa1b2c3d4L));
            out.write(u16le(2));
            out.write(u16le(4));
            out.write(u32le(0));
            out.write(u32le(0));
            out.write(u32le(65535));
            out.write(u32le(1));
        }

        void writePacket(byte[] data) throws IOException {
            out.write(u32le(timestamp++));
            out.write(u32le(randomBetween(0, 999999)));
            out.write(u32le(data.length));
            out.write(u32le(data.length));
            out.write(data);
        }

        @Override public void close() throws IOException { out.close(); }
    }

    private static byte[] ethernet(String srcMac, String dstMac) {
        return concat(macBytes(dstMac), macBytes(srcMac), u16be(0x0800));
    }

    private static byte[] ipv4(String srcIp, String dstIp, int protocol, int payloadLen) {
        byte[] header = concat(
            u8(0x45), u8(0), u16be(20 + payloadLen),
            u16be(randomBetween(1, 65535)), u16be(0x4000),
            u8(64), u8(protocol), u16be(0),
            ipBytes(srcIp), ipBytes(dstIp)
        );
        return header; // Matches the Python source: checksum is left as zero.
    }

    private static byte[] tcp(int srcPort, int dstPort, long seq, long ack, int flags) {
        return concat(u16be(srcPort), u16be(dstPort), u32be(seq), u32be(ack),
            u8(5 << 4), u8(flags), u16be(65535), u16be(0), u16be(0));
    }

    private static byte[] udp(int srcPort, int dstPort, int payloadLen) {
        return concat(u16be(srcPort), u16be(dstPort), u16be(8 + payloadLen), u16be(0));
    }

    private static byte[] tlsClientHello(String sni) {
        byte[] sniBytes = sni.getBytes(StandardCharsets.US_ASCII);
        byte[] sniEntry = concat(u8(0), u16be(sniBytes.length), sniBytes);
        byte[] sniList = concat(u16be(sniEntry.length), sniEntry);
        byte[] sniExt = concat(u16be(0), u16be(sniList.length), sniList);
        byte[] supportedVersions = concat(u16be(0x002b), u16be(3), u8(2), u16be(0x0304));
        byte[] extensions = concat(sniExt, supportedVersions);
        byte[] extensionsData = concat(u16be(extensions.length), extensions);

        byte[] randomBytes = new byte[32];
        RANDOM.nextBytes(randomBytes);
        byte[] body = concat(u16be(0x0303), randomBytes,
            u8(0), u16be(4), u16be(0x1301), u16be(0x1302),
            u8(1), u8(0), extensionsData);

        byte[] handshake = concat(u8(1),
            new byte[]{0, (byte) ((body.length >>> 8) & 0xff), (byte) (body.length & 0xff)}, body);
        return concat(u8(0x16), u16be(0x0301), u16be(handshake.length), handshake);
    }

    private static byte[] httpRequest(String host, String path) {
        String request = "GET " + path + " HTTP/1.1\r\nHost: " + host
            + "\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n";
        return request.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] dnsQuery(String domain) {
        byte[] question = new byte[0];
        for (String label : domain.split("\\.")) {
            byte[] name = label.getBytes(StandardCharsets.US_ASCII);
            question = concat(question, u8(name.length), name);
        }
        question = concat(question, u8(0), u16be(1), u16be(1));
        return concat(u16be(randomBetween(1, 65535)), u16be(0x0100),
            u16be(1), u16be(0), u16be(0), u16be(0), question);
    }

    public static void main(String[] args) throws IOException {
        String filename = args.length > 0 ? args[0] : "test_dpi.pcap";
        String userMac = "00:11:22:33:44:55";
        String gatewayMac = "aa:bb:cc:dd:ee:ff";
        String userIp = "192.168.1.100";
        long seqBase = 1000;
        int tlsCount = 0, httpCount = 0, dnsCount = 0;

        String[][] tls = {
            {"142.250.185.206","www.google.com","443"},
            {"142.250.185.110","www.youtube.com","443"},
            {"157.240.1.35","www.facebook.com","443"},
            {"157.240.1.174","www.instagram.com","443"},
            {"104.244.42.65","twitter.com","443"},
            {"52.94.236.248","www.amazon.com","443"},
            {"23.52.167.61","www.netflix.com","443"},
            {"140.82.114.4","github.com","443"},
            {"104.16.85.20","discord.com","443"},
            {"35.186.224.25","zoom.us","443"},
            {"35.186.227.140","web.telegram.org","443"},
            {"99.86.0.100","www.tiktok.com","443"},
            {"35.186.224.47","open.spotify.com","443"},
            {"192.0.78.24","www.cloudflare.com","443"},
            {"13.107.42.14","www.microsoft.com","443"},
            {"17.253.144.10","www.apple.com","443"}
        };
        String[][] http = {{"93.184.216.34","example.com","80"},
                           {"185.199.108.153","httpbin.org","80"}};
        String[] dns = {"www.google.com","www.youtube.com","www.facebook.com","api.twitter.com"};

        try (PcapWriter writer = new PcapWriter(filename)) {
            for (String[] item : tls) {
                String dstIp = item[0], sni = item[1];
                int dstPort = Integer.parseInt(item[2]);
                int srcPort = randomBetween(49152, 65535);
                byte[] eth = ethernet(userMac, gatewayMac);
                byte[] tcp = tcp(srcPort, dstPort, seqBase, 0, 0x02);
                writer.writePacket(concat(eth, ipv4(userIp, dstIp, 6, tcp.length), tcp));

                tcp = tcp(dstPort, srcPort, seqBase + 1000, seqBase + 1, 0x12);
                writer.writePacket(concat(ethernet(gatewayMac, userMac),
                    ipv4(dstIp, userIp, 6, tcp.length), tcp));

                tcp = tcp(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x10);
                writer.writePacket(concat(eth, ipv4(userIp, dstIp, 6, tcp.length), tcp));

                byte[] payload = tlsClientHello(sni);
                tcp = tcp(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x18);
                writer.writePacket(concat(eth, ipv4(userIp, dstIp, 6, tcp.length + payload.length), tcp, payload));
                seqBase += 10000;
                tlsCount++;
            }

            for (String[] item : http) {
                String dstIp = item[0], host = item[1];
                int dstPort = Integer.parseInt(item[2]);
                int srcPort = randomBetween(49152, 65535);
                byte[] eth = ethernet(userMac, gatewayMac);
                byte[] tcp = tcp(srcPort, dstPort, seqBase, 0, 0x02);
                writer.writePacket(concat(eth, ipv4(userIp, dstIp, 6, tcp.length), tcp));
                byte[] payload = httpRequest(host, "/");
                tcp = tcp(srcPort, dstPort, seqBase + 1, 1, 0x18);
                writer.writePacket(concat(eth, ipv4(userIp, dstIp, 6, tcp.length + payload.length), tcp, payload));
                seqBase += 10000;
                httpCount++;
            }

            for (String domain : dns) {
                int srcPort = randomBetween(49152, 65535);
                byte[] payload = dnsQuery(domain);
                byte[] eth = ethernet(userMac, gatewayMac);
                byte[] udp = udp(srcPort, 53, payload.length);
                writer.writePacket(concat(eth, ipv4(userIp, "8.8.8.8", 17, udp.length + payload.length), udp, payload));
                dnsCount++;
            }

            String blockedIp = "192.168.1.50";
            for (int i = 0; i < 5; i++) {
                int srcPort = randomBetween(49152, 65535);
                byte[] eth = ethernet("00:11:22:33:44:56", gatewayMac);
                byte[] tcp = tcp(srcPort, 443, seqBase, 0, 0x02);
                writer.writePacket(concat(eth, ipv4(blockedIp, "172.217.0.100", 6, tcp.length), tcp));
                seqBase += 1000;
            }
        }
        System.out.println("Created " + filename + " with test traffic");
        System.out.println("  - " + tlsCount + " TLS connections with SNI");
        System.out.println("  - " + httpCount + " HTTP connections");
        System.out.println("  - " + dnsCount + " DNS queries");
        System.out.println("  - 5 packets from blocked IP 192.168.1.50");
    }
}
