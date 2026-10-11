package dpi;

public final class Platform {
    private Platform() {}
    public static int swapBytes16(int v) { return ((v & 0xff) << 8) | ((v >>> 8) & 0xff); }
    public static long swapBytes32(long v) {
        return ((v & 0xffL)<<24) | ((v & 0xff00L)<<8) | ((v & 0xff0000L)>>>8) | ((v & 0xff000000L)>>>24);
    }
    public static boolean isLittleEndian() { return java.nio.ByteOrder.nativeOrder() == java.nio.ByteOrder.LITTLE_ENDIAN; }
    public static int netToHost16(int v) { return v & 0xffff; }
    public static long netToHost32(long v) { return v & 0xffffffffL; }
    public static int hostToNet16(int v) { return v & 0xffff; }
    public static long hostToNet32(long v) { return v & 0xffffffffL; }
}
