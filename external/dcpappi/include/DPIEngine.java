package dpi;

import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.LongAdder;

public final class DPIEngine implements AutoCloseable {
    public record Config(int numLoadBalancers,int fpsPerLb,int queueSize,String rulesFile,boolean verbose) {
        public Config(){this(2,2,10000,"",false);}
        public Config { if(numLoadBalancers<1||fpsPerLb<1||queueSize<1)throw new IllegalArgumentException("Thread counts and queue size must be positive"); }
    }
    private final Config config;private final RuleManager rules=new RuleManager();private final Types.DPIStats stats=new Types.DPIStats();
    private FastPathProcessor.Manager fpManager;private LoadBalancer.Manager lbManager;private volatile boolean running;
    private final LongAdder packetIds=new LongAdder();
    public DPIEngine(Config config){this.config=config;if(config.rulesFile()!=null&&!config.rulesFile().isBlank())rules.loadRules(config.rulesFile());}
    public boolean initialize(){int n=config.numLoadBalancers()*config.fpsPerLb();fpManager=new FastPathProcessor.Manager(n,rules,this::handleOutput,config.queueSize());lbManager=new LoadBalancer.Manager(config.numLoadBalancers(),config.fpsPerLb(),fpManager.getQueues(),config.queueSize());return true;}
    public boolean processFile(String input,String output){
        if(fpManager==null)initialize();
        try(PcapReader reader=new PcapReader()){
            reader.open(input);PcapReader.PcapGlobalHeader gh=reader.getGlobalHeader();
            try(DataOutputStream out=new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(Path.of(output))))){
                writeGlobalHeader(out,gh);
                // Writer is synchronized with worker callbacks; collect forwarded packets in a queue.
                ThreadSafeQueue<Types.PacketJob> outputQueue=new ThreadSafeQueue<>(config.queueSize());
                // Reinitialize processors so their output callback targets this invocation's queue.
                fpManager.stopAll();fpManager=new FastPathProcessor.Manager(config.numLoadBalancers()*config.fpsPerLb(),rules,(j,a)->{if(a!=Types.PacketAction.DROP)try{outputQueue.push(j);}catch(InterruptedException e){Thread.currentThread().interrupt();}},config.queueSize());
                lbManager=new LoadBalancer.Manager(config.numLoadBalancers(),config.fpsPerLb(),fpManager.getQueues(),config.queueSize());
                fpManager.startAll();lbManager.startAll();running=true;
                Thread writer=new Thread(()->{try{while(running||!outputQueue.isEmpty()){var op=outputQueue.popWithTimeout(100);if(op.isPresent())writePacket(out,op.get());}}catch(Exception e){throw new RuntimeException(e);}},"PCAP-writer");writer.start();
                PcapReader.RawPacket raw;int id=0;
                while((raw=reader.readNextPacket())!=null){Optional<PacketParser.ParsedPacket> parsed=PacketParser.parse(raw);stats.totalPackets.increment();stats.totalBytes.add(raw.data().length);
                    if(parsed.isEmpty()||!parsed.get().hasIp()){stats.forwardedPackets.increment();synchronized(out){writePacketRaw(out,raw);}continue;}
                    PacketParser.ParsedPacket p=parsed.get();Types.PacketJob job=PacketParser.toJob(raw,p,id++);stats.totalPackets.sum();if(p.protocol()==6)stats.tcpPackets.increment();else if(p.protocol()==17)stats.udpPackets.increment();else stats.otherPackets.increment();
                    try{lbManager.getLBForPacket(job.tuple).getInputQueue().push(job);}catch(InterruptedException e){Thread.currentThread().interrupt();break;}
                }
                lbManager.stopAll();fpManager.stopAll();running=false;outputQueue.shutdown();writer.join();return true;
            }
        }catch(Exception e){if(config.verbose())e.printStackTrace();return false;}
    }
    private static void writeGlobalHeader(DataOutputStream out,PcapReader.PcapGlobalHeader h)throws IOException{
        ByteBuffer b=ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);b.putInt(0xa1b2c3d4).putShort((short)h.versionMajor()).putShort((short)h.versionMinor()).putInt(h.thisZone()).putInt((int)h.sigFigs()).putInt((int)h.snapLen()).putInt((int)h.network());out.write(b.array());
    }
    private static void writePacket(DataOutputStream out,Types.PacketJob j)throws IOException{
        ByteBuffer b=ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);b.putInt((int)j.tsSec).putInt((int)j.tsUsec).putInt(j.data.length).putInt(j.data.length);synchronized(out){out.write(b.array());out.write(j.data);}
    }
    private static void writePacketRaw(DataOutputStream out,PcapReader.RawPacket p)throws IOException{
        ByteBuffer b=ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);b.putInt((int)p.header().tsSec()).putInt((int)p.header().tsUsec()).putInt(p.data().length).putInt((int)p.header().origLen());out.write(b.array());out.write(p.data());
    }
    private void handleOutput(Types.PacketJob j,Types.PacketAction a){if(a==Types.PacketAction.DROP)stats.droppedPackets.increment();else stats.forwardedPackets.increment();}
    public void start(){if(fpManager==null)initialize();running=true;fpManager.startAll();lbManager.startAll();}
    public void stop(){running=false;if(lbManager!=null)lbManager.stopAll();if(fpManager!=null)fpManager.stopAll();}
    public void waitForCompletion(){}
    public void blockIP(String ip){rules.blockIP(ip);}public void unblockIP(String ip){rules.unblockIP(ip);}
    public void blockApp(Types.AppType a){rules.blockApp(a);}public void blockApp(String a){rules.blockApp(Types.AppType.valueOf(a.toUpperCase(Locale.ROOT)));}
    public void unblockApp(Types.AppType a){rules.unblockApp(a);}public void unblockApp(String a){rules.unblockApp(Types.AppType.valueOf(a.toUpperCase(Locale.ROOT)));}
    public void blockDomain(String d){rules.blockDomain(d);}public void unblockDomain(String d){rules.unblockDomain(d);}
    public boolean loadRules(String f){return rules.loadRules(f);}public boolean saveRules(String f){return rules.saveRules(f);}
    public RuleManager getRuleManager(){return rules;}public Config getConfig(){return config;}public boolean isRunning(){return running;}
    public Types.DPIStats getStats(){return stats;}
    public String generateClassificationReport(){return fpManager==null?"{}":fpManager.classificationReport();}
    public String generateReport(){return "Packets: "+stats.totalPackets.sum()+"\nBytes: "+stats.totalBytes.sum()+"\nForwarded: "+stats.forwardedPackets.sum()+"\nDropped: "+stats.droppedPackets.sum()+"\nTCP: "+stats.tcpPackets.sum()+"\nUDP: "+stats.udpPackets.sum()+"\n"+generateClassificationReport();}
    public void printStatus(){System.out.println(generateReport());}
    @Override public void close(){stop();}
}
