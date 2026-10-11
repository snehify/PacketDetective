package dpi;

import java.util.*;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.BiConsumer;

public final class FastPathProcessor implements AutoCloseable {
    public record FPStats(long packetsProcessed,long packetsForwarded,long packetsDropped,long connectionsTracked,long sniExtractions,long classificationHits){}
    private final int id;private final ThreadSafeQueue<Types.PacketJob> input;private final ConnectionTracker tracker;private final RuleManager rules;
    private final BiConsumer<Types.PacketJob,Types.PacketAction> output;
    private final LongAdder processed=new LongAdder(),forwarded=new LongAdder(),dropped=new LongAdder(),sniCount=new LongAdder(),hits=new LongAdder();
    private volatile boolean running;private Thread thread;
    public FastPathProcessor(int id,RuleManager rules,BiConsumer<Types.PacketJob,Types.PacketAction> output,int queueSize){this.id=id;this.rules=rules;this.output=output;input=new ThreadSafeQueue<>(queueSize);tracker=new ConnectionTracker(id,100000);}
    public void start(){if(running)return;running=true;thread=new Thread(this::run,"FP-"+id);thread.start();}
    private void run(){try{while(running||!input.isEmpty()){Optional<Types.PacketJob> o=input.popWithTimeout(100);if(o.isEmpty())continue;Types.PacketJob j=o.get();Types.PacketAction a=processPacket(j);processed.increment();if(a==Types.PacketAction.DROP)dropped.increment();else forwarded.increment();output.accept(j,a);}}catch(InterruptedException e){Thread.currentThread().interrupt();}}
    private Types.PacketAction processPacket(Types.PacketJob j){
        Types.Connection c=tracker.getOrCreateConnection(j.tuple);tracker.updateConnection(c,j.data.length,false);
        byte[] payload=j.payload();
        if(c.appType==Types.AppType.UNKNOWN){
            Optional<String> host=SNIExtractor.extract(payload);
            if(host.isPresent()){sniCount.increment();j.domain=host.get();j.appType=Types.sniToAppType(host.get());tracker.classifyConnection(c,j.appType,host.get());hits.increment();}
            else {host=SNIExtractor.extractHTTPHost(payload);if(host.isPresent()){j.domain=host.get();j.appType=Types.AppType.HTTP;tracker.classifyConnection(c,j.appType,host.get());hits.increment();}
                else if(j.tuple.dstPort()==53){Optional<String> dns=SNIExtractor.extractDNSQuery(payload);if(dns.isPresent()){j.domain=dns.get();j.appType=Types.AppType.DNS;tracker.classifyConnection(c,j.appType,dns.get());}}}
        } else {j.appType=c.appType;j.domain=c.sni;}
        var reason=rules.shouldBlock(j.tuple.srcIp(),j.tuple.dstPort(),j.appType,j.domain);
        if(reason.isPresent()){tracker.blockConnection(c);return Types.PacketAction.DROP;}
        return Types.PacketAction.FORWARD;
    }
    public void stop(){running=false;input.shutdown();if(thread!=null)try{thread.join(3000);}catch(InterruptedException e){Thread.currentThread().interrupt();}}
    public ThreadSafeQueue<Types.PacketJob> getInputQueue(){return input;}public ConnectionTracker getConnectionTracker(){return tracker;}public int getId(){return id;}public boolean isRunning(){return running;}
    public FPStats getStats(){return new FPStats(processed.sum(),forwarded.sum(),dropped.sum(),tracker.getActiveCount(),sniCount.sum(),hits.sum());}
    @Override public void close(){stop();}
    public static final class Manager {
        private final List<FastPathProcessor> fps=new ArrayList<>();
        public Manager(int n,RuleManager rules,BiConsumer<Types.PacketJob,Types.PacketAction> out,int qsize){for(int i=0;i<n;i++)fps.add(new FastPathProcessor(i,rules,out,qsize));}
        public void startAll(){fps.forEach(FastPathProcessor::start);}public void stopAll(){fps.forEach(FastPathProcessor::stop);}
        public FastPathProcessor getFP(int id){return fps.get(id);}public int getNumFPs(){return fps.size();}
        public List<ThreadSafeQueue<Types.PacketJob>> getQueues(){return fps.stream().map(FastPathProcessor::getInputQueue).toList();}
        public long[] getAggregatedStats(){long p=0,f=0,d=0,c=0;for(FastPathProcessor fp:fps){FPStats s=fp.getStats();p+=s.packetsProcessed();f+=s.packetsForwarded();d+=s.packetsDropped();c+=s.connectionsTracked();}return new long[]{p,f,d,c};}
        public String classificationReport(){Map<Types.AppType,Long> m=new EnumMap<>(Types.AppType.class);for(FastPathProcessor fp:fps)for(Types.Connection c:fp.tracker.getAllConnections())m.merge(c.appType,1L,Long::sum);return m.toString();}
    }
}
