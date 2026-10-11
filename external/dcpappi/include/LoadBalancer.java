package dpi;

import java.util.*;
import java.util.concurrent.atomic.LongAdder;

public final class LoadBalancer implements AutoCloseable {
    public record LBStats(long packetsReceived,long packetsDispatched,List<Long> perFpPackets){}
    private final int id,fpStart; private final List<ThreadSafeQueue<Types.PacketJob>> fpQueues;
    private final ThreadSafeQueue<Types.PacketJob> input; private final LongAdder received=new LongAdder(),dispatched=new LongAdder();
    private final long[] perFp; private volatile boolean running; private Thread thread;
    public LoadBalancer(int id,List<ThreadSafeQueue<Types.PacketJob>> queues,int fpStart,int queueSize){this.id=id;this.fpStart=fpStart;this.fpQueues=List.copyOf(queues);this.perFp=new long[queues.size()];this.input=new ThreadSafeQueue<>(queueSize);}
    public void start(){if(running)return;running=true;thread=new Thread(this::run,"LB-"+id);thread.start();}
    private void run(){try{while(running||!input.isEmpty()){var op=input.popWithTimeout(100);if(op.isEmpty())continue;Types.PacketJob j=op.get();received.increment();int ix=Math.floorMod(j.tuple.hashCode(),fpQueues.size());try{fpQueues.get(ix).push(j);synchronized(perFp){perFp[ix]++;}}catch(InterruptedException e){Thread.currentThread().interrupt();break;}dispatched.increment();}}catch(InterruptedException e){Thread.currentThread().interrupt();} }
    public void stop(){running=false;input.shutdown();if(thread!=null)try{thread.join(2000);}catch(InterruptedException e){Thread.currentThread().interrupt();}}
    public ThreadSafeQueue<Types.PacketJob> getInputQueue(){return input;}
    public LBStats getStats(){List<Long> p=new ArrayList<>();synchronized(perFp){for(long x:perFp)p.add(x);}return new LBStats(received.sum(),dispatched.sum(),p);}
    public boolean isRunning(){return running;}
    @Override public void close(){stop();}
    public static final class Manager {
        private final List<LoadBalancer> lbs;private final int fpsPerLb;
        public Manager(int n,int per,List<ThreadSafeQueue<Types.PacketJob>> queues,int qsize){if(n<1||per<1)throw new IllegalArgumentException();fpsPerLb=per;lbs=new ArrayList<>();for(int i=0;i<n;i++){int start=i*per;int end=Math.min(queues.size(),start+per);lbs.add(new LoadBalancer(i,queues.subList(start,end),start,qsize));}}
        public void startAll(){lbs.forEach(LoadBalancer::start);}public void stopAll(){lbs.forEach(LoadBalancer::stop);}
        public LoadBalancer getLB(int id){return lbs.get(id);}public int getNumLBs(){return lbs.size();}
        public LoadBalancer getLBForPacket(Types.FiveTuple t){return lbs.get(Math.floorMod(t.hashCode(),lbs.size()));}
        public long[] getAggregatedStats(){long r=0,d=0;for(LoadBalancer l:lbs){LBStats s=l.getStats();r+=s.packetsReceived();d+=s.packetsDispatched();}return new long[]{r,d};}
    }
}
