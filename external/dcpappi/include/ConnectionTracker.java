package dpi;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.locks.*;

public final class ConnectionTracker {
    private final int fpId; private final int maxConnections;
    private final LinkedHashMap<Types.FiveTuple,Types.Connection> connections=new LinkedHashMap<>(128,.75f,true);
    private long totalSeen,classifiedCount,blockedCount;
    private final ReadWriteLock lock=new ReentrantReadWriteLock();
    public ConnectionTracker(int fpId,int maxConnections){this.fpId=fpId;this.maxConnections=maxConnections;}
    public Types.Connection getOrCreateConnection(Types.FiveTuple tuple){
        lock.writeLock().lock();try{Types.Connection c=connections.get(tuple);if(c!=null)return c;
            if(connections.size()>=maxConnections&&!connections.isEmpty())connections.remove(connections.keySet().iterator().next());
            c=new Types.Connection(tuple);connections.put(tuple,c);totalSeen++;return c;
        }finally{lock.writeLock().unlock();}
    }
    public Types.Connection getConnection(Types.FiveTuple tuple){lock.readLock().lock();try{return connections.get(tuple);}finally{lock.readLock().unlock();}}
    public void updateConnection(Types.Connection c,int bytes,boolean outbound){if(c==null)return; synchronized(c){if(outbound){c.packetsOut++;c.bytesOut+=bytes;}else{c.packetsIn++;c.bytesIn+=bytes;}c.lastSeenNanos=System.nanoTime();}}
    public void classifyConnection(Types.Connection c,Types.AppType app,String sni){if(c==null)return;synchronized(c){if(c.state!=Types.ConnectionState.CLASSIFIED)classifiedCount++;c.appType=app;c.sni=sni==null?"":sni;c.state=Types.ConnectionState.CLASSIFIED;}}
    public void blockConnection(Types.Connection c){if(c!=null){c.action=Types.PacketAction.DROP;c.state=Types.ConnectionState.BLOCKED;blockedCount++;}}
    public void closeConnection(Types.FiveTuple t){lock.writeLock().lock();try{Types.Connection c=connections.get(t);if(c!=null)c.state=Types.ConnectionState.CLOSED;}finally{lock.writeLock().unlock();}}
    public int cleanupStale(Duration timeout){long cutoff=System.nanoTime()-timeout.toNanos();lock.writeLock().lock();try{int before=connections.size();connections.entrySet().removeIf(e->e.getValue().lastSeenNanos<cutoff);return before-connections.size();}finally{lock.writeLock().unlock();}}
    public List<Types.Connection> getAllConnections(){lock.readLock().lock();try{return List.copyOf(connections.values());}finally{lock.readLock().unlock();}}
    public int getActiveCount(){lock.readLock().lock();try{return (int)connections.values().stream().filter(c->c.state!=Types.ConnectionState.CLOSED).count();}finally{lock.readLock().unlock();}}
    public record TrackerStats(int activeConnections,long totalConnectionsSeen,long classifiedConnections,long blockedConnections){}
    public TrackerStats getStats(){lock.readLock().lock();try{return new TrackerStats(getActiveCount(),totalSeen,classifiedCount,blockedCount);}finally{lock.readLock().unlock();}}
    public void clear(){lock.writeLock().lock();try{connections.clear();}finally{lock.writeLock().unlock();}}
    public void forEach(java.util.function.Consumer<Types.Connection> callback){getAllConnections().forEach(callback);}
    public int getFpId(){return fpId;}
    public static final class GlobalConnectionTable {
        private final List<ConnectionTracker> trackers;
        public GlobalConnectionTable(int n){trackers=new ArrayList<>(Collections.nCopies(n,null));}
        public synchronized void registerTracker(int id,ConnectionTracker t){trackers.set(id,t);}
        public synchronized String generateReport(){TrackerStatsAggregate a=aggregate();return "Active connections: "+a.active+"\nTotal connections seen: "+a.seen+"\nApplication distribution: "+a.apps+"\nTop domains: "+a.domains;}
        public synchronized TrackerStatsAggregate aggregate(){
            long active=0,seen=0;Map<Types.AppType,Long> apps=new EnumMap<>(Types.AppType.class);Map<String,Long> domains=new HashMap<>();
            for(ConnectionTracker t:trackers)if(t!=null){TrackerStats s=t.getStats();active+=s.activeConnections;seen+=s.totalConnectionsSeen;for(Types.Connection c:t.getAllConnections()){if(c.appType!=Types.AppType.UNKNOWN)apps.merge(c.appType,1L,Long::sum);if(!c.sni.isBlank())domains.merge(c.sni,1L,Long::sum);}}
            List<Map.Entry<String,Long>> top=domains.entrySet().stream().sorted(Map.Entry.<String,Long>comparingByValue().reversed()).limit(10).toList();return new TrackerStatsAggregate(active,seen,apps,top);
        }
        public record TrackerStatsAggregate(long active,long seen,Map<Types.AppType,Long> apps,List<Map.Entry<String,Long>> domains){}
    }
}
