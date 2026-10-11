package dpi;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.locks.*;

public final class RuleManager {
    public enum BlockType { IP, APP, DOMAIN, PORT }
    public record BlockReason(BlockType type,String detail) {}
    private final Set<Long> ips=new HashSet<>();
    private final Set<Types.AppType> apps=EnumSet.noneOf(Types.AppType.class);
    private final Set<String> domains=new HashSet<>();
    private final Set<Integer> ports=new HashSet<>();
    private final ReadWriteLock lock=new ReentrantReadWriteLock();
    public void blockIP(long ip){lock.writeLock().lock();try{ips.add(ip&0xffffffffL);}finally{lock.writeLock().unlock();}}
    public void blockIP(String ip){blockIP(Types.FiveTuple.parseIp(ip));}
    public void unblockIP(long ip){lock.writeLock().lock();try{ips.remove(ip&0xffffffffL);}finally{lock.writeLock().unlock();}}
    public void unblockIP(String ip){unblockIP(Types.FiveTuple.parseIp(ip));}
    public boolean isIPBlocked(long ip){lock.readLock().lock();try{return ips.contains(ip&0xffffffffL);}finally{lock.readLock().unlock();}}
    public List<String> getBlockedIPs(){lock.readLock().lock();try{return ips.stream().map(Types.FiveTuple::ipToString).sorted().toList();}finally{lock.readLock().unlock();}}
    public void blockApp(Types.AppType a){lock.writeLock().lock();try{apps.add(a);}finally{lock.writeLock().unlock();}}
    public void unblockApp(Types.AppType a){lock.writeLock().lock();try{apps.remove(a);}finally{lock.writeLock().unlock();}}
    public boolean isAppBlocked(Types.AppType a){lock.readLock().lock();try{return apps.contains(a);}finally{lock.readLock().unlock();}}
    public List<Types.AppType> getBlockedApps(){lock.readLock().lock();try{return List.copyOf(apps);}finally{lock.readLock().unlock();}}
    public void blockDomain(String d){String s=normalize(d);lock.writeLock().lock();try{domains.add(s);}finally{lock.writeLock().unlock();}}
    public void unblockDomain(String d){lock.writeLock().lock();try{domains.remove(normalize(d));}finally{lock.writeLock().unlock();}}
    public boolean isDomainBlocked(String d){String s=normalize(d);lock.readLock().lock();try{for(String pat:domains)if(matches(s,pat))return true;return false;}finally{lock.readLock().unlock();}}
    public List<String> getBlockedDomains(){lock.readLock().lock();try{return domains.stream().sorted().toList();}finally{lock.readLock().unlock();}}
    public void blockPort(int p){checkPort(p);lock.writeLock().lock();try{ports.add(p);}finally{lock.writeLock().unlock();}}
    public void unblockPort(int p){lock.writeLock().lock();try{ports.remove(p);}finally{lock.writeLock().unlock();}}
    public boolean isPortBlocked(int p){lock.readLock().lock();try{return ports.contains(p);}finally{lock.readLock().unlock();}}
    public Optional<BlockReason> shouldBlock(long srcIp,int dstPort,Types.AppType app,String domain){
        if(isIPBlocked(srcIp))return Optional.of(new BlockReason(BlockType.IP,Types.FiveTuple.ipToString(srcIp)));
        if(isPortBlocked(dstPort))return Optional.of(new BlockReason(BlockType.PORT,Integer.toString(dstPort)));
        if(app!=null&&isAppBlocked(app))return Optional.of(new BlockReason(BlockType.APP,app.name()));
        if(domain!=null&&!domain.isBlank()&&isDomainBlocked(domain))return Optional.of(new BlockReason(BlockType.DOMAIN,domain));
        return Optional.empty();
    }
    private static void checkPort(int p){if(p<0||p>65535)throw new IllegalArgumentException("Invalid port");}
    private static String normalize(String s){return s.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$","");}
    private static boolean matches(String domain,String pattern){return domain.equals(pattern)||(pattern.startsWith("*.")&&domain.endsWith(pattern.substring(1))&&domain.length()>pattern.length()-1);}
    public boolean saveRules(String file){
        lock.readLock().lock();try(BufferedWriter w=Files.newBufferedWriter(Path.of(file))){
            for(long ip:ips)w.write("IP "+Types.FiveTuple.ipToString(ip)+"\n");
            for(var a:apps)w.write("APP "+a.name()+"\n");for(String d:domains)w.write("DOMAIN "+d+"\n");for(int p:ports)w.write("PORT "+p+"\n");return true;
        }catch(IOException e){return false;}finally{lock.readLock().unlock();}
    }
    public boolean loadRules(String file){
        try{List<String> lines=Files.readAllLines(Path.of(file));for(String line:lines){String[]p=line.trim().split("\\s+",2);if(p.length!=2||p[0].startsWith("#"))continue;
            try{switch(p[0].toUpperCase(Locale.ROOT)){case "IP"->blockIP(p[1]);case "APP"->blockApp(Types.AppType.valueOf(p[1].toUpperCase(Locale.ROOT)));case "DOMAIN"->blockDomain(p[1]);case "PORT"->blockPort(Integer.parseInt(p[1]));default->{}}}catch(RuntimeException ignored){}
        }return true;}catch(IOException e){return false;}
    }
    public void clearAll(){lock.writeLock().lock();try{ips.clear();apps.clear();domains.clear();ports.clear();}finally{lock.writeLock().unlock();}}
    public Map<String,Integer> getStats(){lock.readLock().lock();try{return Map.of("blocked_ips",ips.size(),"blocked_apps",apps.size(),"blocked_domains",domains.size(),"blocked_ports",ports.size());}finally{lock.readLock().unlock();}}
}
