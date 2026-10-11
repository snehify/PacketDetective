package dpi;

import java.util.*;

/** Java counterpart of main_working.cpp using the shared DPI implementation. */
public final class MainWorking {
    private MainWorking() {}
    public static void main(String[] args) {
        if(args.length<2){System.err.println("Usage: java dpi.MainWorking <input.pcap> <output.pcap> [--block-ip IP] [--block-app APP] [--block-domain DOMAIN]");return;}
        try(DPIEngine engine=new DPIEngine(new DPIEngine.Config())){
            for(int i=2;i<args.length;i++){
                switch(args[i]){
                    case "--block-ip" -> {if(++i>=args.length)throw new IllegalArgumentException("Missing IP");engine.blockIP(args[i]);}
                    case "--block-app" -> {if(++i>=args.length)throw new IllegalArgumentException("Missing app");engine.blockApp(args[i]);}
                    case "--block-domain" -> {if(++i>=args.length)throw new IllegalArgumentException("Missing domain");engine.blockDomain(args[i]);}
                    default -> throw new IllegalArgumentException("Unknown option: "+args[i]);
                }
            }
            if(!engine.initialize()||!engine.processFile(args[0],args[1]))throw new IllegalStateException("PCAP processing failed");
            engine.printStatus();
        }catch(Exception e){System.err.println("Error: "+e.getMessage());}
    }
}
