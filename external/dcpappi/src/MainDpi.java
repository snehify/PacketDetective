package dpi;

import java.util.*;

/** Java conversion of main_dpi.cpp: configurable multithreaded DPI command line. */
public final class MainDpi {
    private MainDpi() {}
    public static void main(String[] args) {
        if(args.length<2){System.err.println("Usage: java dpi.MainDpi <input.pcap> <output.pcap> [--block-ip IP] [--block-app APP] [--block-domain DOMAIN] [--rules FILE] [--lbs N] [--fps N] [--verbose]");return;}
        String input=args[0],output=args[1],rulesFile="";int lbs=2,fps=2;boolean verbose=false;
        List<String> ips=new ArrayList<>(),apps=new ArrayList<>(),domains=new ArrayList<>();
        for(int i=2;i<args.length;i++){
            String a=args[i];
            if(a.equals("--block-ip")&&i+1<args.length)ips.add(args[++i]);
            else if(a.equals("--block-app")&&i+1<args.length)apps.add(args[++i]);
            else if(a.equals("--block-domain")&&i+1<args.length)domains.add(args[++i]);
            else if(a.equals("--rules")&&i+1<args.length)rulesFile=args[++i];
            else if(a.equals("--lbs")&&i+1<args.length)lbs=Integer.parseInt(args[++i]);
            else if(a.equals("--fps")&&i+1<args.length)fps=Integer.parseInt(args[++i]);
            else if(a.equals("--verbose"))verbose=true;
            else {System.err.println("Unknown or incomplete option: "+a);return;}
        }
        try(DPIEngine engine=new DPIEngine(new DPIEngine.Config(lbs,fps,10000,rulesFile,verbose))){
            for(String ip:ips)engine.blockIP(ip);
            for(String app:apps)engine.blockApp(app);
            for(String d:domains)engine.blockDomain(d);
            if(!engine.initialize()||!engine.processFile(input,output)){System.err.println("Processing failed");return;}
            engine.printStatus();
        }catch(Exception e){System.err.println("Error: "+e.getMessage());if(verbose)e.printStackTrace();}
    }
}
