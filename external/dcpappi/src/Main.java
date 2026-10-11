package dpi;

public final class Main {
    private Main(){}
    public static void main(String[] args) {
        if(args.length<2){System.err.println("Usage: java dpi.Main <input.pcap> <output.pcap> [rules.txt]");System.exit(2);}
        DPIEngine.Config config=new DPIEngine.Config(2,2,10000,args.length>2?args[2]:"",true);
        try(DPIEngine engine=new DPIEngine(config)){
            if(!engine.initialize()||!engine.processFile(args[0],args[1])){System.err.println("PCAP processing failed.");System.exit(1);}
            engine.printStatus();
        }
    }
}
