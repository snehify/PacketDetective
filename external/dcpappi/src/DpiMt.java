package dpi;

/** Java entry point corresponding to the standalone multithreaded dpi_mt.cpp variant.
 * It reuses the shared queue/load-balancer/fast-path implementation rather than duplicating
 * the source file's local helper classes.
 */
public final class DpiMt {
    private DpiMt() {}
    public static void main(String[] args) {
        if(args.length<2){System.err.println("Usage: java dpi.DpiMt <input.pcap> <output.pcap> [--block-ip IP] [--block-app APP] [--block-domain DOMAIN]");return;}
        try(DPIEngine engine=new DPIEngine(new DPIEngine.Config())){
            for(int i=2;i<args.length;i++){
                String option=args[i];
                if(i+1>=args.length){System.err.println("Missing value for "+option);return;}
                String value=args[++i];
                switch(option){case "--block-ip"->engine.blockIP(value);case "--block-app"->engine.blockApp(value);case "--block-domain"->engine.blockDomain(value);default->{System.err.println("Unknown option: "+option);return;}}
            }
            if(!engine.initialize()||!engine.processFile(args[0],args[1])){System.err.println("Processing failed");return;}
            engine.printStatus();
        }catch(Exception e){System.err.println("Error: "+e.getMessage());}
    }
}
