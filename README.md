# PacketDetective 🔍
### Java-Based Network Packet Analysis & Protocol Classification Engine

PacketDetective is a Java-based network packet analysis engine that reads PCAP (Packet Capture) files, parses network packet headers, identifies communication protocols, and classifies network traffic.

The project explores how network traffic can be analyzed at the packet level using Java, with a focus on networking fundamentals, byte-level parsing, protocol identification, and packet-processing concepts.

## 🚀 Key Features

- **PCAP File Processing:** Reads captured network traffic from PCAP files.
- **Ethernet Parsing:** Extracts Ethernet frame information.
- **IPv4 Analysis:** Parses IPv4 headers and extracts network-layer information.
- **TCP & UDP Support:** Identifies and processes TCP and UDP packets.
- **Protocol Classification:** Recognizes supported application-level protocols and services.
- **Packet Statistics:** Reports packet counts, total bytes, transport protocol distribution, and classification results.
- **Java Implementation:** Demonstrates byte manipulation, object-oriented programming, and network protocol analysis.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Java | Core implementation |
| PCAP | Packet capture input format |
| Ethernet | Data-link layer parsing |
| IPv4 | Network-layer packet analysis |
| TCP / UDP | Transport-layer protocol analysis |
| DNS / HTTP | Application protocol identification |
| Git & GitHub | Version control |

## 🏗️ How It Works

PacketDetective processes captured network traffic through a packet-analysis workflow.

```text
          PCAP Input File
                 |
                 v
          Packet Reader
                 |
                 v
         Ethernet Parsing
                 |
                 v
           IPv4 Parsing
                 |
                 v
       Transport Protocol Analysis
             /       \
           TCP       UDP
             \       /
                 |
                 v
       Protocol Classification
                 |
                 v
          Packet Statistics
                 |
                 v
          Analysis Output
```

### Processing Workflow

1. **Read PCAP:** Load packets from the supplied capture file.
2. **Parse Ethernet:** Extract Ethernet frame information.
3. **Parse IPv4:** Identify IPv4 packets and inspect their headers.
4. **Identify Transport Protocol:** Determine whether the packet uses TCP or UDP.
5. **Classify Traffic:** Inspect supported protocol information and classify recognizable traffic.
6. **Generate Statistics:** Summarize packet counts, bytes, transport protocols, and classifications.

## 📡 Supported Protocols & Classifications

The implementation handles:

- Ethernet
- IPv4
- TCP
- UDP
- DNS
- HTTP

The classification engine also recognizes supported service categories, including:

- Google
- Facebook
- YouTube
- Twitter
- Instagram
- Amazon
- Microsoft
- Apple
- Telegram
- TikTok
- Spotify
- Zoom
- Discord
- GitHub
- Cloudflare

Classification depends on the information available in the captured packets. Not every packet can be identified, so some traffic may be classified as `UNKNOWN`.

## ⚙️ Getting Started

### Prerequisites

- Java Development Kit (JDK)
- Git
- Windows PowerShell or a compatible terminal

### 1. Clone the Repository

```bash
git clone https://github.com/snehify/PacketDetective.git
cd PacketDetective
```

### 2. Compile the Java Source Files

Run the following command in PowerShell:

```powershell
javac -d out (Get-ChildItem external\dcpappi\include\*.java, external\dcpappi\src\*.java).FullName
```

### 3. Run PacketDetective

```powershell
java -cp out dpi.Main "external\dcpappi\testdata\test_dpi.pcap" "external\dcpappi\testdata\output.pcap"
```

The program processes the supplied PCAP file and generates packet-analysis statistics.

## 📊 Sample Execution Results

Example output from a test PCAP file:

| Metric | Result |
|---|---:|
| Total Packets | 77 |
| Total Bytes | 5,738 |
| TCP Packets | 73 |
| UDP Packets | 4 |
| Forwarded Packets | 0 |
| Dropped Packets | 0 |

Example classification results include:

| Classification | Packets |
|---|---:|
| UNKNOWN | 21 |
| HTTP | 2 |
| DNS | 4 |

Other recognized service classifications include Google, YouTube, GitHub, Microsoft, Telegram, Spotify, and Cloudflare.

*Note: Results are from a specific test capture and will vary depending on the input PCAP file.*

## 💡 Technical Concepts Explored

This project provided practical experience with:

- Network protocol layering and encapsulation.
- Ethernet, IPv4, TCP, and UDP packet structures.
- Byte manipulation and binary data parsing in Java.
- Header offsets and packet payload inspection.
- Application protocol identification.
- Packet classification and traffic analysis.
- Object-oriented design and modular Java development.

## 🔮 Future Improvements

Potential enhancements include:

- Live network traffic capture and analysis.
- Expanded application protocol detection.
- Improved handling of encrypted traffic and unknown packets.
- Connection tracking and flow-level statistics.
- Advanced multithreaded packet processing.
- Real-time network traffic monitoring and visualization.
- Extended telecom protocol analysis.

## 👩‍💻 Author

- GitHub: [@snehify](https://github.com/snehify)
- LinkedIn: [snehacodes](https://www.linkedin.com/in/snehacodes/)

---

⭐ If you find this project interesting, consider starring the repository!
