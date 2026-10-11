# external/dcpappi — Java DPI project package

This folder combines the Java core components and Java entry points. C++ source/header files (`.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`) are excluded.

## Folder structure

- `include/` — Java core components (package `dpi`)
- `src/` — Java entry points and `GenerateTestPcap.java`
- `testdata/` — sample PCAP captures
- `resources/reference/` — original CMake configuration and Python generator retained for reference; they are not required to compile the Java code
- `README_ORIGINAL.md`, `WINDOWS_SETUP.md` — supplied project documentation

Requires Java 17 or newer. Run these commands from the `external` folder (the parent of `dcpappi`):

```powershell
javac -d out (Get-ChildItem dcpappi\include\*.java, dcpappi\src\*.java).FullName
java -cp out dpi.Main dcpappi\testdata\test_dpi.pcap dcpappi\testdata\output_java.pcap
```

To generate a new synthetic capture, run this from `external\dcpappi\src` or specify an output path:

```powershell
javac GenerateTestPcap.java
java GenerateTestPcap ..\testdata\generated_test.pcap
```

Note: the original `dpi_engine` executable was not copied because it is a compiled non-Java binary. The Java DPI implementation is a conversion, so behavior may not be identical to the original C++ implementation.
