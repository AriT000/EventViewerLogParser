# EventViewerLogParser
Parses logs from Windows EventViewer, noting the following:  
- Unusual logins
- System errors
- Critical events

<br />

### Usage:
---

1. Export logs to .csv format:  
    > Open Windows Event Viewer  
    > Select the logs you want to analyze  
    > Choose "Save All Events As..."  
    > Select CSV as the format  

2. Run the script:  

`python windows_event_parser.py your_exported_logs.csv`  

3. Optional parameters:

`--format json` for JSON output  
`--output filename.txt` to save to a file
