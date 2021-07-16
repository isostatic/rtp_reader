# rtp_reader

A quick and dirty tool to take a pcap file and look at RTP streams inside it, looking for gaps in the RTP sequence number, CC numbers on the pids, and optionally outputting the contents to a file for later playback

Used for internal debugging, but might be useful to people who are as smoothbrained as me and don't have any proper tools. Any issues, tough. Any comments on the terrible code quality? Tougher. 

Parse a tcpdump capture file
  ./dumpts.py -i /tmp/cap.cap 

Listen across a span port for all RTP streams and output stats every second in an interactive session
  tcpdump -i eno2 -w - | ./dumpts.py  -s 1 -rt

Listen across a span port for all RTP streams and output stats every 10 seconds to different logfiles
  tcpdump -i eno2 -w - | ./dumpts.py  -s 4 -l /var/tmp/eno2

Dump contents of a capture to a .ts (appends to existing TS for use on concattenated caps)
  ./dumpts.py -i /tmp/cap.cap -o output

