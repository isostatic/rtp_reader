# rtp_reader

A quick and dirty tool to take a pcap file and look at RTP streams inside it, looking for gaps in the RTP sequence number, CC numbers on the pids, and optionally outputting the contents to a file for later playback

Parse a tcpdump capture file
  ./dumpts.py -i /tmp/cap.cap 

Listen across a span port for all RTP streams and output stats every 4000 packets
  tcpdump -i eno2 -w - | ./dumpts.py  -s 4000

Dump contents of a capture to a .ts (appends to existing TS for use on concattenated caps)
  ./dumpts.py -i /tmp/cap.cap -o output

