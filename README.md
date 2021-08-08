# rtp_reader 

# dumpts.py

A quick and dirty tool to take a pcap file and look at RTP streams inside it, looking for gaps in the RTP sequence number, CC numbers on the pids, and optionally outputting the contents to a file for later playback

Might be useful for people looking at RTP streams and don't have any proper tools. Any issues, tough. Any comments on the terrible code quality? Tough, I know that, I'm not a developer, I write tools to the minimum quality to help me do a job and then move on.

Parse a tcpdump capture file
  ./dumpts.py -i /tmp/cap.cap 

Listen across a span port for all RTP streams and output stats every second in an interactive session
  tcpdump -i eno2 -w - | ./dumpts.py  -s 1 -rt

Listen across a span port for all RTP streams and output stats every 10 seconds to different logfiles
  tcpdump -i eno2 -w - | ./dumpts.py  -s 4 -l /var/tmp/eno2

Dump contents of a capture to a .ts (appends to existing TS for use on concattenated caps)
  ./dumpts.py -i /tmp/cap.cap -o output


# rtpwatch.*

An ebpf filter which looks for holes in RTP streams / sequence numbers and reports them to userspace (as well as keeping a track, far more efficent than using dumpts. I've not written any C for 20 years so not great but I think (combined with BCC's lovely errors) it's secure enough. Likely has a memory leak as it doesn't time out rtp streams from memory, so every stream it sees stays forever.
