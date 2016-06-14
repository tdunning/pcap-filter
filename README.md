# pcap-filter
Experiments in PCAP file decoding at speed

The basic idea is the ordinary PCAP decoders available in Java give away boatloads 
of speed by very bad I/O patterns and creation of too many objects.
 
It is much more efficient to read a ton of data into memory and then "parse" it
without moving anything. Any characteristic of packets that you want can be 
interrogated directly from the bytes in question on demand which increases speed
further by avoiding the decoding of data that just gets thrown away.

The tests in this project are really demonstration programs that show how much 
difference this can make. You can run these tests using

    mvn test

## Just how fast is it?

Well, if you don't have just less than a minute to run the tests, here is what I 
get on my laptop:

    Speed test for per packet object without buffering
        Read 859.7 MB in 14.93 s for 57.6 MB/s
        8772352 packets, 8772352 TCP packets, 0 UDP
    
    Speed test for per packet object with buffering
        Read 859.7 MB in 1.13 s for 761.1 MB/s
        8772352 packets, 8772352 TCP packets, 0 UDP
        
    Speed test for in-place packet decoding
        Read 859.7 MB in 0.53 s for 1611.4 MB/s
        8772352 packets, 8772352 TCP packets, 0 UDP
    
The data here is in cache, not on disk. Since we want to see how fast this can go 
without worrying about extraneous bottlenecks, this is good.
 
The short answer is that buffering and decoding packages in a sensible way is about 
30x faster than being silly. Of this improvement, simply buffering reasonably
gives nearly 15x improvement and in-place decoding gives the remaining 2x.

To illustrate the improvement due to better I/O patterns, here are results 
from a different test that reads a GB of data using different size
reads:

| Read size | Time | Speed |
| ---------: | ----: | -----: |
| 50	| 16.4 s | 60.9 MB/s  |
| 100	| 8.7 s | 114.6 MB/s  |
| 200	| 4.6 s | 216.6 MB/s  |
| 500	| 2.0 s | 489.0 MB/s  |
| 1000	| 1.1 s | 911.5 MB/s  |
| 2000	| 0.7 s | 1456.9 MB/s |
| 3000	| 0.6 s | 1699.6 MB/s |
| 4000	| 0.6 s | 1709.6 MB/s |
| 5000	| 0.4 s | 2321.1 MB/s |
| 6000	| 0.4 s | 2497.3 MB/s |
| 8000	| 0.5 s | 2025.8 MB/s |
| 10000	| 0.5 s | 2191.2 MB/s |

