package com.mapr;

import com.google.common.io.Resources;
import org.junit.Assert;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by tdunning on 11/10/15.
 */
public class PacketDecoderTest {
    @Test
    public void testByteOrdering() throws IOException {
        File f = File.createTempFile("foo", "pcap");
        f.deleteOnExit();
        try (DataOutputStream out = new DataOutputStream(new FileOutputStream(f))) {
            writeHeader(out);
        }

        byte[] buf = new byte[4];
        try (InputStream in = new FileInputStream(f)) {
            PacketDecoder pd = new PacketDecoder(in);
            assertTrue(pd.isBigEndian());
        }
    }

    public static void writeHeader(DataOutputStream out) throws IOException {
        //        typedef struct pcap_hdr_s {
        //            guint32 magic_number;   /* magic number */
        //            guint16 version_major;  /* major version number */
        //            guint16 version_minor;  /* minor version number */
        //            gint32  thiszone;       /* GMT to local correction */
        //            guint32 sigfigs;        /* accuracy of timestamps */
        //            guint32 snaplen;        /* max length of captured packets, in octets */
        //            guint32 network;        /* data link type */
        //        } pcap_hdr_t;
        //        magic_number: used to detect the file format itself and the byte ordering. The writing application writes 0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will read either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads the swapped 0xd4c3b2a1 value, it knows that all the following fields will have to be swapped too. For nanosecond-resolution files, the writing application writes 0xa1b23c4d, with the two nibbles of the two lower-order bytes swapped, and the reading application will read either 0xa1b23c4d (identical) or 0x4d3cb2a1 (swapped).
        //        version_major, version_minor: the version number of this file format (current version is 2.4)
        //        thiszone: the correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
        //        sigfigs: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
        //        snaplen: the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user), see: incl_len vs. orig_len below
        //        network: link-layer header type, specifying the type of headers at the beginning of the packet (e.g. 1 for Ethernet, see tcpdump.org's link-layer header types page for details); this can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.

        out.writeInt(0xa1b2c3d4);        // PCAP magic number
        out.writeShort(2);               // version 2.4
        out.writeShort(4);
        out.writeInt(0);                 // assume GMT times
        out.writeInt(0);                 // everybody does this
        out.writeInt(65536);             // customary length limit
        out.writeInt(1);                 // ETHERNET
    }

    @Test
    public void testSpeed() throws IOException {
//        DataInputStream in = Resources.getResource("data-20M.pcap").openStream();
        InputStream in = new FileInputStream("tcp-5.pcap");
        PacketDecoder pd = new PacketDecoder(in);
        PacketDecoder.Packet p = pd.nextPacket();
        long total = 0;
        int tcpCount = 0;
        int udpCount = 0;
        int allCount = 0;
        long t0 = System.nanoTime();
        while (p != null) {
            total += p.getPacketLength();
            allCount++;
            if (p.isTcpPacket()) {
                tcpCount++;
            } else if (p.isUdpPacket()) {
                udpCount++;
            }
            p = pd.nextPacket();
        }
        long t1 = System.nanoTime();
        System.out.printf("Read %.1f MB in %.2f s for %.1f MB/s\n", total / 1e6, (t1 - t0) / 1e9, (double) total * 1e3 / (t1 - t0));
        System.out.printf("%d packets, %d TCP packets, %d UDP\n", allCount, tcpCount, udpCount);
    }

    @Test
    public void testBufferDecode() throws IOException {
        InputStream in = new FileInputStream("tcp-5.pcap");
        PacketDecoder pd = new PacketDecoder(in);
        PacketDecoder.Packet p = pd.packet();

        byte[] buffer = new byte[100000];
        int validBytes = in.read(buffer);

        int offset = pd.decodePacket(buffer, 0, p);
        long total = 0;
        int tcpCount = 0;
        int udpCount = 0;
        int allCount = 0;
        long t0 = System.nanoTime();
        while (p != null) {
            total += p.getPacketLength();
            allCount++;
            if (p.isTcpPacket()) {
                tcpCount++;
            } else if (p.isUdpPacket()) {
                udpCount++;
            }
            offset = pd.decodePacket(buffer, offset, p);
            if (validBytes - offset < 5000) {
                System.arraycopy(buffer, 0, buffer, offset, validBytes - offset);
                validBytes = validBytes - offset;
                int n = in.read(buffer, validBytes, buffer.length - validBytes);
                if (n <= 0) {
                    p = null;
                } else {
                    validBytes += n;
                    offset = 0;
                }
            }
        }
        long t1 = System.nanoTime();
        System.out.printf("Read %.1f MB in %.2f s for %.1f MB/s\n", total / 1e6, (t1 - t0) / 1e9, (double) total * 1e3 / (t1 - t0));
        System.out.printf("%d packets, %d TCP packets, %d UDP\n", allCount, tcpCount, udpCount);

    }

    @Test
    public void testBigReads() throws IOException {
        for (int size : new int[]{10, 10, 10, 20, 50, 100, 200, 500, 1000, 10000}) {
            try (InputStream in = new FileInputStream("tcp-5.pcap")) {
                long t0 = System.nanoTime();
                byte[] buf = new byte[size];
                long total = 0;
                int foo = 0;
                int n = in.read(buf);
                while (n > 0) {
                    foo += buf[3];
                    total += n;
                    n = in.read(buf);
                }
                long t1 = System.nanoTime();
                double t = (t1 - t0) * 1e-9;
                System.out.printf("%d\t%.1f MB in %.1f s, %.1f MB/s\n", size, total * 1e-6, t, total * 1e-6 / t);
            }

        }
    }
}