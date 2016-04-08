package com.mapr;

import com.google.common.base.Preconditions;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Shorts;

import java.io.IOException;
import java.io.InputStream;

/**
 * Created by tdunning on 11/9/15.
 */
public class PacketDecoder {
    //  typedef struct pcap_hdr_s {
    //      guint32 magic_number;   /* magic number */
    //      guint16 version_major;  /* major version number */
    //      guint16 version_minor;  /* minor version number */
    //      gint32  thiszone;       /* GMT to local correction */
    //      guint32 sigfigs;        /* accuracy of timestamps */
    //      guint32 snaplen;        /* max length of captured packets, in octets */
    //      guint32 network;        /* data link type */
    //  } pcap_hdr_t;
    //  magic_number: used to detect the file format itself and the byte ordering. The writing application writes
    //    0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will read
    //    either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads the swapped
    //    0xd4c3b2a1 value, it knows that all the following fields will have to be swapped too. For
    //    nanosecond-resolution files, the writing application writes 0xa1b23c4d, with the two nibbles
    //    of the two lower-order bytes swapped, and the reading application will read either 0xa1b23c4d
    //    (identical) or 0x4d3cb2a1 (swapped).
    //  version_major, version_minor: the version number of this file format (current version is 2.4)
    //  thiszone: the correction time in seconds between GMT (UTC) and the local timezone of the following
    //     packet header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0.
    //     If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00,
    //     thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
    //  sigfigs: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
    //  snaplen: the "snapshot length" for the capture (typically 65535 or even more, but might be limited
    //     by the user), see: incl_len vs. orig_len below
    //  network: link-layer header type, specifying the type of headers at the beginning of the packet (e.g.
    //     1 for Ethernet, see tcpdump.org's link-layer header types page for details); this can be various
    //     types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.
    public static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PCAP_MAGIC_LITTLE_ENDIAN = 0xD4C3B2A1;
    public final byte[] globalHeader = new byte[GLOBAL_HEADER_SIZE];
    public static final int PCAP_MAGIC_NUMBER = 0xA1B2C3D4;

    public static final int etherHeaderLength = 14;
    public static final int etherTypeOffset = 12;
    public static final int etherTypeIP = 0x800;

    private final int maxLength;
    private boolean bigEndian;

    private InputStream input;

    public PacketDecoder(InputStream input) throws IOException {
        this.input = input;
        input.read(globalHeader);
        switch (getInt(globalHeader, 0)) {
            case PCAP_MAGIC_NUMBER:
                bigEndian = true;
                break;
            case PCAP_MAGIC_LITTLE_ENDIAN:
                bigEndian = false;
                break;
            default:
                Preconditions.checkState(false, String.format("Bad magic number = %08x", getIntFileOrder(globalHeader, 0)));
        }
        Preconditions.checkState(getShortFileOrder(globalHeader, 4) == 2, "Wanted major version == 2");
        maxLength = getIntFileOrder(globalHeader, 16);
    }

    public void addTcpListener(TcpListener listener) {

    }

    public Packet nextPacket() throws IOException {
        Packet r = new Packet();
        if (r.readPcap(input)) {
            return r;
        } else {
            return null;
        }
    }

    public boolean isBigEndian() {
        return bigEndian;
    }

    public int decodePacket(byte[] buffer, int offset, Packet p) {
        return p.decodePcap(buffer, offset);
    }

    public Packet packet() {
        return new Packet();
    }

    private class InvalidPcapFormat extends IOException {
        public InvalidPcapFormat(String msg) {
            super(msg);
        }
    }

    private class TcpListener {
    }

    public int getIntFileOrder(byte[] buf, int offset) {
        if (bigEndian) {
            return Ints.fromBytes(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
        } else {
            return Ints.fromBytes(buf[offset + 3], buf[offset + 2], buf[offset + 1], buf[offset]);
        }
    }

    public int getShortFileOrder(byte[] buf, int offset) {
        if (bigEndian) {
            return Shorts.fromBytes(buf[offset], buf[offset + 1]);
        } else {
            return Shorts.fromBytes(buf[offset + 1], buf[offset]);
        }
    }

    public int getInt(byte[] buf, int offset) {
        return Ints.fromBytes(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
    }

    public int getShort(byte[] buf, int offset) {
        return 0xffff & Shorts.fromBytes(buf[offset], buf[offset + 1]);
    }

    public int getByte(byte[] buf, int offset) {
        return 0xff & buf[offset];
    }

    public class Packet {
        // pcap header
        //        typedef struct pcaprec_hdr_s {
        //            guint32 ts_sec;         /* timestamp seconds */
        //            guint32 ts_usec;        /* timestamp microseconds */
        //            guint32 incl_len;       /* number of octets of packet saved in file */
        //            guint32 orig_len;       /* actual length of packet */
        //        } pcaprec_hdr_t;
        private static final int PCAP_HEADER_SIZE = 4 * 4;
        private static final byte ICMP_PROTOCOL = 1;
        private static final byte TCP_PROTOCOL = 6;
        private static final byte UDP_PROTOCOL = 17;
        private static final int HOP_BY_HOP_EXTENSION_V6 = 0;
        private static final int DESTINATION_OPTIONS_V6 = 60;
        private static final int ROUTING_V6 = 43;
        private static final int FRAGMENT_V6 = 44;
        private static final int AUTHENTICATION_V6 = 51;
        private static final int ENCAPSULATING_SECURITY_V6 = 50;
        private static final int MOBILITY_EXTENSION_V6 = 135;
        private static final int NO_NEXT_HEADER = 59;

        private long timestamp;

        private byte[] pcapHeader;
        private int pcapOffset;
        private byte[] raw;

        int etherOffset;
        int ipOffset;
        int ipVersion;
        int subOffset;
        int payloadOffset;

        private int packetLength;
        private int etherProtocol;
        private int protocol;

        public boolean readPcap(InputStream in) throws IOException {
            pcapHeader = new byte[PCAP_HEADER_SIZE];
            pcapOffset = 0;
            int n = in.read(pcapHeader);
            if (n < pcapHeader.length) {
                return false;
            }
            int originalLength = decodePcapHeader();

            raw = new byte[originalLength];
            n = in.read(raw);
            etherOffset = 0;

            decodeEtherPacket();
            return true;
        }

        public int decodePcap(byte[] buffer, int offset) {
            pcapHeader = buffer;
            pcapOffset = offset;
            int originalLength = decodePcapHeader();

            raw = buffer;
            etherOffset = offset + PCAP_HEADER_SIZE;

            decodeEtherPacket();
            return offset + PCAP_HEADER_SIZE + originalLength;
        }

        private void decodeEtherPacket() {
            int n;
            etherProtocol = getShort(raw, etherOffset + 12);
            ipOffset = etherOffset + 14;
            if (isIpV4Packet()) {
                Preconditions.checkState(ipVersion() == 4, "Should have seen IP version 4, got %d", ipVersion());
                ipVersion = 4;

                n = ipV4HeaderLength();
                Preconditions.checkState(n >= 20 && n < 200, "Invalid header length: ", n);
                subOffset = ipOffset + n;

                Preconditions.checkState(getShort(raw, ipOffset + 6) == 0, "Don't support IP fragmentation yet");

                protocol = getByte(raw, ipOffset + 9);
                if (isTcpPacket()) {
                    payloadOffset = subOffset + (raw[subOffset + 12] >>> 4);
                }
            } else if (isIpV6Packet()) {
                Preconditions.checkState(ipVersion() == 6, "Should have seen IP version 6, got %d", ipVersion());
                ipVersion = 6;

                int headerLength = 40;
                int nextHeader = raw[ipOffset + 6] & 0xff;
                while (nextHeader != TCP_PROTOCOL && nextHeader != UDP_PROTOCOL && nextHeader != NO_NEXT_HEADER) {
                    switch (nextHeader) {
                        case HOP_BY_HOP_EXTENSION_V6:
                            nextHeader = getByte(raw, ipOffset + headerLength);
                            headerLength += (getByte(raw, ipOffset + headerLength) + 1) * 8;
                            break;
                        case DESTINATION_OPTIONS_V6:
                            nextHeader = getByte(raw, ipOffset + headerLength);
                            headerLength += (getByte(raw, ipOffset + headerLength) + 1) * 8;
                            break;
                        case ROUTING_V6:
                            nextHeader = getByte(raw, ipOffset + headerLength);
                            headerLength += (getByte(raw, ipOffset + headerLength) + 1) * 8;
                            break;
                        case FRAGMENT_V6:
                            nextHeader = getByte(raw, ipOffset + headerLength);
                            headerLength += 8;
                            break;
                        case AUTHENTICATION_V6:
                            break;
                        case ENCAPSULATING_SECURITY_V6:
                            Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
                            break;
                        case MOBILITY_EXTENSION_V6:
                            Preconditions.checkState(false, "Can't handle ENCAPSULATING_SECURITY extension");
                            break;
                        default:
                            Preconditions.checkState(false, "Unknown V6 extension or protocol: ", nextHeader);
                            break;
                    }
                }

                if (nextHeader != NO_NEXT_HEADER) {
                    payloadOffset = ipOffset + headerLength;
                }
                protocol = nextHeader;
            }
        }

        private int decodePcapHeader() {
            timestamp = getIntFileOrder(pcapHeader, pcapOffset) * 1000000L + getIntFileOrder(pcapHeader, 4);
            int originalLength = getIntFileOrder(pcapHeader, pcapOffset + 8);
            Preconditions.checkState(originalLength < maxLength, "Packet too long (%d bytes)", originalLength);
            packetLength = getIntFileOrder(pcapHeader, pcapOffset + 12);
            return originalLength;
        }

        private int ipV4HeaderLength() {
            return (getByte(raw, ipOffset) & 0xf) * 4;
        }

        private int ipVersion() {
            return getByte(raw, ipOffset) >>> 4;
        }

        public byte[] getEthernetSource() {
            byte[] r = new byte[6];
            System.arraycopy(raw, 0, r, 0, 6);
            return r;
        }

        public byte[] getEthernetDestination() {
            byte[] r = new byte[6];
            System.arraycopy(raw, 6, r, 0, 6);
            return r;
        }

        public boolean isIpV4Packet() {
            return etherProtocol == 0x800;
        }

        public boolean isIpV6Packet() {
            return etherProtocol == 0x86dd;
        }

        public boolean isTcpPacket() {
            return protocol == TCP_PROTOCOL;
        }

        public boolean isUdpPacket() {
            return protocol == UDP_PROTOCOL;
        }

        public int getPacketLength() {
            return packetLength;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }
}
