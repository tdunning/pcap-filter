package com.mapr;

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Concatenates PCAP files. The only trickiness is that we have to skip the
 * 24 byte header on all but the first file.
 */
public class ConcatPcap {
    public static void main(String[] args) throws IOException {
        try (DataOutputStream out = new DataOutputStream(System.out)) {
            if (args.length > 0) {
                boolean first = true;
                for (String arg : args) {
                    try (FileInputStream in = new FileInputStream(arg)) {
                        copy(first, in, out);
                        first = false;
                    }
                }
            } else {
                copy(true, System.in, out);
            }
        }
    }

    /**
     * Concatenates a stream onto the output.
     * @param first   Is this the beginning of the output?
     * @param in      The data to copy to the output
     * @param out     Where the output should go
     * @throws IOException
     */
    public static void copy(boolean first, InputStream in, DataOutputStream out) throws IOException {
        byte[] buffer = new byte[1024 * 1024];
        int n;
        if (!first) {
            //noinspection UnusedAssignment
            n = (int) in.skip(6 * 4L);
        }
        n = in.read(buffer);
        while (n > 0) {
            out.write(buffer, 0, n);
            n = in.read(buffer);
        }
    }
}
