package com.mapr;

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by tdunning on 11/10/15.
 */
public class ConcatPcap {
    public static void main(String[] args) throws IOException {
        try (DataOutputStream out = new DataOutputStream(System.out)) {
            boolean first = true;
            if (args.length > 0) {
                for (String arg : args) {
                    try (FileInputStream in = new FileInputStream(arg)) {
                        copy(first, in, out);
                        first = false;
                    }
                }
            } else {
                copy(first, System.in, out);
            }
        }
    }


    private static void copy(boolean first, InputStream in, DataOutputStream out) throws IOException {
        byte[] buffer = new byte[1024 * 1024];
        int n;
        if (!first) {
            n = (int) in.skip(6 * 4L);
        }
        n = in.read(buffer);
        while (n > 0) {
            out.write(buffer, 0, n);
            n = in.read(buffer);
        }
    }
}
