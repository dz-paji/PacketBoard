package com.packetboard.packetboard;

import com.packetboard.packetboard.Parser.Pcap;

import java.io.IOException;

public class PacketParser {
    Pcap data;
    public void load(String fileName) {
        try {
            data = Pcap.fromFile(fileName);
        } catch (IOException e)
        {

        }
    }
}
