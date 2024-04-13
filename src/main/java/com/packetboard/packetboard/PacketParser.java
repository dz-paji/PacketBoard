package com.packetboard.packetboard;

import com.packetboard.packetboard.Parser.EthernetFrame;
import com.packetboard.packetboard.Parser.Ipv4Packet;
import com.packetboard.packetboard.Parser.Ipv6Packet;
import com.packetboard.packetboard.Parser.Pcap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class PacketParser {
    private Pcap data;
    private final TreeMap<String, Integer> localTalkers = new TreeMap<>(); // IP: Packet count.
    private final TreeMap<String, String> addressResolution = new TreeMap<>(); // IP: MAC
    private final TreeMap<String, Long> dataCount = new TreeMap<>(); // dstIP: Data(bytes)
    private final TreeMap<String, ArrayList> sniRecords = new TreeMap<>(); // dstIP: Arraylist(SNI(domain name))
    private final TreeMap<String, String> rDNSRecords = new TreeMap<>(); // IP: rDNS
    private Integer ipv4Counts = 0;
    private Integer ipv6Counts = 0;
    private Logger logger = LogManager.getLogger(PacketParser.class);

    /**
     * Header length of each protocol.
     */
    private static class overheadLenght {
        public static final int ETHERNET = 14; // IEEE 802.3
        public static final int IPV4 = 20;
        public static final int ICMP = 8;
        public static final int UDP = 8;
        public static final int TCP = 20;
        public static final int ARP = 28;
        public static final int RAW = 0; // Begins with IPv4/IPv6
        public static final int IEEE802_11 = 22; // WIFI
    }

    public void load(String fileName, Boolean doSNI, Boolean dorDNS) {
        try {
            data = Pcap.fromFile(fileName);
            // check link-type.
            var linkType = data.hdr().network();

            // Create thread pool
            ExecutorService executors = Executors.newFixedThreadPool(4);
            ArrayList<Future> futures = new ArrayList<>();
            data.packets().forEach(packet -> {
                futures.add(executors.submit(() -> {
                    switch (linkType) {
                        case ETHERNET:
                            EthernetFrame ethFrame = (EthernetFrame) packet.body();
                            parseEther(ethFrame, doSNI, dorDNS);
                            break;
                    }
                    return;
                }));
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void parseEther(EthernetFrame ethFrame, Boolean doSNI, Boolean dorDNS) {
        // Check the type of the next packet
        switch (ethFrame.etherType()) {
            case IPV4:
                ipv4Counts++;

                Ipv4Packet ipv4Packet = (Ipv4Packet) ethFrame.body();
                String destIPv4 = parseIPv4(ipv4Packet.dstIpAddr());
                String srcIPv4 = parseIPv4(ipv4Packet.srcIpAddr());
                String srcMAC = parseMac(ethFrame.srcMac());
                String dstMAC = parseMac(ethFrame.dstMac());
                var size = ipv4Packet.totalLength();

                // SNI
                if (doSNI && sniRecords.get(destIPv4) == null) {
                    var sni = getSNI(destIPv4);
                    sniRecords.put(destIPv4, sni);
                }

                // rDNS
                if (dorDNS && rDNSRecords.get(destIPv4) == null) {
                    var rDNS = getRDNS(destIPv4);
                    rDNSRecords.put(destIPv4, rDNS);
                }

                // Add stats from the packet
                registerPacket(srcIPv4, destIPv4, srcMAC, dstMAC, size);

                break;
            case IPV6:
                ipv6Counts++;

                Ipv6Packet ipv6Packet = (Ipv6Packet) ethFrame.body();
                String destIPv6 = parseIPv6(ipv6Packet.dstIpv6Addr());
                String srcIPv6 = parseIPv6(ipv6Packet.srcIpv6Addr());
                String srcMAC6 = parseMac(ethFrame.srcMac());
                String dstMAC6 = parseMac(ethFrame.dstMac());
                var size6 = ipv6Packet.payloadLength();

                // Add stats from the packet
                registerPacket(srcIPv6, destIPv6, srcMAC6, dstMAC6, size6);
                break;
        }
    }

    private String getRDNS(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.getCanonicalHostName();
        } catch (UnknownHostException e) {
            logger.error("Host unknown for rDNS of {}", ip);
            logger.debug(e);
            return "Unknown";
        }
    }

    private ArrayList getSNI(String ip) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");

            // Custom trust manager
            ctx.init(null, new TrustManager[]{new SniTrustManager()}, null);
            SSLSocketFactory factory = ctx.getSocketFactory();
            SSLSocket socks = (SSLSocket) factory.createSocket(ip, 443);


            socks.startHandshake();
            var session = socks.getSession();

            var certs = session.getPeerCertificates();
            var cert = (X509Certificate) certs[0];
            var altNames = cert.getSubjectAlternativeNames();
            if (altNames == null) {
                return new ArrayList();
            }
            ArrayList<String> names = new ArrayList<>();
            altNames.forEach(name -> {
                names.add(name.get(1).toString());
            });
            return names;
        } catch (IOException e) {
            logger.error("IO Exception while lookup SNI for {}", ip);
            logger.debug(e);
            return new ArrayList();
        } catch (NoSuchAlgorithmException | KeyManagementException | CertificateParsingException e) {
            logger.error("Certificate error while lookup SNI for {}", ip);
            logger.debug(e);
            return new ArrayList();
        }
    }

    private void registerPacket(String srcIPv4, String destIPv4, String srcMAC, String dstMAC, int size) {
        // Register the packet
        if (localTalkers.get(srcIPv4) == null) {
            localTalkers.put(srcIPv4, 1);
        } else {
            localTalkers.put(srcIPv4, localTalkers.get(srcIPv4) + 1);
        }

        // Count data
        if (dataCount.get(destIPv4) == null) {
            dataCount.put(destIPv4, (long) size);
        } else {
            dataCount.put(destIPv4, dataCount.get(destIPv4) + size);
        }

        // Register the MAC address
        // ASSUMPTION: An IP address will only associate with one MAC address.
        addressResolution.putIfAbsent(srcIPv4, srcMAC);
        addressResolution.putIfAbsent(destIPv4, dstMAC);
    }

    private String parseIPv6(byte[] ipAddr) {
        StringBuilder builder = new StringBuilder();
        for (byte b : ipAddr) {
            var this_int = Integer.parseInt(String.format("%02X", b), 16);
            builder.append(this_int).append(":");
        }

        // remove the last column
        builder.deleteCharAt(builder.length() - 1);
        return builder.toString();
    }

    private String parseIPv4(byte[] srcIpAddr) {
        var a = String.format("%02X", srcIpAddr[0]);
        var b = String.format("%02X", srcIpAddr[1]);
        var c = String.format("%02X", srcIpAddr[2]);
        var d = String.format("%02X", srcIpAddr[3]);
        var a_int = Integer.parseInt(a, 16);
        var b_int = Integer.parseInt(b, 16);
        var c_int = Integer.parseInt(c, 16);
        var d_int = Integer.parseInt(d, 16);
        return String.format("%d.%d.%d.%d", a_int, b_int, c_int, d_int);
    }

    private String parseMac(byte[] mac) {
        var a = String.format("%02X", mac[0]);
        var b = String.format("%02X", mac[1]);
        var c = String.format("%02X", mac[2]);
        var d = String.format("%02X", mac[3]);
        var e = String.format("%02X", mac[4]);
        var f = String.format("%02X", mac[5]);
        return String.format("%s:%s:%s:%s:%s:%s", a,b,c,d,e,f);
    }

    private class SniTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

}