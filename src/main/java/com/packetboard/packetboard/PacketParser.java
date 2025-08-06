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
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class PacketParser {
    private final ConcurrentHashMap<String, Integer> localTalkers = new ConcurrentHashMap<>(); // IP: Packet count.
    private final ConcurrentHashMap<String, Long> localTalkersData = new ConcurrentHashMap<>(); // IP: data(bytes)
    private final ConcurrentHashMap<String, String> addressResolution = new ConcurrentHashMap<>(); // IP: MAC
    private final ConcurrentHashMap<String, Long> dataCount = new ConcurrentHashMap<>(); // dstIP: Data(bytes)
    private final ConcurrentHashMap<String, ArrayList> sniRecords = new ConcurrentHashMap<>(); // dstIP: Arraylist(SNI(domain name))
    private final ConcurrentHashMap<String, String> rDNSRecords = new ConcurrentHashMap<>(); // IP: rDNS
    private final ConcurrentHashMap<String, Long> sniDataCount = new ConcurrentHashMap<>(); // SNI: Data(bytes)
    private final AtomicInteger ipv4Counts = new AtomicInteger(0);
    private final AtomicInteger ipv6Counts = new AtomicInteger(0);
    private final Logger logger = LogManager.getLogger(PacketParser.class);
    private AtomicBoolean doSNI, dorDNS = new AtomicBoolean(false);

    private Boolean localTrafficStats = true; // Collect local traffic stats. TODO: Bind to JavaFX.

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

    /**
     * Parse a given pcap file.
     *
     * @param fileName Path to the file
     * @param doSNI    Look up SNI for each dst IP?
     * @param dorDNS   Look up rDNS for each dst IP?
     */
    public void load(String fileName, Boolean doSNI, Boolean dorDNS) {
        try {
            // register settings
            this.doSNI = new AtomicBoolean(doSNI);
            this.dorDNS = new AtomicBoolean(dorDNS);
            Pcap data = Pcap.fromFile(fileName);
            // check link-type.
            var linkType = data.hdr().network();

            // Create thread pool
            ExecutorService executors = Executors.newFixedThreadPool(64);
            ArrayList<Future> futures = new ArrayList<>();
            data.packets().forEach(packet -> {
                futures.add(executors.submit(() -> {
                    switch (linkType) {
                        case ETHERNET:
                            EthernetFrame ethFrame = (EthernetFrame) packet.body();
                            parseEther(ethFrame);
                            break;
                    }
                    return;

                }));
            });

            // Wait for all threads to finish
            for (Future future : futures) {
                try {
                    future.get();
                } catch (InterruptedException | ExecutionException e) {
                    logger.error("Error while parsing packet");
                    logger.error(e);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * When link-type of pcap is set to Ethernet. Parse the packet.
     *
     * @param ethFrame Ethernet frame
     */
    private void parseEther(EthernetFrame ethFrame) {
        // Check the type of the next packet
        switch (ethFrame.etherType()) {
            case IPV4:
                ipv4Counts.incrementAndGet();

                Ipv4Packet ipv4Packet = (Ipv4Packet) ethFrame.body();
                String destIPv4 = parseIPv4(ipv4Packet.dstIpAddr());
                String srcIPv4 = parseIPv4(ipv4Packet.srcIpAddr());
                String srcMAC = parseMac(ethFrame.srcMac());
                String dstMAC = parseMac(ethFrame.dstMac());
                var size = ipv4Packet.totalLength();

                // SNI
                if (doSNI.get() && sniRecords.get(destIPv4) == null && !isLocalIPv4(destIPv4)) {
                    var sni = getSNI(destIPv4);
                    if (sni != null) {
                        sniRecords.put(destIPv4, sni);
                    }
                }
                if (doSNI.get() && sniRecords.get(srcIPv4) == null && !isLocalIPv4(srcIPv4)) {
                    var sni = getSNI(srcIPv4);
                    if (sni != null) {
                        sniRecords.put(srcIPv4, sni);
                    }
                }

                // rDNS
                if (dorDNS.get() && rDNSRecords.get(destIPv4) == null && !isLocalIPv4(destIPv4)) {
                    var rDNS = getRDNS(destIPv4);
                    rDNSRecords.put(destIPv4, rDNS);
                }
                if (dorDNS.get() && rDNSRecords.get(srcIPv4) == null && !isLocalIPv4(srcIPv4)) {
                    var rDNS = getRDNS(srcIPv4);
                    rDNSRecords.put(srcIPv4, rDNS);
                }

                // Add stats from the packet
                registerPacket(srcIPv4, destIPv4, srcMAC, dstMAC, size);

                break;
            case IPV6:
                ipv6Counts.incrementAndGet();

                Ipv6Packet ipv6Packet = (Ipv6Packet) ethFrame.body();
                String destIPv6 = parseIPv6(ipv6Packet.dstIpv6Addr());
                String srcIPv6 = parseIPv6(ipv6Packet.srcIpv6Addr());
                String srcMAC6 = parseMac(ethFrame.srcMac());
                String dstMAC6 = parseMac(ethFrame.dstMac());
                var size6 = ipv6Packet.payloadLength();

                //SNI
                if (doSNI.get() && sniRecords.get(destIPv6) == null && !isLocalIPv6(destIPv6)) {
                    var sni = getSNI(destIPv6);
                    sniRecords.put(destIPv6, sni);
                }
                if (doSNI.get() && sniRecords.get(srcIPv6) == null && !isLocalIPv6(srcIPv6)) {
                    var sni = getSNI(srcIPv6);
                    sniRecords.put(srcIPv6, sni);
                }

                // rDNS
                if (dorDNS.get() && rDNSRecords.get(destIPv6) == null) {
                    var rDNS = getRDNS(destIPv6);
                    rDNSRecords.put(destIPv6, rDNS);
                }
                if (dorDNS.get() && rDNSRecords.get(srcIPv6) == null) {
                    var rDNS = getRDNS(srcIPv6);
                    rDNSRecords.put(srcIPv6, rDNS);
                }

                // Add stats from the packet
                registerPacket6(srcIPv6, destIPv6, srcMAC6, dstMAC6, size6);
                break;
        }
    }

    private boolean isLocalIPv4(String ip) {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.") || ip.startsWith("172.17.") || ip.startsWith("172.18.") || ip.startsWith("172.19.") || ip.startsWith("172.20.") || ip.startsWith("172.21.") || ip.startsWith("172.22.") || ip.startsWith("172.23.") || ip.startsWith("172.24.") || ip.startsWith("172.25.") || ip.startsWith("172.26.") || ip.startsWith("172.27.") || ip.startsWith("172.28.") || ip.startsWith("172.29.") || ip.startsWith("172.30.") || ip.startsWith("172.31.");
    }

    private boolean isLocalIPv6(String ip) {
        return ip.startsWith("fe80") || ip.startsWith("fd");
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
            socks.setSoTimeout(1000);
            socks.startHandshake();
            var session = socks.getSession();

            // Reads certs
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
        } catch (SocketTimeoutException e) {
            logger.error("Timeout while lookup SNI for {}", ip);
            logger.debug(e);
            return new ArrayList();
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

    /**
     * Collect stats from a parsed packet.
     *
     * @param srcIPv4  src IP, from pcap.
     * @param destIPv4 dst IP, from pcap.
     * @param srcMAC   src MAC from pcap.
     * @param dstMAC   dst MAC from pcap.
     * @param size     size of the packet as described in IP header.
     */
    private void registerPacket(String srcIPv4, String destIPv4, String srcMAC, String dstMAC, int size) {
        if (isLocalIPv4(srcIPv4)) {
            // Source is local machine
            if (localTalkers.get(srcIPv4) == null) {
                localTalkers.put(srcIPv4, 1);
            } else {
                localTalkers.put(srcIPv4, localTalkers.get(srcIPv4) + 1);
            }

            if (localTalkersData.get(srcIPv4) == null) {
                localTalkersData.put(srcIPv4, (long) size);
            } else {
                localTalkersData.put(srcIPv4, localTalkersData.get(srcIPv4) + size);
            }

            if (localTrafficStats) {
                // Count local networking data with localTalkersData flag set.
                if (dataCount.get(srcIPv4) == null) {
                    dataCount.put(srcIPv4, (long) size);
                } else {
                    dataCount.put(srcIPv4, dataCount.get(srcIPv4) + size);
                }
            }
        } else {
            // Source is Internet machine
            // Count data
            if (dataCount.get(srcIPv4) == null) {
                dataCount.put(srcIPv4, (long) size);
            } else {
                dataCount.put(srcIPv4, dataCount.get(srcIPv4) + size);
            }

            if (doSNI.get()) {
                ArrayList<String> snis = sniRecords.get(srcIPv4);
                if (snis.size() > 0) {
                    String sni = snis.get(0);
                    if (sniDataCount.get(sni) == null) {
                        sniDataCount.put(sni, (long) size);
                    } else {
                        sniDataCount.put(sni, sniDataCount.get(sni) + size);
                    }
                }
            }
        }

        if (isLocalIPv4(destIPv4)) {
            // destination is local machine
            // Source is local machine
            if (localTalkers.get(destIPv4) == null) {
                localTalkers.put(destIPv4, 1);
            } else {
                localTalkers.put(destIPv4, localTalkers.get(destIPv4) + 1);
            }

            if (localTalkersData.get(destIPv4) == null) {
                localTalkersData.put(destIPv4, (long) size);
            } else {
                localTalkersData.put(destIPv4, localTalkersData.get(destIPv4) + size);
            }

            if (localTrafficStats) {
                // Count local networking data with localTalkersData flag set.
                if (dataCount.get(destIPv4) == null) {
                    dataCount.put(destIPv4, (long) size);
                } else {
                    dataCount.put(destIPv4, dataCount.get(destIPv4) + size);
                }
            }
        } else {
            // destination is internet node
            // Count data
            if (dataCount.get(destIPv4) == null) {
                dataCount.put(destIPv4, (long) size);
            } else {
                dataCount.put(destIPv4, dataCount.get(destIPv4) + size);
            }

            if (doSNI.get()) {
                ArrayList<String> snis = sniRecords.get(destIPv4);
                if (snis.size() > 0) {
                    String sni = snis.get(0);
                    if (sniDataCount.get(sni) == null) {
                        sniDataCount.put(sni, (long) size);
                    } else {
                        sniDataCount.put(sni, sniDataCount.get(sni) + size);
                    }
                }
            }
        }

        // Register the MAC address
        // ASSUMPTION: An IP address will only associate with one MAC address.
        addressResolution.putIfAbsent(srcIPv4, srcMAC);
        addressResolution.putIfAbsent(destIPv4, dstMAC);
    }

    /**
     * Collect stats from a parsed packet.
     *
     * @param srcIPv6  src IP, from pcap.
     * @param destIPv6 dst IP, from pcap.
     * @param srcMAC   src MAC from pcap.
     * @param dstMAC   dst MAC from pcap.
     * @param size     size of the packet as described in IP header.
     */
    private void registerPacket6(String srcIPv6, String destIPv6, String srcMAC, String dstMAC, int size) {
        if (isLocalIPv4(srcIPv6)) {
            // Source is local machine
            if (localTalkers.get(srcIPv6) == null) {
                localTalkers.put(srcIPv6, 1);
            } else {
                localTalkers.put(srcIPv6, localTalkers.get(srcIPv6) + 1);
            }

            if (localTalkersData.get(srcIPv6) == null) {
                localTalkersData.put(srcIPv6, (long) size);
            } else {
                localTalkersData.put(srcIPv6, localTalkersData.get(srcIPv6) + size);
            }

            if (localTrafficStats) {
                // Count local networking data with localTalkersData flag set.
                if (dataCount.get(srcIPv6) == null) {
                    dataCount.put(srcIPv6, (long) size);
                } else {
                    dataCount.put(srcIPv6, dataCount.get(srcIPv6) + size);
                }
            }
        } else {
            // Source is Internet machine
            // Count data
            if (dataCount.get(srcIPv6) == null) {
                dataCount.put(srcIPv6, (long) size);
            } else {
                dataCount.put(srcIPv6, dataCount.get(srcIPv6) + size);
            }

            if (doSNI.get()) {
                ArrayList<String> snis = sniRecords.get(srcIPv6);
                if (!snis.isEmpty()) {
                    String sni = snis.get(0);
                    if (sniDataCount.get(sni) == null) {
                        sniDataCount.put(sni, (long) size);
                    } else {
                        sniDataCount.put(sni, sniDataCount.get(sni) + size);
                    }
                }
            }
        }

        if (isLocalIPv4(destIPv6)) {
            // destination is local machine
            // Source is local machine
            if (localTalkers.get(destIPv6) == null) {
                localTalkers.put(destIPv6, 1);
            } else {
                localTalkers.put(destIPv6, localTalkers.get(destIPv6) + 1);
            }

            if (localTalkersData.get(destIPv6) == null) {
                localTalkersData.put(destIPv6, (long) size);
            } else {
                localTalkersData.put(destIPv6, localTalkersData.get(destIPv6) + size);
            }

            if (localTrafficStats) {
                // Count local networking data with localTalkersData flag set.
                if (dataCount.get(destIPv6) == null) {
                    dataCount.put(destIPv6, (long) size);
                } else {
                    dataCount.put(destIPv6, dataCount.get(destIPv6) + size);
                }
            }
        } else {
            // destination is internet node
            // Count data
            if (dataCount.get(destIPv6) == null) {
                dataCount.put(destIPv6, (long) size);
            } else {
                dataCount.put(destIPv6, dataCount.get(destIPv6) + size);
            }

            if (doSNI.get()) {
                ArrayList<String> snis = sniRecords.get(destIPv6);
                if (snis.size() > 0) {
                    String sni = snis.get(0);
                    if (sniDataCount.get(sni) == null) {
                        sniDataCount.put(sni, (long) size);
                    } else {
                        sniDataCount.put(sni, sniDataCount.get(sni) + size);
                    }
                }
            }
        }

        // Register the MAC address
        // ASSUMPTION: An IP address will only associate with one MAC address.
        addressResolution.putIfAbsent(srcIPv6, srcMAC);
        addressResolution.putIfAbsent(destIPv6, dstMAC);
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
        return String.format("%s:%s:%s:%s:%s:%s", a, b, c, d, e, f);
    }

    /**
     * Our insecure trust manager. Trust everything.
     */
    private static class SniTrustManager implements X509TrustManager {

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

    /**
     * Local top speakers.
     *
     * @return [Top packet speaker IP; MAC; Packet counts; Top data speak IP; MAC; Packet counts.]
     */
    public ArrayList<String> getLocalTopSpeaker() {
        ArrayList<String> topSpeakers = new ArrayList<>();
        localTalkers.entrySet().stream().max(Comparator.comparingInt(HashMap.Entry::getValue));
        var topPacket = localTalkers.entrySet().stream().max(Comparator.comparingInt(HashMap.Entry::getValue)).get();
        var topData = localTalkersData.entrySet().stream().max(Comparator.comparingLong(HashMap.Entry::getValue)).get();
        topSpeakers.add(topPacket.getKey());
        topSpeakers.add(addressResolution.get(topPacket.getKey()));
        topSpeakers.add(topPacket.getValue().toString());
        topSpeakers.add(topData.getKey());
        topSpeakers.add(addressResolution.get(topData.getKey()));
        topSpeakers.add(topData.getValue().toString());

        return topSpeakers;
    }

    /**
     * Get top 10 destinations information
     *
     * @return [[Top 10 dest ips] : [Top 10 dest data] : [Top 10 dest SNIs] : [Top10 dest rDNS]]
     */
    public ArrayList<ArrayList<String>> getTopDest() {
        ArrayList<String> topDest = new ArrayList<>();
        ArrayList<String> topData = new ArrayList<>();
        ArrayList<String> topSNI = new ArrayList<>();
        ArrayList<String> topRDNS = new ArrayList<>();
        ArrayList<ArrayList<String>> resp = new ArrayList<>();

        ArrayList<Long> traffic = new ArrayList<>();
        for (Long data : dataCount.values()) {
            traffic.add(data);
        }
        // sort data in descending order
        traffic.sort(Comparator.reverseOrder());

        // get top 10 / most ips
        int topsize = 10;
        if (dataCount.size() < 10) {
            topsize = dataCount.size();
        }
        for (int i = 0; i < topsize; i++) {
            var data = traffic.get(i);
            int dataUnitTracker = 0; // 0: bytes, 1: KB, 2: MB, 3: GB
            double kb = (double) data; // convert and store to double for accurate division
            while (kb >= 1024 && dataUnitTracker < 3) {
                kb /= 1024; // convert to KB
                dataUnitTracker++;
            }
            kb = Math.round(kb * 100.0) / 100.0; // round to 2 decimal places
            var dataUnit = "bytes"; // default unit
            switch (dataUnitTracker) {
                case 1 -> {
                    dataUnit = "KB";
                }
                case 2 -> {
                    dataUnit = "MB";
                }
                case 3 -> {
                    dataUnit = "GB";
                }
                default -> {
                    dataUnit = "bytes";
                }
            }
            for (String ip : dataCount.keySet()) {
                if (Objects.equals(dataCount.get(ip), data)) {
                    topDest.add(ip);
                    topData.add(kb + " " + dataUnit);
                    if (dorDNS.get()) {
                        topRDNS.add(rDNSRecords.get(ip));
                    }
                    if (doSNI.get()) {
                        ArrayList snis = sniRecords.get(ip);
                        if (snis.size() > 0) {
                            topSNI.add(snis.get(0).toString());
                        } else {
                            // Faild to do sni. Empty Arraylist.
                            topSNI.add("Unknown");
                        }
                    }
                }
            }
        }
        System.out.println("top data: " + topData);
        resp.add(topDest);
        resp.add(topData);
        resp.add(topSNI);
        resp.add(topRDNS);
        return resp;
    }

    /**
     * Get top 10 SNI ranking of the pcap file.
     *
     * @return ["SNI NAME: Data (bytes)"]
     */
    public ArrayList<String> getSNIRanking() {
        ArrayList<String> topSNI = new ArrayList<>();
        ArrayList<Long> traffic = new ArrayList<>();
        for (Long data : sniDataCount.values()) {
            traffic.add(data);
        }
        // sort data in descending order
        traffic.sort(Comparator.reverseOrder());

        // get top 10 / most contained snis
        int topsize = 10;
        if (sniDataCount.size() < 10) {
            topsize = sniDataCount.size();
        }
        for (int i = 0; i < topsize; i++) {
            var data = traffic.get(i);
            for (String sni : sniDataCount.keySet()) {
                if (sniDataCount.get(sni) == data) {
                    topSNI.add(sni + ": " + data + " (bytes)");
                }
            }
        }
        return topSNI;
    }

    public Integer getIpv4Counts() {
        return ipv4Counts.get();
    }

    public Integer getIpv6Counts() {
        return ipv6Counts.get();
    }

    public void setDorDNS(Boolean dorDNS) {
        this.dorDNS = new AtomicBoolean(dorDNS);
    }

    public void setDoSNI(Boolean doSNI) {
        this.doSNI = new AtomicBoolean(doSNI);
    }
}