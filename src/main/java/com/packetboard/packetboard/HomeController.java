package com.packetboard.packetboard;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.chart.PieChart;
import javafx.scene.control.Accordion;
import javafx.scene.control.Label;
import javafx.scene.control.TitledPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;

public class HomeController {
    private Boolean doSNI;
    private Boolean dorDNS;
    private Stage appStage;
    private PacketParser parser = new PacketParser();
    @FXML
    private VBox graphsBox, topDestBox, IPProtocolBox;
    @FXML
    private Label packetTopMAC, packetTopIP, packetTopPacket, dataTopIP, dataTopMAC, dataTopData;
    @FXML
    private Accordion homeAccordion;

    public void setSNI(Boolean doSNI) {
        this.doSNI = doSNI;
    }

    public void setrDNS(Boolean dorDNS) {
        this.dorDNS = dorDNS;
    }

    public void setStage(Stage stage) {
        appStage = stage;
    }

    private void loadDatatoScene() {
        // Local top speakers
        var a = parser.getLocalTopSpeaker();
        packetTopIP.setText(a.get(0));
        packetTopMAC.setText(" (" + a.get(1) + " ) ");
        packetTopPacket.setText(a.get(2) + " packets");
        dataTopIP.setText(a.get(3));
        dataTopMAC.setText(" (" + a.get(4) + " ) ");
        dataTopData.setText(a.get(5) + " bytes");

        // most visited destinations
        var destData = parser.getTopDest();
        var topDest = destData.get(0);
        var topData = destData.get(1);
        var topSNI = destData.get(2);
        var toprDNS = destData.get(3);

        for (int i = 0; i < topDest.size(); i++) {
            HBox thisDst = new HBox();
            Label destLabel = new Label((i + 1) + ": " + topDest.get(i) + " ");
            thisDst.getChildren().add(destLabel);
            Label dataLabel = new Label(" " + topData.get(i));
            thisDst.getChildren().add(dataLabel);
            if (doSNI) {
                Label sniLabel = new Label("Domain Name: " + topSNI.get(i));
                thisDst.getChildren().add(sniLabel);
            }
            if (dorDNS) {
                Label rdnsLabel = new Label(" rDNS: " + toprDNS.get(i));
                thisDst.getChildren().add(rdnsLabel);
            }
            topDestBox.getChildren().add(thisDst);
        }

        // IP Analysis graph
        double totalPackets = parser.getIpv4Counts() + parser.getIpv6Counts();

        ObservableList<PieChart.Data> ipPieData = FXCollections.observableArrayList(
                new PieChart.Data("IPv4 packets " + (parser.getIpv4Counts() / totalPackets * 100) + "%", parser.getIpv4Counts()),
                new PieChart.Data("IPv6 packets " + (parser.getIpv6Counts() / totalPackets * 100) + "%", parser.getIpv6Counts())
        );
        PieChart ipPieChart = new PieChart(ipPieData);
        IPProtocolBox.getChildren().add(ipPieChart);

        if (doSNI) {        // SNIs with most data
            TitledPane sniPane = new TitledPane();
            VBox sniRanking = new VBox();
            sniPane.setContent(sniRanking);
            sniPane.setText("Top destinations by domain name");
            var sniData = parser.getSNIRanking();
            for (String record : sniData) {
                Label sniLabel = new Label(record);
                sniRanking.getChildren().add(sniLabel);

            }
            homeAccordion.getPanes().add(sniPane);
        }

    }

    public void setParser(PacketParser parser) {
        this.parser = parser;
        loadDatatoScene();
    }

    @FXML
    public void openNewFile() {
        FileChooser pcapChooser = new FileChooser();
        pcapChooser.setTitle("Open pcap file");
        pcapChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PCAP files", "*.pcap"));
        Stage pcapChooserStage = new Stage();
        File pcapFile = pcapChooser.showOpenDialog(pcapChooserStage);

        if (pcapFile != null) {
            parser.load(pcapFile.getPath(), doSNI, dorDNS);
        }
    }
}
