package com.packetboard.packetboard;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.CheckBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;

public class HelloController {
    PacketParser parser = new PacketParser();
    private Stage appStage;
    @FXML
    private CheckBox sniBox, rdnsBox = new CheckBox();
    private Boolean doSNI, dorDNS;

    @FXML
    protected void onImportBtnClick() {
        FileChooser pcapChooser = new FileChooser();
        pcapChooser.setTitle("Open pcap file");
        pcapChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PCAP files", "*.pcap"));
        Stage pcapChooserStage = new Stage();
        File pcapFile = pcapChooser.showOpenDialog(pcapChooserStage);

        if (pcapFile != null) {
            doSNI = sniBox.isSelected();
            dorDNS = rdnsBox.isSelected();
            parser.load(pcapFile.getPath(), doSNI, dorDNS);

            try {
                loadHome();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    public void setStage(Stage stage) {
        appStage = stage;
    }

    public void loadHome() throws IOException {
        FXMLLoader homeLoader = new FXMLLoader(HelloController.class.getResource("home-view.fxml"));
        Scene homeScene = new Scene(homeLoader.load());
        HomeController homeController = homeLoader.getController();
        homeController.setrDNS(dorDNS);
        homeController.setSNI(doSNI);
        homeController.setStage(appStage);
        homeController.setParser(parser);
        appStage.setScene(homeScene);
    }
}