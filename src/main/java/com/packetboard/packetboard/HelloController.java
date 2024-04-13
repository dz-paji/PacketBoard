package com.packetboard.packetboard;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;

public class HelloController {
    PacketParser parser = new PacketParser();
    private Stage appStage;

    @FXML
    protected void onImportBtnClick() {
        FileChooser pcapChooser = new FileChooser();
        pcapChooser.setTitle("Open pcap file");
        pcapChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PCAP files", "*.pcap"));
        Stage pcapChooserStage = new Stage();
        File pcapFile = pcapChooser.showOpenDialog(pcapChooserStage);

        if (pcapFile != null) {
            parser.load(pcapFile.getPath());
        }

    }

    public void setStage(Stage stage) {
        appStage = stage;
    }

    public void loadHome() throws IOException {
        FXMLLoader homeLoader = new FXMLLoader(HelloController.class.getResource("home-view.fxml"));
        Scene homeScene = new Scene(homeLoader.load());
        appStage.setScene(homeScene);
    }
}