package com.packetboard.packetboard;

import javafx.fxml.FXML;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class HomeController {
    private Boolean doSNI;
    private Boolean dorDNS;
    private Stage appStage;
    @FXML
    private VBox graphsBox = new VBox();

    public void setSNI(Boolean doSNI) {
        this.doSNI = doSNI;
    }

    public void setrDNS(Boolean dorDNS) {
        this.dorDNS = dorDNS;
    }

    public void setStage(Stage stage) {
        appStage = stage;
    }
}
