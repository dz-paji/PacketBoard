package com.packetboard.packetboard;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class HelloApplication extends Application {
    private Stage appStage;

    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("hello-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load());

        // Save the stage
        appStage = stage;
        stage.setTitle("PacketBoard");
        stage.setScene(scene);
        stage.show();

        // Pass control to the controller
        HelloController helloCtler = fxmlLoader.getController();
        helloCtler.setStage(stage);
    }

    public void loadHome() throws IOException {
        FXMLLoader homeLoader = new FXMLLoader(HelloApplication.class.getResource("home-view.fxml"));
        Scene homeScene = new Scene(homeLoader.load());
        appStage.setScene(homeScene);
    }

    public static void main(String[] args) {
        launch();
    }
}