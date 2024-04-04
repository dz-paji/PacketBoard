module com.packetboard.packetboard {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.web;

    requires org.kordamp.ikonli.javafx;
    requires org.kordamp.bootstrapfx.core;
    requires kaitai.struct.runtime;

    opens com.packetboard.packetboard to javafx.fxml;
    exports com.packetboard.packetboard;
    exports com.packetboard.packetboard.Parser;
    opens com.packetboard.packetboard.Parser to javafx.fxml;
}