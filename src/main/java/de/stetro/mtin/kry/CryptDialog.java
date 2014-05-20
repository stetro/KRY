package de.stetro.mtin.kry;

import de.stetro.mtin.kry.util.AESFileSecurity;
import de.stetro.mtin.kry.util.AESFileSecurityImpl;

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;


public class CryptDialog {
    private JTextField browseTextField;
    private JButton browseButton;
    private JPanel formPanel;
    private JLabel applicationStatus;
    private JButton openFileButton;
    private JTextArea textArea;
    private JTextField passwordTextField;
    private JButton decryptButton;
    private JButton encryptButton;
    private JComboBox comboBox1;
    private AESFileSecurity aesFileSecurity = new AESFileSecurityImpl();

    public CryptDialog() {
        prepareJFrame();
        browseButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {
                browseFile();
            }
        });
        openFileButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {
                readFileToTextArea();
            }
        });
        decryptButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                decrypt();
            }
        });
        encryptButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                encrypt();
            }
        });
    }

    private void encrypt() {
        try {
            char[] password = passwordTextField.getText().toCharArray();
            String mode = comboBox1.getSelectedItem().toString();
            String fileName = browseTextField.getText();
            FileInputStream file = new FileInputStream(new File(fileName));
            long before = System.currentTimeMillis();
            aesFileSecurity.encrypt(password, mode, file, fileName + ".enc");
            long after = System.currentTimeMillis();
            applicationStatus.setText("Encrypt file successfully - " + (after - before) + "ms");
        } catch (Exception e1) {
            applicationStatus.setText("Error en crypting file ...");
        }
    }

    private void decrypt() {
        try {
            char[] password = passwordTextField.getText().toCharArray();
            String mode = comboBox1.getSelectedItem().toString();
            String fileName = browseTextField.getText();
            FileInputStream file = new FileInputStream(new File(fileName));
            long before = System.currentTimeMillis();
            aesFileSecurity.decrypt(password, mode, file, fileName + ".dec");
            long after = System.currentTimeMillis();
            applicationStatus.setText("Decrypt file successfully - " + (after - before) + "ms");
        } catch (Exception e1) {
            applicationStatus.setText("Error decrypting file ...");
        }
    }

    private void readFileToTextArea() {
        byte[] encoded;
        try {
            encoded = Files.readAllBytes(Paths.get(browseTextField.getText()));
            textArea.setText(new String(encoded, StandardCharsets.UTF_8));
            applicationStatus.setText("Red file successfully");
        } catch (IOException e) {
            applicationStatus.setText("Error reading File ...");
        }
    }

    private void browseFile() {
        JFileChooser fc;
        fc = new JFileChooser();
        fc.setCurrentDirectory(new File("."));
        int returnVal = fc.showOpenDialog(formPanel);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            browseTextField.setText(file.getAbsolutePath());
        } else {
            applicationStatus.setText("Error selecting xml file.");
        }
    }

    private void prepareJFrame() {
        JFrame frame = new JFrame("MainWindow");
        frame.setContentPane(formPanel);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.pack();
        frame.setSize(600, 500);
        frame.setVisible(true);
    }
}
