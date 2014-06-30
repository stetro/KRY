package de.stetro.mtin.kry;

import de.stetro.mtin.kry.util.AESFileSecurity;
import de.stetro.mtin.kry.util.AESFileSecurityImpl;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;


public class CryptDialog {
    private JTextField browseTextField;
    private JButton browseButton;
    private JPanel formPanel;
    private JLabel applicationStatus;

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

        String[] strings = {"CBC", "CFB16", "OFB16", "CTR"};
        comboBox1.setModel(new DefaultComboBoxModel(strings));
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
        frame.setSize(600, 150);
        frame.setVisible(true);
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        formPanel = new JPanel();
        formPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(4, 3, new Insets(5, 5, 5, 5), -1, -1));
        formPanel.setMaximumSize(new Dimension(600, 2147483647));
        browseButton = new JButton();
        browseButton.setText("Browse ...");
        formPanel.add(browseButton, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        browseTextField = new JTextField();
        formPanel.add(browseTextField, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Path:");
        formPanel.add(label1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        applicationStatus = new JLabel();
        applicationStatus.setText("");
        formPanel.add(applicationStatus, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        passwordTextField = new JTextField();
        formPanel.add(passwordTextField, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Password:");
        formPanel.add(label2, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        decryptButton = new JButton();
        decryptButton.setText("Decrypt");
        formPanel.add(decryptButton, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        encryptButton = new JButton();
        encryptButton.setText("Encrypt");
        formPanel.add(encryptButton, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        comboBox1 = new JComboBox();
        formPanel.add(comboBox1, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Mode:");
        formPanel.add(label3, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return formPanel;
    }
}