/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptchat;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/**
 *
 * @author Milos
 */
public class ChatClient extends javax.swing.JFrame {

    static int serverPort;
    static String serverAdress;
    DataInputStream in = null;
    DataOutputStream out = null;
    String clientName;
    boolean stop = true; // Used in ending KSocket
    Socket client = null;
    List<ChatLog> logs; // List of chat logs with other users
    List<String[]> keys; // Public keys of other users
    static AsymmetricC asymmetric;
    static SymmetricC symmetric;

    public ChatClient() {
        initComponents();
        this.setTitle("CryptChat");
        logs = new ArrayList<>();
        keys = new ArrayList<>();
        
        this.setLocationRelativeTo(null);
        
        // Disable parts of jFrame
        this.enables(false);
    }

    class KSocket implements Runnable {

        int port;
        JTextArea jta; // Za primanje poruka
        JTextField jtf; // Za slanje poruka
        String serverName;

        public KSocket(String serverName, int port, JTextArea jta, JTextField jtf) {
            this.serverName = serverName;
            this.port = port;
            this.jta = jta;
            this.jtf = jtf;
            asymmetric = new AsymmetricC();
            asymmetric.createNewKeys();
        }

        @Override
        public void run() {
            try {
                jta.setText("Connecting to " + serverName + " on port " + port + "\n");
                try {
                    client = new Socket(serverName, port);
                } catch (Exception e) {
                    connectionNotif_L.setText("Failed to connect to server");
                    jta.append("Connection failed\nError message:\n" + e.toString());
                }

                in = new DataInputStream(client.getInputStream());
                out = new DataOutputStream(client.getOutputStream());
                Runtime.getRuntime().addShutdownHook(new Disconnect());

                // Send public key to server / Server PRVO prihvata public key 
                out.writeUTF(asymmetric.getPublicKeyHex());

                // Recieve session key for client server communication / Server DRUGO salje symmetric key
                symmetric = new SymmetricC(asymmetric.decryptRSA(in.readUTF()));
                System.out.println("Symmetric key: " + symmetric.getKeyHex());

                // Send client display name / Server TRECE prihvata ime klijenta pa saljemo
                out.writeUTF(clientName);

                // Receive confirmation the name isn't taken and terminate runnible in case it isn't / Server CETVRTO potvrdjuje da li je ime slobodno i salje info
                boolean available = Boolean.parseBoolean(in.readUTF());
                if (!available) {
                    stop = true;
                    in.close();
                    out.close();
                    client.close();
                    connectionNotif_L.setText("Display name is taken. Try another.");
                    jta.append("Connection failed: Display name " + clientName + " is already taken.\n");
                } else {
                    jta.append("Connection established: " + client.getRemoteSocketAddress() + "\n");
                    // Send a request for user list
                    out.writeUTF(symmetric.encryptMessage("-rl#"));

                    // Enable jFrame elements
                    enables(true);
                }
                while (!stop) {
                    String receivedCipher = in.readUTF();
                    // Decrypt with server session key
                    String received = symmetric.decryptMessage(receivedCipher);

                    // Tokeinze the recived string based on protocol. String example: -m#
                    StringTokenizer st = new StringTokenizer(received, "#");
                    String type = st.nextToken();
                    boolean found;
                    switch (type) {
                        // -m Message
                        case "-m":
                            // Received looks like: -m#sender#message
                            String sender = st.nextToken();
                            String messageCipher = st.nextToken();

                            // Decryption and verification
                            String senderPKey = ""; // We search for the senders public key for verification
                            boolean senderExists = false;
                            for (String[] profile : keys) { // Go through all the keys
                                if (profile[0].equals(sender)) {
                                    senderPKey = profile[1];
                                    senderExists = true;
                                    break;
                                }
                            }
                            if (!senderExists) // If we can't find the sender's name among our list of users, we break
                            {
                                break;
                            }

                            String[] MessageVerify = asymmetric.decryptMessage(messageCipher, senderPKey);
                            String message = MessageVerify[0];
                            boolean verified = Boolean.parseBoolean(MessageVerify[1]);

                            found = false;
                            // We look for the log of the sender and add the new message / Provjerava da li imamo korisnika u listi aktivnih partnera "logs" i appendamo njegovu poruku
                            for (ChatLog log : logs) {
                                if (log.getName().equals(sender)) {
                                    found = true;
                                    if (verified) {
                                        log.append(sender + ": " + message);
                                    } else {
                                        log.append("----------------------\nERROR: Signature cannot be verified.\nMessage from " + sender + " decrypts to: " + message);
                                    }
                                    if (userList_L.getSelectedValue() != null) {
                                        if (userList_L.getSelectedValue().equals(log.getName())) {
                                            inbox_TA.setText(log.getLog());
                                        }
                                    }
                                }
                            }
                            if (!found) {
                                // If there is no previous log, a new one is created
                                ChatLog cl = new ChatLog(sender);
                                cl.append(sender + ": " + message);
                                if (userList_L.getSelectedValue() != null) {
                                    if (userList_L.getSelectedValue().equals(sender)) {
                                        inbox_TA.setText(cl.getLog());
                                    }
                                }
                                logs.add(cl);
                            }
                            break;

                        // -rl Refresh list
                        case "-rl":
                            int listSize = Integer.parseInt(st.nextToken());
                            String[] userListArray;
                            if (listSize != 0) {
                                userListArray = new String[listSize];
                            } else {
                                userListArray = new String[listSize + 1];
                            }
                            String nextUser;
                            // Adding public keys of other users to list / Dodajemo javne kljuceve u listu
                            String nextKey;
                            for (int i = 0; i < userListArray.length; i++) {
                                nextUser = st.nextToken();
                                userListArray[i] = nextUser;
                                if (listSize != 0) {
                                    nextKey = st.nextToken();

                                    found = false;

                                    for (String[] profile : keys) {
                                        if (profile[0].equals(nextUser)) {
                                            found = true;
                                        }
                                    }
                                    if (!found) {
                                        String[] keyProfile = new String[2];
                                        keyProfile[0] = nextUser;
                                        keyProfile[1] = nextKey;
                                        keys.add(keyProfile);
                                    }
                                }
                            }
                            userList_L.setListData(userListArray);

                            break;
                        case "-ul":
                            out.writeUTF(symmetric.encryptMessage("-rl#"));
                            break;
                    }
                }
            } catch (IOException ex) {
                Logger.getLogger(ChatClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        inbox_TA = new javax.swing.JTextArea();
        send_TF = new javax.swing.JTextField();
        send_B = new javax.swing.JButton();
        connect_B = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        userList_L = new javax.swing.JList<>();
        jLabel3 = new javax.swing.JLabel();
        refreshUserList_B = new javax.swing.JButton();
        notifications_LB = new javax.swing.JLabel();
        disconnect_B = new javax.swing.JButton();
        connectionNotif_L = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setResizable(false);

        inbox_TA.setEditable(false);
        inbox_TA.setColumns(20);
        inbox_TA.setRows(5);
        jScrollPane1.setViewportView(inbox_TA);

        send_B.setText("Send");
        send_B.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                send_BActionPerformed(evt);
            }
        });

        connect_B.setText("Connect to Server");
        connect_B.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connect_BActionPerformed(evt);
            }
        });

        userList_L.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                userList_LValueChanged(evt);
            }
        });
        jScrollPane2.setViewportView(userList_L);

        jLabel3.setText("Current users:");

        refreshUserList_B.setText("Refresh");
        refreshUserList_B.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshUserList_BActionPerformed(evt);
            }
        });

        notifications_LB.setForeground(new java.awt.Color(255, 51, 0));

        disconnect_B.setText("Disconnect");
        disconnect_B.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disconnect_BActionPerformed(evt);
            }
        });

        connectionNotif_L.setForeground(new java.awt.Color(255, 51, 51));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 543, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(connect_B, javax.swing.GroupLayout.PREFERRED_SIZE, 133, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(connectionNotif_L, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 6, Short.MAX_VALUE)
                                .addComponent(refreshUserList_B))
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(disconnect_B)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(notifications_LB, javax.swing.GroupLayout.PREFERRED_SIZE, 613, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(send_TF, javax.swing.GroupLayout.PREFERRED_SIZE, 543, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(send_B)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(connect_B)
                        .addComponent(jLabel3)
                        .addComponent(refreshUserList_B))
                    .addComponent(connectionNotif_L, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 283, Short.MAX_VALUE)
                    .addComponent(jScrollPane2))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(send_TF, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(send_B))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(disconnect_B)
                    .addComponent(notifications_LB, javax.swing.GroupLayout.PREFERRED_SIZE, 16, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void send_BActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_send_BActionPerformed
        String recipient = userList_L.getSelectedValue();
        String message = send_TF.getText();
        if (recipient != null && !message.equals("")) {
            String messageCipher;
            try {
                for (String[] profile : keys) {
                    if (profile[0].equals(recipient)) {
                        messageCipher = asymmetric.encryptMessage(message, profile[1]);
                        String send = "-m#" + recipient + "#" + messageCipher;
                        this.out.writeUTF(symmetric.encryptMessage(send));//m for message
                    }
                }

                this.send_TF.setText("");
                System.out.println("Message sent to " + recipient);
            } catch (IOException ex) {
                Logger.getLogger(ChatClient.class.getName()).log(Level.SEVERE, null, ex);
            }

            boolean found = false;
            for (ChatLog log : this.logs) {
                if (log.getName().equals(recipient)) {
                    found = true;
                    log.append(clientName + ": " + message);
                    if (userList_L.getSelectedValue().equals(log.getName())) {
                        inbox_TA.setText(log.getLog());
                    }
                }
            }
            if (!found) {
                ChatLog cl = new ChatLog(recipient);
                cl.append(clientName + ": " + message);
                if (userList_L.getSelectedValue().equals(cl.getName())) {
                    inbox_TA.setText(cl.getLog());
                }
                this.logs.add(cl);
            }
        }
    }//GEN-LAST:event_send_BActionPerformed

    private void connect_BActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connect_BActionPerformed
        ClientConnect cc = new ClientConnect(this, true);
        cc.setVisible(true);
        this.resetNotifs();

        if (cc.connectPressed) {
            this.serverAdress = cc.serverAdress;
            this.serverPort = cc.port;
            this.clientName = cc.displayName;
            Thread connection = new Thread(new KSocket(serverAdress, serverPort, inbox_TA, send_TF));
            this.stop = false;
            connection.start();
            System.out.println("Connection establsihed with server");
        }
    }//GEN-LAST:event_connect_BActionPerformed

    private void refreshUserList_BActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshUserList_BActionPerformed
        try {
            out.writeUTF(symmetric.encryptMessage("-rl#"));
            System.out.println("User list refreshed");
        } catch (IOException ex) {
            Logger.getLogger(ChatClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_refreshUserList_BActionPerformed

    private void disconnect_BActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disconnect_BActionPerformed
        try {
            out.writeUTF(symmetric.encryptMessage("-dc#"));
            this.stop = true;
            in.close();
            out.close();
            client.close();
            this.resetNotifs();
            this.inbox_TA.setText("");
            this.notifications_LB.setText("Disconnected!");
            System.out.println("Disconnected from server");

            this.enables(false);
        } catch (IOException ex) {
            Logger.getLogger(ChatClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_disconnect_BActionPerformed

    private void userList_LValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_userList_LValueChanged
        if (userList_L.getSelectedValue() != null) {
            boolean found = false;
            if (userList_L.getSelectedValue().equals("-No active users-")) {
                found = true;
            }
            for (ChatLog log : this.logs) {
                if (log.getName().equals(userList_L.getSelectedValue())) {
                    found = true;
                    inbox_TA.setText(log.getLog());
                    break;
                }
            }
            if (!found) {
                inbox_TA.setText("No active chat with " + userList_L.getSelectedValue());
            }
        } else {
            inbox_TA.setText(":|");
        }
    }//GEN-LAST:event_userList_LValueChanged

    public void enables(boolean enable) {
        refreshUserList_B.setEnabled(enable);
        send_B.setEnabled(enable);
        send_TF.setEnabled(enable);
        disconnect_B.setEnabled(enable);
        userList_L.setEnabled(enable);
        inbox_TA.setEditable(enable);
        connect_B.setEnabled(!enable);
    }

    public void resetNotifs() {
        this.notifications_LB.setText("");
        this.connectionNotif_L.setText("");
    }

    class Disconnect extends Thread {

        public void run() {
            try {
                out.writeUTF(symmetric.encryptMessage("-dc#"));
                stop = true;
                in.close();
                out.close();
                client.close();
                setVisible(false);
                dispose();
                
            } catch (IOException ex) {
                Logger.getLogger(ChatClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ChatClient.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ChatClient.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ChatClient.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ChatClient.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                
                new ChatClient().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton connect_B;
    private javax.swing.JLabel connectionNotif_L;
    private javax.swing.JButton disconnect_B;
    private javax.swing.JTextArea inbox_TA;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JLabel notifications_LB;
    private javax.swing.JButton refreshUserList_B;
    private javax.swing.JButton send_B;
    private javax.swing.JTextField send_TF;
    private javax.swing.JList<String> userList_L;
    // End of variables declaration//GEN-END:variables
}
