/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networkProtocolAnalyzer;

import java.io.File;
import java.util.ArrayList;
import javax.swing.JOptionPane;
import javax.swing.table.DefaultTableModel;
import static networkProtocolAnalyzer.StartPanel.errbuf;
import java.util.Date;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 *
 * @author n0krashy
 */
public class MainPanel extends javax.swing.JPanel {

    int i;
    Pcap livePcap;
    Pcap offlinePcap;
    ArrayList<PcapPacket> packets;
    ArrayList<PcapPacket> filteredPackets;
    PcapPacketHandler<String> jpacketHandler;
    DefaultTableModel dtm;
    PcapDumper dumper;
    Tcp tcp;
    Udp udp;
    Ip4 ip4;
    Ip6 ip6;
    Http http;
    Ethernet ethernet;
    Arp arp;
    Icmp icmp;
    byte[] sIP;
    byte[] dIP;
    String sourceIP;
    String destIP;
    String protocol;
    FileFilter fileTypeFilter;
    String tempFile;
    File file;
    String captureFilter;

    public MainPanel() {
        packets = new ArrayList<>();
        filteredPackets = new ArrayList<>();
        captureFilter = "";
        fileTypeFilter = new FileNameExtensionFilter("pcap", "pcap");
        http = new Http();
        tcp = new Tcp();
        udp = new Udp();
        ip4 = new Ip4();
        ip6 = new Ip6();
        ethernet = new Ethernet();
        arp = new Arp();
        icmp = new Icmp();
        sIP = new byte[4];
        dIP = new byte[4];
        tempFile = "tmp-capture-file.pcap";
        initComponents();
        saveFileBox.setFileFilter(fileTypeFilter);
        loadFileBox.setFileFilter(fileTypeFilter);
        dtm = (DefaultTableModel) packetsTable.getModel();
    }

    private void getPacketInformation(PcapPacket packet) {
        protocol = "";
        // get source & destination MAC addresses
        if (packet.hasHeader(ethernet)) {
            sIP = packet.getHeader(ethernet).source();
            dIP = packet.getHeader(ethernet).destination();
        }

        // get Source & destination IP addresses
        if (packet.hasHeader(ip4) || (packet.hasHeader(ip4) && packet.hasHeader(icmp))) {
            sIP = packet.getHeader(ip4).source();
            dIP = packet.getHeader(ip4).destination();
        } else if (packet.hasHeader(ip6) || (packet.hasHeader(ip6) && packet.hasHeader(icmp))) {
            sIP = packet.getHeader(ip6).source();
            dIP = packet.getHeader(ip6).destination();
        }

        if (packet.hasHeader(arp)) {
            protocol = "ARP";
        } else if (packet.hasHeader(icmp)) {
            protocol = "ICMP";
        } else if (packet.hasHeader(tcp)) {
            protocol = "TCP";
        } else if (packet.hasHeader(udp)) {
            protocol = "UDP";
        }

        if (packet.hasHeader(http)) {
            protocol = "HTTP";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 23) || (packet.hasHeader(udp) && udp.source() == 23)) {
            protocol = "Telnet";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 21) || (packet.hasHeader(udp) && udp.source() == 21) || (packet.hasHeader(tcp) && tcp.source() == 20) || (packet.hasHeader(udp) && udp.source() == 20)) {
            protocol = "FTP";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 7) || (packet.hasHeader(udp) && udp.source() == 7)) {
            protocol = "ECHO";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 33) || (packet.hasHeader(udp) && udp.source() == 33)) {
            protocol = "DSP";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 53) || (packet.hasHeader(udp) && udp.source() == 53)) {
            protocol = "DNS";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 5355) || (packet.hasHeader(udp) && udp.source() == 5355)) {
            protocol = "LLMNR";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 1900) || (packet.hasHeader(udp) && udp.source() == 1900)) {
            protocol = "SSDP";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 465) || (packet.hasHeader(udp) && udp.source() == 465)) {
            protocol = "IGMPv3";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 546) || (packet.hasHeader(udp) && udp.source() == 546) || (packet.hasHeader(tcp) && tcp.source() == 547) || (packet.hasHeader(udp) && udp.source() == 547)) {
            protocol = "DHCP";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 25) || (packet.hasHeader(udp) && udp.source() == 25)) {
            protocol = "SMTP";
        } else if ((packet.hasHeader(tcp) && tcp.source() == 22) || (packet.hasHeader(udp) && udp.source() == 22)) {
            protocol = "SSH";
        }
        
        //set source & dest IP equal to MAC address
        sourceIP = org.jnetpcap.packet.format.FormatUtils.mac(sIP);
        destIP = org.jnetpcap.packet.format.FormatUtils.mac(dIP);
        
        //if protocol is ip4 or ip6 or imcp it will have IP address so set source & dest. equal to
        if (packet.hasHeader(ip4) || packet.hasHeader(ip6) || packet.hasHeader(icmp)) {
            sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
            destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
        }
    }

    private void getPackets() {
        jpacketHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                getPacketInformation(packet);
                if (protocol != "") {
                    // add GUI row in packets table
                    packets.add(packet);
                    filteredPackets.add(packet);
                    tableFilter(captureFilter, packet);
                }
                dumper.dump(packet);
            }

        };
    }

    private void startDevice() {
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        livePcap = Pcap.openLive(StartPanel.device.getName(), snaplen, flags, timeout, StartPanel.errbuf);
        dumper = livePcap.dumpOpen(tempFile);
        file = new File(tempFile);

        if (livePcap == null) {
            JOptionPane.showMessageDialog(null,
                    "Error while opening device for capture: " + errbuf.toString(),
                    "Device opening Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
    }

    private void save(String filePath) {
        dumper.close(); // Won't be able to delete without explicit close
        livePcap.close();
        file.renameTo(new File(filePath));
        saveButton.setEnabled(false);
    }

    private void load(String fileName) {
        final StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        offlinePcap = Pcap.openOffline(fileName, errbuf);
        if (offlinePcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
        reset(true);
        getPackets();
        offlinePcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
        offlinePcap.close();
    }

    private void reset(boolean clearPackets) {
        dtm.setRowCount(0);
        packetBytesTextArea.setText("");
        packetDetailsTextArea.setText("");
        i = 1;
        filteredPackets.clear();
        if (clearPackets) {
            packets.clear();
        }
    }

    private void deviceController(boolean startCapture) {
        if (startCapture == true) {
            reset(true);
            startDevice();
            getPackets();
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    livePcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
                }
            });
            t.start();
            startStopButton.setText("Stop");
            loadButton.setEnabled(false);
            saveButton.setEnabled(false);
        } else {
            saveButton.setEnabled(true);
            loadButton.setEnabled(true);
            livePcap.breakloop();
            startStopButton.setText("Start");
        }
    }

    public void tableFilter(String filter, PcapPacket packet) {
        if (filter.equals("")) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("arp") && packet.hasHeader(arp)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("tcp") && packet.hasHeader(tcp)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("udp") && packet.hasHeader(udp)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("icmp") && packet.hasHeader(icmp)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("ip4") && packet.hasHeader(ip4)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("ip6") && packet.hasHeader(ip6)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("ethernet") && packet.hasHeader(ethernet)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        } else if (filter.equalsIgnoreCase("HTTP") && packet.hasHeader(http)) {
            dtm.addRow(new Object[]{i, new Date(packet.getCaptureHeader().timestampInMillis()), sourceIP, destIP, protocol, packet.getCaptureHeader().caplen()});
            filteredPackets.add(packet);
        }
        i++;
    }

    private void filterPackets(String filter) {
        reset(false);
        for (PcapPacket packet : packets) {
            getPacketInformation(packet);
            tableFilter(filter, packet);
        }
        captureFilter = filter;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        loadFileBox = new javax.swing.JFileChooser();
        saveFileBox = new javax.swing.JFileChooser();
        startStopButton = new javax.swing.JButton();
        saveButton = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        packetsTable = new javax.swing.JTable();
        jScrollPane3 = new javax.swing.JScrollPane();
        packetBytesTextArea = new javax.swing.JTextArea();
        filterField = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        packetDetailsTextArea = new javax.swing.JTextArea();
        filterButton = new javax.swing.JButton();
        loadButton = new javax.swing.JButton();

        saveFileBox.setDialogType(javax.swing.JFileChooser.SAVE_DIALOG);

        startStopButton.setText("Start");
        startStopButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                startStopButtonActionPerformed(evt);
            }
        });

        saveButton.setText("Save");
        saveButton.setEnabled(false);
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });

        packetsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "No.", "Time", "Source", "Destination", "Protocol", "Length"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.Integer.class
            };
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        packetsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                packetsTableMouseClicked(evt);
            }
        });
        jScrollPane2.setViewportView(packetsTable);

        packetBytesTextArea.setEditable(false);
        packetBytesTextArea.setColumns(20);
        packetBytesTextArea.setRows(5);
        jScrollPane3.setViewportView(packetBytesTextArea);

        filterField.setText("Apply a display filter");
        filterField.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                filterFieldMouseClicked(evt);
            }
        });
        filterField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                filterFieldKeyPressed(evt);
            }
        });

        packetDetailsTextArea.setEditable(false);
        packetDetailsTextArea.setColumns(20);
        packetDetailsTextArea.setRows(5);
        jScrollPane1.setViewportView(packetDetailsTextArea);

        filterButton.setText("Filter");
        filterButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filterButtonActionPerformed(evt);
            }
        });

        loadButton.setText("Load");
        loadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(startStopButton)
                        .addGap(18, 18, 18)
                        .addComponent(saveButton)
                        .addGap(18, 18, 18)
                        .addComponent(loadButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(filterButton, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 738, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 738, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 738, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(filterField, javax.swing.GroupLayout.PREFERRED_SIZE, 738, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(loadButton, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(startStopButton)
                        .addComponent(saveButton)
                        .addComponent(filterButton)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(filterField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 390, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 114, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 101, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void startStopButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_startStopButtonActionPerformed
        if (startStopButton.getText().equalsIgnoreCase("Start")) {
            deviceController(true);
        } else {
            deviceController(false);
        }

    }//GEN-LAST:event_startStopButtonActionPerformed

    private void packetsTableMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_packetsTableMouseClicked
        PcapPacket packet = filteredPackets.get(packetsTable.getSelectedRow());
        packetDetailsTextArea.setText(packet.toString());
        packetBytesTextArea.setText(packet.toHexdump());
    }//GEN-LAST:event_packetsTableMouseClicked

    private void filterFieldMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_filterFieldMouseClicked
        filterField.setText("");
    }//GEN-LAST:event_filterFieldMouseClicked

    private void filterButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_filterButtonActionPerformed
        filterPackets(filterField.getText());
    }//GEN-LAST:event_filterButtonActionPerformed

    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveButtonActionPerformed
        saveFileBox.showSaveDialog(this);
        saveFileBox.resetChoosableFileFilters(); //reset file filters after opening the diaglog box to allow accepting any entered name without having to add .pcap in the end of that name
        try {
            String filePath = saveFileBox.getSelectedFile().getAbsolutePath() + ".pcap";
            save(filePath);
        } catch (NullPointerException e) {
        }
        saveFileBox.setFileFilter(fileTypeFilter);
    }//GEN-LAST:event_saveButtonActionPerformed

    private void loadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadButtonActionPerformed
        loadFileBox.showOpenDialog(this);
        try {
            String filePath = loadFileBox.getSelectedFile().getAbsolutePath() + ".pcap";
            load(filePath);
        } catch (NullPointerException e) {
        }
    }//GEN-LAST:event_loadButtonActionPerformed

    private void filterFieldKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_filterFieldKeyPressed
        if (evt.getKeyCode() == 10) {
            filterPackets(filterField.getText());
        }
    }//GEN-LAST:event_filterFieldKeyPressed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton filterButton;
    private javax.swing.JTextField filterField;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JButton loadButton;
    private javax.swing.JFileChooser loadFileBox;
    private javax.swing.JTextArea packetBytesTextArea;
    private javax.swing.JTextArea packetDetailsTextArea;
    private javax.swing.JTable packetsTable;
    private javax.swing.JButton saveButton;
    private javax.swing.JFileChooser saveFileBox;
    private javax.swing.JButton startStopButton;
    // End of variables declaration//GEN-END:variables
}
