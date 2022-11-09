
package burp;


import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.jsoup.*;


import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.jsoup.UncheckedIOException;

import javax.imageio.ImageIO;
import javax.net.ssl.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.image.RenderedImage;
import java.io.*;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;


import java.awt.image.BufferedImage;
import java.util.regex.Pattern;

public class BurpExtender implements burp.IBurpExtender, burp.ITab, burp.IContextMenuFactory, ClipboardOwner {

    public PrintWriter stdout;

    private JPanel jPanel1;


    // tabs

    private JTabbedPane tab_config;
    private JPanel panel_config;
    private JPanel panel_issue;
    private JPanel panel_poc;
    private JPanel panel_creds;
    private JPanel panel_host;

    //buttons
    private JButton b_gen_token;
    private JButton b_check_token;
    private JButton b_save_settings;
    private JButton b_save_settings_no_password;
    private JButton b_load_settings;
    private JButton b_projects_list;
    private JButton b_issue_submit;

    //boxes
    private Box boxHorizontal1;
    private Box boxHorizontal1_e;
    private Box boxHorizontal2;
    private Box boxHorizontal2_e;
    private Box boxHorizontal3;
    private Box boxHorizontal3_e;
    private Box boxHorizontal4;
    private Box boxHorizontal4_e;
    private Box boxHorizontal5;
    private Box boxHorizontal5_e;
    private Box boxHorizontal6;
    private Box boxHorizontal6_e;
    private Box boxHorizontal7;
    private Box boxVertical;

    private Box issue_first_column;
    private Box issue_box_horizontal1;
    private Box issue_box_horizontal1_e;
    private Box issue_box_horizontal2;
    private Box issue_box_horizontal2_e;
    private Box issue_box_horizontal3;
    private Box issue_box_horizontal3_e;
    private Box issue_box_horizontal4;
    private Box issue_box_horizontal4_e;
    private Box issue_box_horizontal5;
    private Box issue_box_horizontal5_e;
    private Box issue_box_horizontal6;
    private Box issue_box_horizontal6_e;
    private Box issue_box_horizontal7;
    private Box issue_box_horizontal7_e;
    private Box issue_box_horizontal8;
    private Box issue_box_horizontal8_e;
    private Box issue_box_horizontal9;
    private Box issue_box_horizontal9_e;
    private Box issue_box_horizontal10;
    private Box issue_box_horizontal10_e;
    private Box issue_box_horizontal11;
    private Box issue_box_horizontal11_e;
    private Box issue_box_horizontal12;
    private Box issue_box_horizontal12_e;
    private Box issue_box_horizontal13;
    private Box issue_box_horizontal13_e;
    private Box issue_box_horizontal14;
    private Box issue_box_horizontal14_e;
    private Box issue_box_horizontal15;
    private Box issue_box_horizontal15_e;
    private Box issue_box_horizontal16;
    private Box issue_box_horizontal16_e;

    private Box issue_box_horizontal_col2;


    private Box issue_columns_horizontal;

    private Color defaultTabColour;

    public ArrayList<Screenshot> screenshot_list = new ArrayList<>();


    private JTable screenshots_table;


    ////Input fields
    final JTextArea URL_form = new JTextArea("http://127.0.0.1:5000/", 1, 20);
    final JTextArea basic_auth_login = new JTextArea("admin", 1, 20);
    final JTextArea basic_auth_password = new JTextArea("password", 1, 20);
    final JTextArea project_uuid = new JTextArea("aaaaaaaa-bbbb-cccc-dddd-aaaaaaaaaaaa", 1, 36);
    final JTextArea token = new JTextArea("aaaaaaaa-bbbb-cccc-dddd-aaaaaaaaaaaa", 1, 20);
    final JTextArea email = new JTextArea("root@localhost.com", 1, 20);
    final JTextArea password = new JTextArea("Qwerty1234", 1, 20);

    final JTextArea issue_name_form = new JTextArea("", 1, 2);
    final JTextArea issue_description_form = new JTextArea(3, 20);
    final JTextArea issue_fix_form = new JTextArea(3, 20);
    final JTextArea issue_technical_form = new JTextArea(3, 20);
    final JTextArea issue_risks_form = new JTextArea(3, 20);
    final JTextArea issue_references_form = new JTextArea(3, 20);
    final JTextArea issue_services_form = new JTextArea(3, 20);
    final JTextArea issue_path_form = new JTextArea(1, 20);
    SpinnerNumberModel issue_cvss_model = new SpinnerNumberModel(
            Float.valueOf(0), // value
            Float.valueOf(0), // min
            Float.valueOf(10), // max
            Float.valueOf(0.1f) // step
    );
    final JSpinner issue_cvss_form = new JSpinner(issue_cvss_model);
    final JTextArea issue_cve_form = new JTextArea(1, 20);
    SpinnerNumberModel issue_cwe_model = new SpinnerNumberModel(
            Integer.valueOf(0), // value
            Integer.valueOf(0), // min
            Integer.valueOf(9999), // max
            Integer.valueOf(1) // step
    );
    final JSpinner issue_cwe_form = new JSpinner(issue_cwe_model);
    String[] issue_status_list = {"Need to recheck", "PoC creation", "PoC available", "Confirmed", "Wasn't Confirmed", "Pending....", "Need to check"};
    final JComboBox issue_status_form = new JComboBox(issue_status_list);
    String[] issue_criticality_list = {"Use CVSS criticality", "Critical (cvss=9.5)", "High (cvss=8.0)", "Medium (cvss=5.0)", "Low (cvss=2.0)", "Information (cvss=0.0)"};
    final JComboBox issue_criticality_form = new JComboBox(issue_criticality_list);
    final JTextArea issue_parameters_form = new JTextArea(1, 20);
    String[] issue_type_list = {"web", "custom", "credentials", "service"};
    final JComboBox issue_type_form = new JComboBox(issue_type_list);
    final JTextArea issue_intruder_form = new JTextArea();

    String[] projects = {};
    String os = "";
    JComboBox list_projects = new JComboBox(projects);

    ////Labels
    final JLabel l_url = new JLabel("URL: ");
    final JLabel l_basic_auth_login = new JLabel("Basic login: ");
    final JLabel l_basic_auth_password = new JLabel(" Basic password: ");
    final JLabel l_project_uuid = new JLabel("Project UUID: ");
    final JLabel l_token = new JLabel("API token: ");
    final JLabel l_email = new JLabel("Email: ");
    final JLabel l_password = new JLabel(" Password: ");
    final JLabel l_header = new JLabel("Pentest Collaboration Framework: configuration");

    final JLabel l_issue_name = new JLabel("Name: ");
    final JLabel l_issue_description = new JLabel("Description: ");
    final JLabel l_issue_fix = new JLabel("  Fix: ");
    final JLabel l_issue_technical = new JLabel("Technical: ");
    final JLabel l_issue_risks = new JLabel("  Risks: ");
    final JLabel l_issue_references = new JLabel("References: ");
    final JLabel l_issue_services = new JLabel("  Services: ");
    final JLabel l_issue_path = new JLabel("  URL path: ");
    final JLabel l_issue_cvss = new JLabel("CVSS: ");
    final JLabel l_issue_cve = new JLabel("CVE: ");
    final JLabel l_issue_cwe = new JLabel("  CWE: ");
    final JLabel l_issue_status = new JLabel("Status: ");
    final JLabel l_issue_criticality = new JLabel("  Criticality: ");
    final JLabel l_issue_parameters = new JLabel("Params: ");
    final JLabel l_issue_type = new JLabel("  Type: ");
    final JLabel l_issue_intruder = new JLabel("Intruder: ");
    final JLabel l_issue_header = new JLabel("Pentest Collaboration Framework: ");
    final JLabel l_issue_poc = new JLabel("Proof of Concept");
    final JLabel l_issue_poc_hint = new JLabel("(You can add screenshot from Repeater)");

    final JCheckBox checkbox_issue_duplicates = new JCheckBox("Search for duplicates  ", true);


    final JLabel l_empty1 = new JLabel(" ");
    final JLabel l_empty2 = new JLabel(" ");
    final JLabel l_empty3 = new JLabel(" ");
    final JLabel l_empty4 = new JLabel(" ");
    final JLabel l_empty5 = new JLabel(" ");
    final JLabel l_empty6 = new JLabel(" ");

    final JLabel l_issue_empty1 = new JLabel(" ");
    final JLabel l_issue_empty2 = new JLabel(" ");
    final JLabel l_issue_empty3 = new JLabel(" ");
    final JLabel l_issue_empty4 = new JLabel(" ");
    final JLabel l_issue_empty5 = new JLabel(" ");
    final JLabel l_issue_empty6 = new JLabel(" ");
    final JLabel l_issue_empty7 = new JLabel(" ");
    final JLabel l_issue_empty8 = new JLabel(" ");
    final JLabel l_issue_empty9 = new JLabel(" ");
    final JLabel l_issue_empty10 = new JLabel(" ");
    final JLabel l_issue_empty11 = new JLabel(" ");
    final JLabel l_issue_empty12 = new JLabel(" ");
    final JLabel l_issue_empty13 = new JLabel(" ");
    final JLabel l_issue_empty14 = new JLabel(" ");
    final JLabel l_issue_empty15 = new JLabel(" ");
    final JLabel l_issue_empty16 = new JLabel(" ");


    private burp.IBurpExtenderCallbacks callbacks;

    private volatile boolean running;


    private burp.IExtensionHelpers helpers;

    Frame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return f;
            }
        }
        return null;
    }

    @Override
    public void registerExtenderCallbacks(final burp.IBurpExtenderCallbacks callbacks) {

        String os = System.getProperty("os.name").toLowerCase();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.registerContextMenuFactory(this);
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("PCF");

        defaultTabColour = getDefaultTabColour();

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                jPanel1 = new JPanel();

                String columnNames[] = {"", "DESCRIPTION", "IMAGE", "", "", "", "", ""};

                Object[][] data = {};


                TableModel model = new DefaultTableModel(data, columnNames) {

                    @Override
                    public Class<?> getColumnClass(int column) {
                        switch (column) {
                            case 0:
                                return Boolean.class;
                            case 1:
                                return String.class;
                            default:
                                return getValueAt(0, column).getClass();
                        }
                    }
                };
                screenshots_table = new JTable(model) {
                    private static final long serialVersionUID = 1L;

                    public boolean isCellEditable(int row, int column) {
                        return column != 2;
                    }

                    ;
                };

                TableColumnModel tcm = screenshots_table.getColumnModel();
                tcm.removeColumn(tcm.getColumn(7));


                screenshots_table.setRowSelectionAllowed(false);

                //jPanel1.setBounds(50,50,1000,500);

                running = true;

                // tabs
                tab_config = new JTabbedPane();

                panel_config = new JPanel();
                panel_issue = new JPanel();
                JPanel panel_help = new JPanel();
                panel_creds = new JPanel();
                panel_host = new JPanel();

                //tab_config.setBounds(50, 50, 1000, 500);
                tab_config.add("Config", panel_config);
                tab_config.add("New issue", panel_issue);
                // tab_config.add("New credentials", panel_creds);
                // tab_config.add("New hosts/hostnames", panel_host);
                tab_config.add("Help", panel_help);

                JPanel help_jpanel = new JPanel();

                Box link_horizontal = Box.createHorizontalBox();

                Box link_vertical = Box.createVerticalBox();

                SwingLink link_repo = new SwingLink("PCF Repository:  https://gitlab.com/invuls/pentest-projects/pcf",
                        "https://gitlab.com/invuls/pentest-projects/pcf");
                link_vertical.add(link_repo);
                SwingLink link_repo_burp = new SwingLink("Plugin Repository:  https://gitlab.com/invuls/pentest-projects/pcf_tools/pcf-burpsuite-extention",
                        "https://gitlab.com/invuls/pentest-projects/pcf_tools/pcf-burpsuite-extention");
                link_vertical.add(link_repo_burp);


                SwingLink link_chat = new SwingLink("Telegram chat:  https://t.me/PentestCollaborationFramework",
                        "https://t.me/PentestCollaborationFramework");
                link_vertical.add(link_chat);
                SwingLink link_wiki = new SwingLink("Wiki:  https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/home",
                        "https://gitlab.com/invuls/pentest-projects/pcf/-/wikis/home");
                link_vertical.add(link_wiki);
                SwingLink link_demo = new SwingLink("Demo:  http://testing-pcf.herokuapp.com/",
                        "http://testing-pcf.herokuapp.com/");
                link_vertical.add(link_demo);
                SwingLink link_releases = new SwingLink("PCF Releases:  https://gitlab.com/invuls/pentest-projects/pcf/-/releases",
                        "https://gitlab.com/invuls/pentest-projects/pcf/-/releases");
                link_vertical.add(link_releases);
                SwingLink link_youtube = new SwingLink("Youtube:  https://www.youtube.com/channel/UC_KxzNcex25rctd7bW7QEyg",
                        "https://www.youtube.com/channel/UC_KxzNcex25rctd7bW7QEyg");
                link_vertical.add(link_youtube);
                SwingLink link_issues = new SwingLink("Issues:  https://gitlab.com/invuls/pentest-projects/pcf/-/issues",
                        "https://gitlab.com/invuls/pentest-projects/pcf/-/issues");
                link_vertical.add(link_issues);
                SwingLink link_feature = new SwingLink("Feature request:  https://gitlab.com/invuls/pentest-projects/pcf/-/issues/new?issuable_template=Feature%20request",
                        "https://gitlab.com/invuls/pentest-projects/pcf/-/issues/new?issuable_template=Feature%20request");
                link_vertical.add(link_feature);
                SwingLink link_contribute = new SwingLink("Contribute:  https://gitlab.com/invuls/pentest-projects/pcf/-/tree/master#%EF%B8%8F-contribute",
                        "https://gitlab.com/invuls/pentest-projects/pcf/-/tree/master#%EF%B8%8F-contribute");
                link_vertical.add(link_contribute);


                Box link_vertical1 = Box.createVerticalBox();


                BufferedImage myPicture = null;
                myPicture = loadImage("images/icon_mini_good.png");
                JLabel picLabel = new JLabel(new ImageIcon(myPicture));
                link_vertical1.add(picLabel);

                link_horizontal.add(link_vertical);
                link_horizontal.add(link_vertical1);

                help_jpanel.add(link_horizontal);
                panel_help.add(help_jpanel);


                //#######################################


                boxVertical = Box.createVerticalBox();

                //###########################
                boxHorizontal1 = Box.createHorizontalBox();
                boxHorizontal1.add(l_header);
                boxHorizontal1_e = Box.createHorizontalBox();
                boxHorizontal1_e.add(l_empty1);


                boxHorizontal2 = Box.createHorizontalBox();
                //jButton1 = new JButton("Check");
                boxHorizontal2.add(l_url);
                boxHorizontal2.add(URL_form);
                //boxHorizontal2.add(jButton1);
                boxHorizontal2_e = Box.createHorizontalBox();
                boxHorizontal2_e.add(l_empty2);

                boxHorizontal3 = Box.createHorizontalBox();
                //l_basic_auth_login.setBorder(BorderFactory.createEmptyBorder(20, 0, 0, 0));
                boxHorizontal3.add(l_basic_auth_login);
                boxHorizontal3.add(basic_auth_login);
                String settings_rtl = callbacks.loadExtensionSetting("PCF_URL");
                if (settings_rtl != null && !settings_rtl.equals("")) {
                    load_settings();
                }
                boxHorizontal3.add(l_basic_auth_password);
                boxHorizontal3.add(basic_auth_password);
                boxHorizontal3_e = Box.createHorizontalBox();
                boxHorizontal3_e.add(l_empty3);

                boxHorizontal4 = Box.createHorizontalBox();
                boxHorizontal4.add(l_email);
                boxHorizontal4.add(email);
                boxHorizontal4.add(l_password);
                boxHorizontal4.add(password);
                boxHorizontal4_e = Box.createHorizontalBox();
                boxHorizontal4_e.add(l_empty4);

                boxHorizontal5 = Box.createHorizontalBox();
                boxHorizontal5.add(l_token);
                boxHorizontal5.add(token);
                boxHorizontal5_e = Box.createHorizontalBox();
                boxHorizontal5_e.add(l_empty5);

                boxHorizontal6 = Box.createHorizontalBox();
                boxHorizontal6.add(l_project_uuid);
                //boxHorizontal6.add(project_uuid);
                list_projects.setEditable(true);
                boxHorizontal6.add(list_projects);
                b_projects_list = new JButton("Get Projects");
                b_projects_list.setEnabled(true);
                boxHorizontal6.add(b_projects_list);
                boxHorizontal6_e = Box.createHorizontalBox();
                boxHorizontal6_e.add(l_empty6);

                boxHorizontal7 = Box.createHorizontalBox();
                b_gen_token = new JButton("Generate token");
                b_check_token = new JButton("Check token");
                if (os.contains("win") || os.contains("mac")) {
                    b_save_settings = new JButton("\uD83D\uDCBE (+ \uD83D\uDD11)");
                    b_save_settings_no_password = new JButton("\uD83D\uDCBE");
                } else {
                    b_save_settings = new JButton("Save (+ pwds)");
                    b_save_settings_no_password = new JButton("Save");
                }
                b_load_settings = new JButton("Load settings");


                b_save_settings.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        callbacks.printOutput("Saving with password!");
                        save_settings(true);
                    }
                });

                b_save_settings_no_password.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        callbacks.printOutput("Saving without password!");
                        save_settings(false);
                    }
                });

                b_load_settings.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        callbacks.printOutput("Load data!");
                        load_settings();
                    }
                });

                b_check_token.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        callbacks.printOutput("Token check!");
                        check_token();
                    }
                });

                b_gen_token.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        callbacks.printOutput("Clicked!");
                        generate_token();
                    }
                });
                b_projects_list.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        callbacks.printOutput("Clicked!");
                        pcf_get_projects();
                    }
                });
                b_gen_token.setEnabled(true);
                b_check_token.setEnabled(true);
                b_save_settings_no_password.setEnabled(true);
                b_save_settings.setEnabled(true);
                b_load_settings.setEnabled(true);

                boxHorizontal7.add(b_gen_token);
                boxHorizontal7.add(b_check_token);
                boxHorizontal7.add(b_save_settings);
                boxHorizontal7.add(b_save_settings_no_password);
                boxHorizontal7.add(b_load_settings);


                boxVertical.add(boxHorizontal1);
                boxVertical.add(boxHorizontal1_e);
                boxVertical.add(boxHorizontal2);
                boxVertical.add(boxHorizontal2_e);
                boxVertical.add(boxHorizontal3);
                boxVertical.add(boxHorizontal3_e);
                boxVertical.add(boxHorizontal4);
                boxVertical.add(boxHorizontal4_e);
                boxVertical.add(boxHorizontal5);
                boxVertical.add(boxHorizontal5_e);
                boxVertical.add(boxHorizontal6);
                boxVertical.add(boxHorizontal6_e);
                boxVertical.add(boxHorizontal7);

                panel_config.add(boxVertical);

                // ###########################################
                // new issue tab
                // ###########################################

                issue_columns_horizontal = Box.createHorizontalBox();


                issue_first_column = Box.createVerticalBox();
                issue_first_column.setSize(1000, 500);


                // add header
                issue_box_horizontal1 = Box.createHorizontalBox();
                issue_box_horizontal1.add(l_issue_header);
                issue_box_horizontal1_e = Box.createHorizontalBox();
                issue_box_horizontal1_e.add(l_issue_empty1);


                // issue name
                issue_box_horizontal2 = Box.createHorizontalBox();
                issue_box_horizontal2.add(l_issue_name);
                issue_box_horizontal2.add(issue_name_form);
                issue_box_horizontal2.add(checkbox_issue_duplicates);
                b_issue_submit = new JButton("Submit!");
                b_issue_submit.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String issue_name = issue_name_form.getText();
                        String issue_description = issue_description_form.getText();
                        Boolean issue_duplicates = checkbox_issue_duplicates.isSelected();
                        String issue_fix = issue_fix_form.getText();
                        String issue_technical = issue_technical_form.getText();
                        String issue_risks = issue_risks_form.getText();
                        String issue_references = issue_references_form.getText();

                        callbacks.printOutput("1");
                        Float issue_cvss = Float.parseFloat(issue_cvss_form.getValue().toString());
                        callbacks.printOutput("2");
                        String issue_criticality = (String) issue_criticality_form.getSelectedItem();
                        String issue_cve = issue_cve_form.getText();
                        Integer issue_cwe = (Integer) issue_cwe_form.getValue();
                        String issue_status = (String) issue_status_form.getSelectedItem();
                        String issue_type = (String) issue_type_form.getSelectedItem();
                        String issue_params = issue_parameters_form.getText();
                        String issue_url = issue_path_form.getText();
                        String issue_intruder = issue_intruder_form.getText();
                        String issue_services = issue_services_form.getText();


                        if (issue_name.equals("")) {
                            JOptionPane.showMessageDialog(null,
                                    "Issue name must not be empty!", "Pentest Collaboration Framework: New issue",
                                    JOptionPane.ERROR_MESSAGE);
                            return;
                        }

                        if (( issue_cvss > 10.0 ||  issue_cvss < 0.0) && issue_criticality.equals("Use CVSS criticality")) {
                            JOptionPane.showMessageDialog(null,
                                    "Issue CVSS must be in 0..10 !", "Pentest Collaboration Framework: New issue", JOptionPane.ERROR_MESSAGE);
                            return;
                        }

                        //Service

                        String[] issue_services_lines = issue_services.split("\n");

                        Service current_service = null;

                        JSONObject services = new JSONObject();
                        JSONArray hostnames = new JSONArray();

                        Boolean result;

                        String hostname_key;
                        String port_id = "0";
                        String hostname_id = "0";

                        callbacks.printOutput("3");


                        int added = 0;

                        for (int i = 0; i < issue_services_lines.length; i++) {
                            if (!issue_services_lines[i].equals("")) {
                                added++;
                                current_service = new Service();
                                result = current_service.Main(issue_services_lines[i]);
                                hostname_id = current_service.hostname_uuid;
                                port_id = current_service.port_uuid;
                                if (!result) return;
                                if (!services.has(current_service.port_uuid)) {
                                    hostnames = new JSONArray();
                                    if (current_service.hostname_uuid.equals("")) {
                                        hostnames.put("0");
                                        hostname_id = "0";
                                    } else {
                                        hostnames.put(current_service.hostname_uuid);
                                    }
                                    services.put(current_service.port_uuid, hostnames);
                                } else {
                                    // if exists

                                    if (current_service.hostname_uuid.equals("")) {

                                        if (getKey((JSONArray) services.get(current_service.port_uuid), "0") == null) {
                                            ((JSONArray) services.get(current_service.port_uuid)).put("0");
                                            hostname_id = "0";
                                        }

                                    } else {
                                        if (getKey((JSONArray) services.get(current_service.port_uuid), current_service.hostname_uuid) == null) {
                                            ((JSONArray) services.get(current_service.port_uuid)).put(current_service.hostname_uuid);
                                        }
                                    }
                                }
                            }
                        }
                        callbacks.printOutput("4");

                        String issue_id = pcf_add_issue(issue_name, issue_description, issue_fix, issue_url, issue_params,
                                issue_cvss, services, issue_technical, issue_risks, issue_references,
                                issue_duplicates, issue_cve, issue_type, issue_status, issue_cwe, issue_intruder);

                        callbacks.printOutput("Added issue: " + issue_id);

                        if (added == 1){
                            upload_selected_screenshots(issue_id, port_id, hostname_id);
                        }


                    }
                });
                b_issue_submit.setBackground(new Color(0xcb5f18));
                b_issue_submit.setEnabled(true);
                issue_box_horizontal2.add(b_issue_submit);
                issue_box_horizontal2_e = Box.createHorizontalBox();
                issue_box_horizontal2_e.add(l_issue_empty2);

                // issue description
                issue_box_horizontal3 = Box.createHorizontalBox();
                issue_box_horizontal3.add(l_issue_description);
                issue_box_horizontal3.add(issue_description_form);
                issue_description_form.setWrapStyleWord(true);
                issue_description_form.setLineWrap(true);
                JScrollPane issue_description_scroll = new JScrollPane(issue_description_form);
                issue_description_scroll.setViewportView(issue_description_form);
                issue_description_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                issue_description_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                issue_box_horizontal3.add(issue_description_scroll);
                issue_box_horizontal3.add(l_issue_fix);
                issue_box_horizontal3.add(issue_fix_form);
                issue_fix_form.setWrapStyleWord(true);
                issue_fix_form.setLineWrap(true);
                JScrollPane issue_fix_scroll = new JScrollPane(issue_fix_form);
                issue_fix_scroll.setViewportView(issue_fix_form);
                issue_fix_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                issue_box_horizontal3.add(issue_fix_scroll);
                issue_box_horizontal3_e = Box.createHorizontalBox();
                issue_box_horizontal3_e.add(l_issue_empty3);

                // issue technical
                issue_box_horizontal5 = Box.createHorizontalBox();
                issue_box_horizontal5.add(l_issue_technical);
                issue_box_horizontal5.add(issue_technical_form);
                issue_technical_form.setWrapStyleWord(true);
                issue_technical_form.setLineWrap(true);
                JScrollPane issue_technical_scroll = new JScrollPane(issue_technical_form);
                issue_technical_scroll.setViewportView(issue_technical_form);
                issue_technical_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                issue_box_horizontal5.add(issue_technical_scroll);
                issue_box_horizontal5.add(l_issue_risks);
                issue_box_horizontal5.add(issue_risks_form);
                issue_risks_form.setWrapStyleWord(true);
                issue_risks_form.setLineWrap(true);
                JScrollPane issue_risks_scroll = new JScrollPane(issue_risks_form);
                issue_risks_scroll.setViewportView(issue_risks_form);
                issue_risks_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                issue_box_horizontal5.add(issue_risks_scroll);
                issue_box_horizontal5_e = Box.createHorizontalBox();
                issue_box_horizontal5_e.add(l_issue_empty5);

                // issue references
                issue_box_horizontal7 = Box.createHorizontalBox();
                issue_box_horizontal7.add(l_issue_references);
                issue_box_horizontal7.add(issue_references_form);
                issue_references_form.setWrapStyleWord(true);
                issue_references_form.setLineWrap(true);
                JScrollPane issue_references_scroll = new JScrollPane(issue_references_form);
                issue_references_scroll.setViewportView(issue_references_form);
                issue_references_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                issue_box_horizontal7.add(issue_references_scroll);
                issue_box_horizontal7.add(l_issue_services);
                issue_box_horizontal7.add(issue_services_form);
                issue_services_form.setWrapStyleWord(true);
                issue_services_form.setLineWrap(true);
                JScrollPane issue_services_scroll = new JScrollPane(issue_services_form);
                issue_services_scroll.setViewportView(issue_services_form);
                issue_services_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                issue_box_horizontal7.add(issue_services_scroll);
                issue_box_horizontal7_e = Box.createHorizontalBox();
                issue_box_horizontal7_e.add(l_issue_empty7);

                // issue path
                /*
                issue_box_horizontal8 = Box.createHorizontalBox();
                issue_box_horizontal8.add(l_issue_path);
                issue_box_horizontal8.add(issue_path_form);
                issue_box_horizontal8_e = Box.createHorizontalBox();
                issue_box_horizontal8_e.add(l_issue_empty8);

                 */

                // issue cvss
                issue_box_horizontal9 = Box.createHorizontalBox();
                issue_box_horizontal9.add(l_issue_cvss);
                issue_box_horizontal9.add(issue_cvss_form);
                issue_box_horizontal9.add(l_issue_criticality);
                issue_box_horizontal9.add(issue_criticality_form);
                issue_box_horizontal9_e = Box.createHorizontalBox();
                issue_box_horizontal9_e.add(l_issue_empty9);

                // issue cve
                issue_box_horizontal10 = Box.createHorizontalBox();
                issue_box_horizontal10.add(l_issue_cve);
                issue_box_horizontal10.add(issue_cve_form);
                issue_box_horizontal10.add(l_issue_cwe);
                issue_box_horizontal10.add(issue_cwe_form);
                issue_box_horizontal10_e = Box.createHorizontalBox();
                issue_box_horizontal10_e.add(l_issue_empty10);

                // issue status
                issue_box_horizontal12 = Box.createHorizontalBox();
                issue_box_horizontal12.add(l_issue_status);
                issue_box_horizontal12.add(issue_status_form);
                issue_box_horizontal12.add(l_issue_type);
                issue_box_horizontal12.add(issue_type_form);
                issue_box_horizontal12_e = Box.createHorizontalBox();
                issue_box_horizontal12_e.add(l_issue_empty12);

                // issue parameters
                issue_box_horizontal14 = Box.createHorizontalBox();
                issue_box_horizontal14.add(l_issue_parameters);
                issue_box_horizontal14.add(issue_parameters_form);
                issue_box_horizontal14.add(l_issue_path);
                issue_box_horizontal14.add(issue_path_form);
                issue_path_form.setWrapStyleWord(true);
                issue_path_form.setLineWrap(true);
                issue_box_horizontal14_e = Box.createHorizontalBox();
                issue_box_horizontal14_e.add(l_issue_empty14);

                // issue intruder
                issue_box_horizontal16 = Box.createHorizontalBox();
                issue_box_horizontal16.add(l_issue_intruder);
                issue_box_horizontal16.add(issue_intruder_form);
                issue_intruder_form.setLineWrap(true);
                issue_intruder_form.setWrapStyleWord(true);
                issue_box_horizontal16_e = Box.createHorizontalBox();
                issue_box_horizontal16_e.add(l_issue_empty16);


                issue_first_column.add(issue_box_horizontal1);
                issue_first_column.add(issue_box_horizontal1_e);
                issue_first_column.add(issue_box_horizontal2);
                issue_first_column.add(issue_box_horizontal2_e);
                issue_first_column.add(issue_box_horizontal3);
                issue_first_column.add(issue_box_horizontal3_e);
                issue_first_column.add(issue_box_horizontal5);
                issue_first_column.add(issue_box_horizontal5_e);
                issue_first_column.add(issue_box_horizontal7);
                issue_first_column.add(issue_box_horizontal7_e);
                //issue_box_vertical.add(issue_box_horizontal8);
                //issue_box_vertical.add(issue_box_horizontal8_e);
                issue_first_column.add(issue_box_horizontal9);
                issue_first_column.add(issue_box_horizontal9_e);
                issue_first_column.add(issue_box_horizontal10);
                issue_first_column.add(issue_box_horizontal10_e);
                issue_first_column.add(issue_box_horizontal12);
                issue_first_column.add(issue_box_horizontal12_e);
                issue_first_column.add(issue_box_horizontal14);
                issue_first_column.add(issue_box_horizontal14_e);
                issue_first_column.add(issue_box_horizontal16);
                issue_first_column.add(issue_box_horizontal16_e);


                //########################################

                JPanel issue_second_column = new JPanel();
                issue_second_column.setSize(1000, 1000);

                Box vertical_box = Box.createVerticalBox();
                vertical_box.setSize(1000, 1000);

                vertical_box.add(l_issue_poc);

                vertical_box.add(new Label("(You can add screenshot from Repeater)"));


                screenshots_table.setSize(1000, 5000);

                screenshots_table.getColumnModel().getColumn(0).setPreferredWidth(20);
                screenshots_table.getColumnModel().getColumn(1).setPreferredWidth(100);
                screenshots_table.getColumnModel().getColumn(2).setPreferredWidth(300);
                screenshots_table.getColumnModel().getColumn(3).setPreferredWidth(20);
                screenshots_table.getColumnModel().getColumn(4).setPreferredWidth(20);
                screenshots_table.getColumnModel().getColumn(5).setPreferredWidth(20);
                screenshots_table.getColumnModel().getColumn(6).setPreferredWidth(20);

                screenshots_table.setRowHeight(100);

                vertical_box.add(screenshots_table.getTableHeader(), BorderLayout.NORTH);
                vertical_box.add(screenshots_table, BorderLayout.CENTER);

                JScrollPane table_scroll = new JScrollPane(screenshots_table);
                table_scroll.setVisible(true);
                vertical_box.add(table_scroll);


                Action delete = new AbstractAction() {
                    public void actionPerformed(ActionEvent e) {
                        callbacks.printOutput("Delete row");

                    }
                };

                ButtonColumn buttonColumn = new ButtonColumn(screenshots_table, delete, 6);
                buttonColumn.setMnemonic(KeyEvent.VK_D);


                issue_second_column.add(vertical_box);


                //##################################

                issue_first_column.setPreferredSize(new Dimension(500, 500));
                issue_first_column.setAutoscrolls(true);

                issue_second_column.setPreferredSize(new Dimension(500, 500));
                issue_second_column.setAutoscrolls(true);

                int top = 10;
                int left = 10;
                int bottom = 10;
                int right = 10;

                issue_first_column.setBorder(BorderFactory.createEmptyBorder(top, left, bottom, right));

                issue_columns_horizontal.add(issue_first_column);

                issue_columns_horizontal.add(issue_second_column);
                panel_issue.add(issue_columns_horizontal, BorderLayout.PAGE_START);


                //################################

                jPanel1.add(tab_config, BorderLayout.PAGE_START);


                //Customized UI components
                callbacks.customizeUiComponent(jPanel1);
                //Add custom tabs to Burp UI
                callbacks.addSuiteTab(BurpExtender.this);


            }
        });
    }

    @Override
    public String getTabCaption() {
        // Return the title of the custom tab page
        return "PCF";
    }

    @Override
    public Component getUiComponent() {
        // Return the component object of the panel in the custom tab
        return jPanel1;
    }

    public void save_settings(Boolean with_pwd) {
        callbacks.saveExtensionSetting("PCF_BASIC_LOGIN", basic_auth_login.getText());
        callbacks.saveExtensionSetting("PCF_URL", URL_form.getText());
        callbacks.saveExtensionSetting("PCF_EMAIL", email.getText());
        callbacks.saveExtensionSetting("PCF_TOKEN", token.getText());
        callbacks.saveExtensionSetting("PCF_PROJECT", ((ComboItem) list_projects.getSelectedItem()).getValue());
        if (with_pwd) {
            l_empty6.setText("Saved PCF settings (with password)!");
            callbacks.saveExtensionSetting("PCF_PASSWORD", password.getText());
            callbacks.saveExtensionSetting("PCF_BASIC_PASSWORD", basic_auth_password.getText());
        } else {
            l_empty6.setText("Saved PCF settings (without password)!");
            callbacks.saveExtensionSetting("PCF_PASSWORD", "");
            callbacks.saveExtensionSetting("PCF_BASIC_PASSWORD", "");
        }
    }

    public void check_token() {
        String token_s = token.getText();
        if (token_s.equals("")) {
            l_empty6.setText("Empty token!");
            return;
        }
        JSONObject jo = new JSONObject();
        jo.put("access_token", token_s);

        JSONObject result_json = pcf_request("api/v1/check_token", jo);
        if (result_json.has("errors")) {
            l_empty6.setText(result_json.getJSONArray("errors").get(0).toString());
            return;
        }
        l_empty6.setText("Token will be available for " + String.valueOf(result_json.getInt("time_left")) + " seconds!");
        return;
    }

    public void load_settings() {
        l_empty6.setText("Loaded PCF settings!");
        basic_auth_login.setText((callbacks.loadExtensionSetting("PCF_BASIC_LOGIN") == null) ? "" : callbacks.loadExtensionSetting("PCF_BASIC_LOGIN"));
        URL_form.setText((callbacks.loadExtensionSetting("PCF_URL") == null) ? "" : callbacks.loadExtensionSetting("PCF_URL"));
        email.setText((callbacks.loadExtensionSetting("PCF_EMAIL") == null) ? "" : callbacks.loadExtensionSetting("PCF_EMAIL"));
        token.setText((callbacks.loadExtensionSetting("PCF_TOKEN") == null) ? "" : callbacks.loadExtensionSetting("PCF_TOKEN"));
        list_projects.removeAllItems();
        String project_uuid = (callbacks.loadExtensionSetting("PCF_PROJECT") == null) ? "" : callbacks.loadExtensionSetting("PCF_PROJECT");
        list_projects.addItem(new ComboItem("Saved project (" + project_uuid + ")", project_uuid));
        password.setText((callbacks.loadExtensionSetting("PCF_PASSWORD") == null) ? "" : callbacks.loadExtensionSetting("PCF_PASSWORD"));
        basic_auth_password.setText((callbacks.loadExtensionSetting("PCF_BASIC_PASSWORD") == null) ? "" : callbacks.loadExtensionSetting("PCF_PASSWORD"));
    }


    public List<JMenuItem> createMenuItems(final burp.IContextMenuInvocation invocation) {


        List<JMenuItem> listMenuItems = new ArrayList<>();
        if (invocation.getToolFlag() == burp.IBurpExtenderCallbacks.TOOL_SCANNER) {

            burp.IScanIssue[] ihrrs;
            ihrrs = invocation.getSelectedIssues();
            JMenuItem menuItem;
            menuItem = new JMenuItem("New issue");
            menuItem.addActionListener(new MenuItemListener(ihrrs));
            listMenuItems.add(menuItem);
            menuItem = new JMenuItem("New issue (fast)");
            menuItem.addActionListener(new MenuItemListener(ihrrs));
            listMenuItems.add(menuItem);
        } else if (invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER) {
            burp.IScanIssue[] ihrrs;
            ihrrs = invocation.getSelectedIssues();
            JMenuItem menuItem_repeater;
            JMenuItem menuItem_poc_and_issue = new JMenuItem("PoC + Issue");
            menuItem_poc_and_issue.addActionListener(new MenuItemListener(ihrrs));
            menuItem_poc_and_issue.addMouseListener(new MouseListener() {
                public void mouseClicked(MouseEvent e) {
                }

                public void mousePressed(MouseEvent e) {
                }

                public void mouseReleased(MouseEvent e) {

                    var message = invocation.getSelectedMessages()[0];
                    var request = message.getRequest();

                    Screenshot new_screenshot = new Screenshot();


                    Frame burp_window = getBurpFrame();

                    // Retrieve Image
                    BufferedImage buffer = new BufferedImage(burp_window.getWidth(), burp_window.getHeight(), BufferedImage.TYPE_INT_RGB);
                    burp_window.paint(buffer.createGraphics());
                    new_screenshot.Main("", buffer);


                    DefaultTableModel model = (DefaultTableModel) screenshots_table.getModel();

                    Image image = new_screenshot.image; // transform it
                    Image newimg = image.getScaledInstance(300, 300, Image.SCALE_SMOOTH); // scale it the smooth way
                    ImageIcon icon = new ImageIcon(newimg);


                    String description = (String) JOptionPane.showInputDialog(null,
                            "PoC Description", "Pentest Collaboration Framework",
                            JOptionPane.INFORMATION_MESSAGE, icon,
                            null, "");

                    callbacks.printOutput("PoC description: " + description);

                    if (description != null) {
                        new_screenshot.description = description;
                        add_screenshot(new_screenshot);
                        new_issue_repeater(request, message.getHttpService());
                    }

                }

                public void mouseEntered(MouseEvent e) {
                }

                public void mouseExited(MouseEvent e) {
                }
            });


            listMenuItems.add(menuItem_poc_and_issue);


            JMenuItem menuItem_poc_and_issue_fast = new JMenuItem("PoC + Issue (fast)");
            menuItem_poc_and_issue_fast.addMouseListener(new MouseListener() {
                public void mouseClicked(MouseEvent e) {
                }

                public void mousePressed(MouseEvent e) {
                }

                public void mouseReleased(MouseEvent e) {

                    var message = invocation.getSelectedMessages()[0];
                    var request = message.getRequest();

                    Screenshot new_screenshot = new Screenshot();


                    Frame burp_window = getBurpFrame();

                    // Retrieve Image
                    BufferedImage buffer = new BufferedImage(burp_window.getWidth(), burp_window.getHeight(), BufferedImage.TYPE_INT_RGB);
                    burp_window.paint(buffer.createGraphics());
                    new_screenshot.Main("", buffer);


                    DefaultTableModel model = (DefaultTableModel) screenshots_table.getModel();

                    Image image = new_screenshot.image; // transform it
                    Image newimg = image.getScaledInstance(300, 300, Image.SCALE_SMOOTH); // scale it the smooth way
                    ImageIcon icon = new ImageIcon(newimg);

                    JTextField issue_name = new JTextField("", 5);
                    JTextField poc_description = new JTextField(5);

                    Object[] input_fields = {
                            "Issue name:", issue_name,
                            "PoC description:", poc_description
                    };


                    int option = JOptionPane.showConfirmDialog(null, input_fields, "Pentest Collaboration Framework: PoC + Issue (fast)", JOptionPane.OK_CANCEL_OPTION);

                    if (option == JOptionPane.OK_OPTION) {
                        if (issue_name.getText() != null && !issue_name.getText().equals("")) {
                            new_issue_repeater(request, message.getHttpService());


                            issue_name_form.setText(issue_name.getText());

                            String issue_description = issue_description_form.getText();
                            Boolean issue_duplicates = checkbox_issue_duplicates.isSelected();
                            String issue_fix = issue_fix_form.getText();
                            String issue_technical = issue_technical_form.getText();
                            String issue_risks = issue_risks_form.getText();
                            String issue_references = issue_references_form.getText();

                            callbacks.printOutput("1");
                            Float issue_cvss = Float.parseFloat(issue_cvss_form.getValue().toString());
                            callbacks.printOutput("2");
                            String issue_criticality = (String) issue_criticality_form.getSelectedItem();
                            String issue_cve = issue_cve_form.getText();
                            Integer issue_cwe = (Integer) issue_cwe_form.getValue();
                            String issue_status = (String) issue_status_form.getSelectedItem();
                            String issue_type = (String) issue_type_form.getSelectedItem();
                            String issue_params = issue_parameters_form.getText();
                            String issue_url = issue_path_form.getText();
                            String issue_intruder = issue_intruder_form.getText();
                            String issue_services = issue_services_form.getText();


                            if (issue_name.equals("")) {
                                JOptionPane.showMessageDialog(null,
                                        "Issue name must not be empty!", "Pentest Collaboration Framework: New issue",
                                        JOptionPane.ERROR_MESSAGE);
                                return;
                            }

                            if (( issue_cvss > 10.0 ||  issue_cvss < 0.0) && issue_criticality.equals("Use CVSS criticality")) {
                                JOptionPane.showMessageDialog(null,
                                        "Issue CVSS must be in 0..10 !", "Pentest Collaboration Framework: New issue", JOptionPane.ERROR_MESSAGE);
                                return;
                            }

                            //Service

                            String[] issue_services_lines = issue_services.split("\n");

                            Service current_service = null;

                            JSONObject services = new JSONObject();
                            JSONArray hostnames = new JSONArray();

                            Boolean result;

                            String hostname_key;

                            String port_id = "0";
                            String hostname_id = "0";


                            int added = 0;

                            for (int i = 0; i < issue_services_lines.length; i++) {
                                if (!issue_services_lines[i].equals("")) {
                                    added++;
                                    current_service = new Service();
                                    result = current_service.Main(issue_services_lines[i]);
                                    hostname_id = current_service.hostname_uuid;
                                    port_id = current_service.port_uuid;
                                    if (!result) return;
                                    if (!services.has(current_service.port_uuid)) {
                                        hostnames = new JSONArray();
                                        if (current_service.hostname_uuid.equals("")) {
                                            hostnames.put("0");
                                            hostname_id = "0";
                                        } else {
                                            hostnames.put(current_service.hostname_uuid);
                                        }
                                        services.put(current_service.port_uuid, hostnames);
                                    } else {
                                        // if exists

                                        if (current_service.hostname_uuid.equals("")) {

                                            if (getKey((JSONArray) services.get(current_service.port_uuid), "0") == null) {
                                                ((JSONArray) services.get(current_service.port_uuid)).put("0");
                                                hostname_id = "0";
                                            }

                                        } else {
                                            if (getKey((JSONArray) services.get(current_service.port_uuid), current_service.hostname_uuid) == null) {
                                                ((JSONArray) services.get(current_service.port_uuid)).put(current_service.hostname_uuid);
                                            }
                                        }
                                    }
                                }
                            }

                            String issue_id = pcf_add_issue(issue_name.getText(), issue_description, issue_fix, issue_url, issue_params,
                                    issue_cvss, services, issue_technical, issue_risks, issue_references,
                                    issue_duplicates, issue_cve, issue_type, issue_status, issue_cwe, issue_intruder);

                            callbacks.printOutput("Added issue: " + issue_id);

                            if (added == 1){
                                upload_selected_screenshots(issue_id, port_id, hostname_id);

                                pcf_add_screenshot(new_screenshot.image, poc_description.getText(), issue_id, port_id, hostname_id);
                            }



                        } else {
                            JOptionPane.showMessageDialog(null,
                                    "Issue name must not be empty!", "Pentest Collaboration Framework: PoC + Issue (fast)", JOptionPane.ERROR_MESSAGE);
                        }
                    }

                }

                public void mouseEntered(MouseEvent e) {
                }

                public void mouseExited(MouseEvent e) {
                }
            });
            listMenuItems.add(menuItem_poc_and_issue_fast);
            menuItem_repeater = new JMenuItem("New PoC");
            menuItem_repeater.addActionListener(new MenuItemListener(ihrrs));
            listMenuItems.add(menuItem_repeater);
            JMenuItem menuItem_new_issue_fast = new JMenuItem("New issue (fast)");
            menuItem_new_issue_fast.addActionListener(new MenuItemListener(ihrrs));
            menuItem_new_issue_fast.addMouseListener(new MouseListener() {
                public void mouseClicked(MouseEvent e) {
                }

                public void mousePressed(MouseEvent e) {
                }

                public void mouseReleased(MouseEvent e) {

                    JTextField issue_name = new JTextField("", 5);

                    Object[] input_fields = {
                            "Issue name:", issue_name
                    };


                    int option = JOptionPane.showConfirmDialog(null, input_fields,
                            "Pentest Collaboration Framework: New Issue (fast)", JOptionPane.OK_CANCEL_OPTION);

                    if (option == JOptionPane.OK_OPTION) {
                        if (issue_name.getText() != null && !issue_name.getText().equals("")) {

                            var message = invocation.getSelectedMessages()[0];
                            var request = message.getRequest();
                            new_issue_repeater(request, message.getHttpService());


                            issue_name_form.setText(issue_name.getText());

                            String issue_description = issue_description_form.getText();
                            Boolean issue_duplicates = checkbox_issue_duplicates.isSelected();
                            String issue_fix = issue_fix_form.getText();
                            String issue_technical = issue_technical_form.getText();
                            String issue_risks = issue_risks_form.getText();
                            String issue_references = issue_references_form.getText();

                            callbacks.printOutput("1");
                            Float issue_cvss = Float.parseFloat(issue_cvss_form.getValue().toString());
                            callbacks.printOutput("2");
                            String issue_criticality = (String) issue_criticality_form.getSelectedItem();
                            String issue_cve = issue_cve_form.getText();
                            Integer issue_cwe = (Integer) issue_cwe_form.getValue();
                            String issue_status = (String) issue_status_form.getSelectedItem();
                            String issue_type = (String) issue_type_form.getSelectedItem();
                            String issue_params = issue_parameters_form.getText();
                            String issue_url = issue_path_form.getText();
                            String issue_intruder = issue_intruder_form.getText();
                            String issue_services = issue_services_form.getText();


                            if (issue_name.getText().equals("")) {
                                JOptionPane.showMessageDialog(null,
                                        "Issue name must not be empty!", "Pentest Collaboration Framework: New issue",
                                        JOptionPane.ERROR_MESSAGE);
                                return;
                            }

                            if (( issue_cvss > 10.0 ||  issue_cvss < 0.0) && issue_criticality.equals("Use CVSS criticality")) {
                                JOptionPane.showMessageDialog(null,
                                        "Issue CVSS must be in 0..10 !", "Pentest Collaboration Framework: New issue", JOptionPane.ERROR_MESSAGE);
                                return;
                            }

                            //Service

                            String[] issue_services_lines = issue_services.split("\n");

                            Service current_service = null;

                            JSONObject services = new JSONObject();
                            JSONArray hostnames = new JSONArray();

                            Boolean result;

                            String hostname_key;


                            for (int i = 0; i < issue_services_lines.length; i++) {
                                if (!issue_services_lines[i].equals("")) {
                                    current_service = new Service();
                                    result = current_service.Main(issue_services_lines[i]);
                                    if (!result) return;
                                    if (!services.has(current_service.port_uuid)) {
                                        hostnames = new JSONArray();
                                        if (current_service.hostname_uuid.equals("")) {
                                            hostnames.put("0");
                                        } else {
                                            hostnames.put(current_service.hostname_uuid);
                                        }
                                        services.put(current_service.port_uuid, hostnames);
                                    } else {
                                        // if exists

                                        if (current_service.hostname_uuid.equals("")) {

                                            if (getKey((JSONArray) services.get(current_service.port_uuid), "0") == null) {
                                                ((JSONArray) services.get(current_service.port_uuid)).put("0");
                                            }

                                        } else {
                                            if (getKey((JSONArray) services.get(current_service.port_uuid), current_service.hostname_uuid) == null) {
                                                ((JSONArray) services.get(current_service.port_uuid)).put(current_service.hostname_uuid);
                                            }
                                        }
                                    }
                                }
                            }

                            String issue_id = pcf_add_issue(issue_name.getText(), issue_description, issue_fix, issue_url, issue_params,
                                    issue_cvss, services, issue_technical, issue_risks, issue_references,
                                    issue_duplicates, issue_cve, issue_type, issue_status, issue_cwe, issue_intruder);

                            callbacks.printOutput("Added issue: " + issue_id);


                        } else {
                            JOptionPane.showMessageDialog(null,
                                    "Issue name must not be empty!", "Pentest Collaboration Framework: PoC + Issue (fast)", JOptionPane.ERROR_MESSAGE);
                            return;
                        }
                    }

                }

                public void mouseEntered(MouseEvent e) {
                }

                public void mouseExited(MouseEvent e) {
                }
            });
            listMenuItems.add(menuItem_new_issue_fast);
            JMenuItem menuItem_request = new JMenuItem("New Issue");
            menuItem_request.addMouseListener(new MouseListener() {
                public void mouseClicked(MouseEvent e) {
                }

                public void mousePressed(MouseEvent e) {
                }

                public void mouseReleased(MouseEvent e) {

                    var message = invocation.getSelectedMessages()[0];
                    var request = message.getRequest();
                    new_issue_repeater(request, message.getHttpService());

                }

                public void mouseEntered(MouseEvent e) {
                }

                public void mouseExited(MouseEvent e) {
                }
            });
            listMenuItems.add(menuItem_request);
        } else if (invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_PROXY) {
            burp.IScanIssue[] ihrrs;
            ihrrs = invocation.getSelectedIssues();
            JMenuItem menuItem_repeater;
            menuItem_repeater = new JMenuItem("New issue");
            menuItem_repeater.addActionListener(new MenuItemListener(ihrrs));
            listMenuItems.add(menuItem_repeater);
        }
        return listMenuItems;
    }

    private JSONArray concat_json_Array(JSONArray arr1, JSONArray arr2)
            throws JSONException {
        JSONArray result = new JSONArray();
        for (int i = 0; i < arr1.length(); i++) {
            result.put(arr1.get(i));
        }
        for (int i = 0; i < arr2.length(); i++) {
            result.put(arr2.get(i));
        }
        return result;
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {

    }

    class MenuItemListener implements ActionListener {

        private final burp.IScanIssue[] ihrrs;

        private IHttpRequestResponse requestResponse;

        public MenuItemListener(burp.IScanIssue[] ihrrs) {
            this.ihrrs = ihrrs;
        }


        public BufferedImage screenshot() {

            Frame burp_window = getBurpFrame();

            BufferedImage buffer = new BufferedImage(burp_window.getWidth(), burp_window.getHeight(), BufferedImage.TYPE_INT_RGB);
            burp_window.paint(buffer.createGraphics());
            return buffer;

        }


        @Override
        public void actionPerformed(ActionEvent ae) {


            String button_text = ((JMenuItem) ae.getSource()).getText();

            callbacks.printOutput("Clicked: " + button_text);


            if (button_text.equals("New issue")) {


                JSONObject cwe_dict = new JSONObject(cwe_json);

                try {

                    for (burp.IScanIssue issue_obj : this.ihrrs) {
                        String issue_name = ((issue_obj.getIssueName() == null) ? "" : issue_obj.getIssueName());
                        Number issue_burp_num = issue_obj.getIssueType();
                        String issue_severity = ((issue_obj.getSeverity() == null) ? "Information" : issue_obj.getSeverity()); // "High", "Medium", "Low", "Information" or "False positive".
                        int issue_type = issue_obj.getIssueType();
                        Number issue_cwe = 0;
                        JSONArray cwe_list;
                        String issue_background = ((issue_obj.getIssueBackground() == null) ? "" : issue_obj.getIssueBackground());
                        String issue_rem_background = ((issue_obj.getRemediationBackground() == null) ? "" : issue_obj.getRemediationBackground());
                        String issue_details = ((issue_obj.getIssueDetail() == null) ? "" : issue_obj.getIssueDetail());
                        String issue_rem_details = ((issue_obj.getRemediationDetail() == null) ? "" : issue_obj.getRemediationDetail());
                        burp.IHttpRequestResponse[] issue_http_messages;
                        issue_http_messages = issue_obj.getHttpMessages();
                        burp.IHttpService issue_service = issue_obj.getHttpService();

                        if (cwe_dict.has(String.valueOf(issue_burp_num))) {

                            cwe_list = cwe_dict.getJSONArray(String.valueOf(issue_burp_num));

                            if (cwe_list.length() > 0) {
                                issue_cwe = cwe_list.getInt(0);
                            }

                        }


                        callbacks.printOutput("Issue name: " + issue_name);
                        callbacks.printOutput("Issue cwe: " + issue_cwe);
                        callbacks.printOutput("Severity: " + issue_severity);
                        callbacks.printOutput("Background: " + issue_background);
                        callbacks.printOutput("Rem Background: " + issue_rem_background);
                        callbacks.printOutput("Details: " + issue_details);
                        callbacks.printOutput("Rem details: " + issue_rem_details);
                        callbacks.printOutput("Service: " + issue_service);

                        if (issue_name.equals("")) {
                            return;
                        }

                        String f_description = issue_details;
                        if (f_description == null) {
                            f_description = "";
                            if (issue_background != null) {
                                f_description = issue_background;
                            }
                        }

                        String f_solution = issue_rem_details;

                        if (f_solution == null) {
                            f_solution = "";
                            if (issue_rem_background != null) {
                                f_solution = issue_rem_background;
                            }
                        }

                        Number cvss = 0.0;
                        switch (issue_severity) {
                            case "High":
                                cvss = 10.0;
                                break;
                            case "Medium":
                                cvss = 5.0;
                            case "Low":
                                cvss = 3.0;
                                break;
                            default:
                                cvss = 0.0;
                                break;
                        }

                        issue_name_form.setText(issue_name);
                        issue_cvss_form.setValue(cvss);
                        issue_description_form.setText(Jsoup.parse(issue_details).wholeText().trim().replace("\r\n", "\n").replace("\n\n", "\n"));
                        issue_fix_form.setText(Jsoup.parse(issue_rem_background).wholeText().trim().replace("\r\n", "\n").replace("\n\n", "\n"));
                        issue_technical_form.setText(Jsoup.parse(issue_background).wholeText().trim().replace("\r\n", "\n").replace("\n\n", "\n"));

                        issue_cwe_form.setValue(issue_cwe);

                        JTabbedPane tp = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
                        int tIndex = getTabIndex(BurpExtender.this);
                        changeTabColour(tp, tIndex, true);

                        String services = "";

                        String params = "";

                        String param_type = "";


                        for (burp.IHttpRequestResponse request : issue_http_messages) {
                            try {
                                params = "";
                                burp.IHttpService service = request.getHttpService();
                                String ip = service.getHost();
                                InetAddress ip_obj = InetAddress.getByName(ip);

                                String real_ip = ip_obj.getHostAddress();
                                String real_hostname = "";
                                if (!real_ip.equals(ip)) {
                                    real_hostname = ip_obj.getHostName();
                                }

                                Integer port = service.getPort();
                                String protocol = service.getProtocol();

                                services = services + "\n" + protocol + "://" + real_ip + ":" + String.valueOf(port);
                                if (!real_hostname.equals("")) {
                                    services = services + "(" + real_hostname + ")";
                                }

                                burp.IRequestInfo reqInfo = helpers.analyzeRequest(request);
                                burp.IResponseInfo resInfo = helpers.analyzeResponse(request.getResponse());
                                String req_path = reqInfo.getUrl().getPath();

                                issue_path_form.setText(req_path);

                                String method = reqInfo.getMethod();
                                reqInfo.getParameters();

                                for (IParameter parameter : reqInfo.getParameters()) {

                                    System.out.println(parameter.getType() + " " + parameter.getName() + " " + parameter.getValue());
                                    switch (parameter.getType()) {
                                        case (IParameter.PARAM_BODY):
                                            param_type = "(POST)";
                                            break;
                                        case (IParameter.PARAM_COOKIE):
                                            param_type = "(COOKIE)";
                                            break;
                                        case (IParameter.PARAM_JSON):
                                            param_type = "(POST-JSON)";
                                            break;
                                        case (IParameter.PARAM_URL):
                                            param_type = "(GET)";
                                            break;
                                        case (IParameter.PARAM_XML):
                                            param_type = "(POST-XML)";
                                            break;
                                        case (IParameter.PARAM_XML_ATTR):
                                            param_type = "(POST-XML-ATTR)";
                                            break;
                                        case (IParameter.PARAM_MULTIPART_ATTR):
                                            param_type = "(POST-MULTIPART)";
                                            break;
                                        default:
                                            param_type = "";
                                            break;
                                    }
                                    params = params + param_type + parameter.getName() + "=" + parameter.getValue() + ", ";


                                }
                                if (params.equals("")) {
                                    //issue_parameters_form.setText("(" + method + ")");
                                } else {
                                    issue_parameters_form.setText(params);
                                }

                            } catch (Exception e) {
                                callbacks.printOutput("Error: " + e);
                            }
                        }

                        services = services.trim();
                        issue_services_form.setText(services);

                        issue_intruder_form.setWrapStyleWord(true);
                        issue_intruder_form.setLineWrap(true);

                        issue_criticality_form.setSelectedIndex(0);

                    }
                } catch (Exception e) {
                    callbacks.printError(e.toString());
                }

            } else if (button_text.equals("New PoC")) {

                Screenshot new_screenshot = new Screenshot();

                // Retrieve Image
                BufferedImage buffer = screenshot();
                // Here you can rotate your image as you want (making your magic)
                new_screenshot.Main("", buffer);

                callbacks.printOutput("New screenshot: " + new_screenshot.image);

                DefaultTableModel model = (DefaultTableModel) screenshots_table.getModel();

                Image image = new_screenshot.image; // transform it
                Image newimg = image.getScaledInstance(300, 300, Image.SCALE_SMOOTH); // scale it the smooth way
                ImageIcon icon = new ImageIcon(newimg);


                String description = (String) JOptionPane.showInputDialog(null,
                        "PoC Description", "Pentest Collaboration Framework",
                        JOptionPane.INFORMATION_MESSAGE, icon,
                        null, "");

                callbacks.printOutput("PoC description: " + description);

                if (description != null) {
                    new_screenshot.description = description;
                    add_screenshot(new_screenshot);
                }


            } else if (button_text.equals("New issue (fast)")) {

                JSONObject cwe_dict = new JSONObject(cwe_json);

                try {

                    for (burp.IScanIssue issue_obj : this.ihrrs) {
                        String issue_name = ((issue_obj.getIssueName() == null) ? "" : issue_obj.getIssueName());
                        Number issue_burp_num = issue_obj.getIssueType();
                        String issue_severity = ((issue_obj.getSeverity() == null) ? "Information" : issue_obj.getSeverity()); // "High", "Medium", "Low", "Information" or "False positive".
                        int issue_type = issue_obj.getIssueType();
                        Number issue_cwe = 0;
                        JSONArray cwe_list;
                        String issue_background = ((issue_obj.getIssueBackground() == null) ? "" : issue_obj.getIssueBackground());
                        String issue_rem_background = ((issue_obj.getRemediationBackground() == null) ? "" : issue_obj.getRemediationBackground());
                        String issue_details = ((issue_obj.getIssueDetail() == null) ? "" : issue_obj.getIssueDetail());
                        String issue_rem_details = ((issue_obj.getRemediationDetail() == null) ? "" : issue_obj.getRemediationDetail());
                        burp.IHttpRequestResponse[] issue_http_messages;
                        issue_http_messages = issue_obj.getHttpMessages();
                        burp.IHttpService issue_service = issue_obj.getHttpService();

                        if (cwe_dict.has(String.valueOf(issue_burp_num))) {

                            cwe_list = cwe_dict.getJSONArray(String.valueOf(issue_burp_num));

                            if (cwe_list.length() > 0) {
                                issue_cwe = cwe_list.getInt(0);
                            }

                        }


                        callbacks.printOutput("Issue name: " + issue_name);
                        callbacks.printOutput("Issue cwe: " + issue_cwe);
                        callbacks.printOutput("Severity: " + issue_severity);
                        callbacks.printOutput("Background: " + issue_background);
                        callbacks.printOutput("Rem Background: " + issue_rem_background);
                        callbacks.printOutput("Details: " + issue_details);
                        callbacks.printOutput("Rem details: " + issue_rem_details);
                        callbacks.printOutput("Service: " + issue_service);

                        if (issue_name.equals("")) {
                            return;
                        }

                        String f_description = issue_details;
                        if (f_description == null) {
                            f_description = "";
                            if (issue_background != null) {
                                f_description = issue_background;
                            }
                        }

                        String f_solution = issue_rem_details;

                        if (f_solution == null) {
                            f_solution = "";
                            if (issue_rem_background != null) {
                                f_solution = issue_rem_background;
                            }
                        }

                        Number cvss = 0.0;
                        switch (issue_severity) {
                            case "High":
                                cvss = 10.0;
                                break;
                            case "Medium":
                                cvss = 5.0;
                            case "Low":
                                cvss = 3.0;
                                break;
                            default:
                                cvss = 0.0;
                                break;
                        }

                        issue_name_form.setText(issue_name);
                        issue_cvss_form.setValue(cvss);
                        issue_description_form.setText(Jsoup.parse(issue_details).wholeText().trim().replace("\r\n", "\n").replace("\n\n", "\n"));
                        issue_fix_form.setText(Jsoup.parse(issue_rem_background).wholeText().trim().replace("\r\n", "\n").replace("\n\n", "\n"));
                        issue_technical_form.setText(Jsoup.parse(issue_background).wholeText().trim().replace("\r\n", "\n").replace("\n\n", "\n"));

                        issue_cwe_form.setValue(issue_cwe);

                        JTabbedPane tp = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
                        int tIndex = getTabIndex(BurpExtender.this);
                        changeTabColour(tp, tIndex, true);

                        String services = "";

                        String params = "";

                        String param_type = "";


                        for (burp.IHttpRequestResponse request : issue_http_messages) {
                            try {
                                params = "";
                                burp.IHttpService service = request.getHttpService();
                                String ip = service.getHost();
                                InetAddress ip_obj = InetAddress.getByName(ip);

                                String real_ip = ip_obj.getHostAddress();
                                String real_hostname = "";
                                if (!real_ip.equals(ip)) {
                                    real_hostname = ip_obj.getHostName();
                                }

                                Integer port = service.getPort();
                                String protocol = service.getProtocol();

                                services = services + "\n" + protocol + "://" + real_ip + ":" + String.valueOf(port);
                                if (!real_hostname.equals("")) {
                                    services = services + "(" + real_hostname + ")";
                                }

                                burp.IRequestInfo reqInfo = helpers.analyzeRequest(request);
                                burp.IResponseInfo resInfo = helpers.analyzeResponse(request.getResponse());
                                String req_path = reqInfo.getUrl().getPath();

                                issue_path_form.setText(req_path);

                                String method = reqInfo.getMethod();
                                reqInfo.getParameters();

                                for (IParameter parameter : reqInfo.getParameters()) {

                                    System.out.println(parameter.getType() + " " + parameter.getName() + " " + parameter.getValue());
                                    switch (parameter.getType()) {
                                        case (IParameter.PARAM_BODY):
                                            param_type = "(POST)";
                                            break;
                                        case (IParameter.PARAM_COOKIE):
                                            param_type = "(COOKIE)";
                                            break;
                                        case (IParameter.PARAM_JSON):
                                            param_type = "(POST-JSON)";
                                            break;
                                        case (IParameter.PARAM_URL):
                                            param_type = "(GET)";
                                            break;
                                        case (IParameter.PARAM_XML):
                                            param_type = "(POST-XML)";
                                            break;
                                        case (IParameter.PARAM_XML_ATTR):
                                            param_type = "(POST-XML-ATTR)";
                                            break;
                                        case (IParameter.PARAM_MULTIPART_ATTR):
                                            param_type = "(POST-MULTIPART)";
                                            break;
                                        default:
                                            param_type = "";
                                            break;
                                    }
                                    params = params + param_type + parameter.getName() + "=" + parameter.getValue() + ", ";


                                }
                                if (params.equals("")) {
                                    //issue_parameters_form.setText("(" + method + ")");
                                } else {
                                    issue_parameters_form.setText(params);
                                }

                            } catch (Exception e) {
                                callbacks.printOutput("Error: " + e);
                            }
                        }

                        services = services.trim();
                        issue_services_form.setText(services);

                        issue_intruder_form.setWrapStyleWord(true);
                        issue_intruder_form.setLineWrap(true);

                        issue_criticality_form.setSelectedIndex(0);

                        String issue_name1 = issue_name_form.getText();
                        String issue_description = issue_description_form.getText();
                        Boolean issue_duplicates = checkbox_issue_duplicates.isSelected();
                        String issue_fix = issue_fix_form.getText();
                        String issue_technical = issue_technical_form.getText();
                        String issue_risks = issue_risks_form.getText();
                        String issue_references = issue_references_form.getText();

                        callbacks.printOutput("1");
                        Float issue_cvss = Float.parseFloat(issue_cvss_form.getValue().toString());
                        callbacks.printOutput("2");
                        String issue_criticality = (String) issue_criticality_form.getSelectedItem();
                        String issue_cve = issue_cve_form.getText();
                        Integer issue_cwe1 = (Integer) issue_cwe_form.getValue();
                        String issue_status = (String) issue_status_form.getSelectedItem();
                        String issue_type1 = (String) issue_type_form.getSelectedItem();
                        String issue_params = issue_parameters_form.getText();
                        String issue_url = issue_path_form.getText();
                        String issue_intruder = issue_intruder_form.getText();
                        String issue_services = issue_services_form.getText();


                        if (issue_name.equals("")) {
                            JOptionPane.showMessageDialog(null,
                                    "Issue name must not be empty!", "Pentest Collaboration Framework: New issue",
                                    JOptionPane.ERROR_MESSAGE);
                            return;
                        }

                        if (( issue_cvss > 10.0 ||  issue_cvss < 0.0) && issue_criticality.equals("Use CVSS criticality")) {
                            JOptionPane.showMessageDialog(null,
                                    "Issue CVSS must be in 0..10 !", "Pentest Collaboration Framework: New issue", JOptionPane.ERROR_MESSAGE);
                            return;
                        }

                        //Service

                        String[] issue_services_lines = issue_services.split("\n");

                        Service current_service = null;

                        JSONObject services1 = new JSONObject();
                        JSONArray hostnames = new JSONArray();

                        Boolean result;

                        String hostname_key;


                        for (int i = 0; i < issue_services_lines.length; i++) {
                            if (!issue_services_lines[i].equals("")) {
                                current_service = new Service();
                                result = current_service.Main(issue_services_lines[i]);
                                if (!result) return;
                                if (!services1.has(current_service.port_uuid)) {
                                    hostnames = new JSONArray();
                                    if (current_service.hostname_uuid.equals("")) {
                                        hostnames.put("0");
                                    } else {
                                        hostnames.put(current_service.hostname_uuid);
                                    }
                                    services1.put(current_service.port_uuid, hostnames);
                                } else {
                                    // if exists

                                    if (current_service.hostname_uuid.equals("")) {

                                        if (getKey((JSONArray) services1.get(current_service.port_uuid), "0") == null) {
                                            ((JSONArray) services1.get(current_service.port_uuid)).put("0");
                                        }

                                    } else {
                                        if (getKey((JSONArray) services1.get(current_service.port_uuid), current_service.hostname_uuid) == null) {
                                            ((JSONArray) services1.get(current_service.port_uuid)).put(current_service.hostname_uuid);
                                        }
                                    }
                                }
                            }
                        }

                        String issue_id = pcf_add_issue(issue_name1, issue_description, issue_fix, issue_url, issue_params,
                                issue_cvss, services1, issue_technical, issue_risks, issue_references,
                                issue_duplicates, issue_cve, issue_type1, issue_status, issue_cwe1, issue_intruder);

                        callbacks.printOutput("Added issue: " + issue_id);

                    }
                } catch (Exception e) {
                    callbacks.printError(e.toString());
                }


            } else if (button_text.equals("Request -> Issue")) {


                callbacks.printOutput(callbacks.getToolName(IBurpExtenderCallbacks.TOOL_REPEATER));


                //this.requestResponse = []

            } else if (button_text.equals("PoC + Issue")) {

            }

        }
    }


    public void set_clipboard_screenshot(BufferedImage elem) {
        TransferableImage trans = new TransferableImage(elem);
        Clipboard c = Toolkit.getDefaultToolkit().getSystemClipboard();
        c.setContents(trans, this);
    }

    public void new_issue_repeater(byte[] request, IHttpService service) {

        String protocol = service.getProtocol();


        var request_obj = callbacks.getHelpers().analyzeRequest(request);


        String path = "";

        try {
            path = request_obj.getUrl().getPath();
        } catch (Exception err) {
            if (request_obj.getHeaders().size() > 0) {
                String firstLine = request_obj.getHeaders().get(0); //first line
                String[] tmp = firstLine.split(" ");
                if (tmp.length == 3)
                    path = tmp[1];
                path = path.split("#")[0];
                path = path.split("\\?")[0];

            }
        }

        issue_name_form.setText("");
        issue_cvss_form.setValue(0);
        issue_description_form.setText("");
        issue_fix_form.setText("");
        issue_risks_form.setText("");
        issue_technical_form.setText("");
        issue_cwe_form.setValue(0);
        issue_references_form.setText("");
        issue_cve_form.setText("");
        issue_path_form.setText(path);

        for (IParameter parameter : request_obj.getParameters()) {
            callbacks.printOutput(parameter.getType() + " " + parameter.getName() + " " + parameter.getValue());
        }


        String params = "";
        String param_type;


        for (IParameter parameter : request_obj.getParameters()) {

            switch (parameter.getType()) {
                case (IParameter.PARAM_BODY):
                    param_type = "(POST)";
                    break;
                case (IParameter.PARAM_COOKIE):
                    param_type = "(COOKIE)";
                    break;
                case (IParameter.PARAM_JSON):
                    param_type = "(POST-JSON)";
                    break;
                case (IParameter.PARAM_URL):
                    param_type = "(GET)";
                    break;
                case (IParameter.PARAM_XML):
                    param_type = "(POST-XML)";
                    break;
                case (IParameter.PARAM_XML_ATTR):
                    param_type = "(POST-XML-ATTR)";
                    break;
                case (IParameter.PARAM_MULTIPART_ATTR):
                    param_type = "(POST-MULTIPART)";
                    break;
                default:
                    param_type = "";
                    break;
            }
            params = params + param_type + parameter.getName() + "=" + parameter.getValue() + ", ";
        }

        issue_parameters_form.setText(params);

        String ip = service.getHost();
        InetAddress ip_obj = null;
        String services = "";
        try {
            ip_obj = InetAddress.getByName(ip);
            String real_ip = ip_obj.getHostAddress();
            String real_hostname = "";
            if (!real_ip.equals(ip)) {
                real_hostname = ip_obj.getHostName();
            }

            Integer port = service.getPort();

            services = services + "\n" + protocol + "://" + real_ip + ":" + String.valueOf(port);
            if (!real_hostname.equals("")) {
                services = services + "(" + real_hostname + ")";
            }
        } catch (UnknownHostException ex) {
            ex.printStackTrace();
        }

        services = services.trim();
        issue_services_form.setText(services);

        issue_criticality_form.setSelectedIndex(0);
    }

    public void add_screenshot(Screenshot new_screenshot) {
        DefaultTableModel model = (DefaultTableModel) screenshots_table.getModel();
        Icon icon_delete = UIManager.getIcon("DesktopIcon.closeIcon");
        Icon icon_view = UIManager.getIcon("Tree.openIcon");
        Icon icon_copy = UIManager.getIcon("Tree.leafIcon");
        Icon icon_save = UIManager.getIcon("FileView.floppyDriveIcon");

        Image image = new_screenshot.image; // transform it
        Image newimg = image.getScaledInstance(300, 300, Image.SCALE_SMOOTH); // scale it the smooth way
        ImageIcon icon = new ImageIcon(newimg);

        model.addRow(new Object[]{
                true,
                new_screenshot.description,
                icon,
                icon_view,
                icon_save,
                icon_copy,
                icon_delete,
                new_screenshot.id
        });

        screenshot_list.add(new_screenshot);
        screenshots_table.setRowHeight(100);

        Action delete = new AbstractAction() {
            public void actionPerformed(ActionEvent e) {

                int result = JOptionPane.showConfirmDialog(null, "Are you sure to delete PoC?",
                        "Pentest Collaboration Framework",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE);
                if (result == JOptionPane.YES_OPTION) {
                    callbacks.printOutput("Delete row");

                    //delete row
                    JTable table = (JTable) e.getSource();
                    int modelRow = Integer.parseInt(e.getActionCommand());

                    String poc_id = (String) table.getModel().getValueAt(table.convertRowIndexToModel(modelRow), 7);

                    ((DefaultTableModel) table.getModel()).removeRow(modelRow);

                    Screenshot elem = null;
                    Integer index = -1;

                    callbacks.printOutput("Length of screenshots array: " + screenshot_list.size());

                    //delete element from array
                    for (int i = 0; i < screenshot_list.size(); i++) {

                        // if the index is
                        // the removal element index
                        if (screenshot_list.get(i).id.equals(poc_id)) {
                            callbacks.printOutput("Screenshot found!");
                            elem = screenshot_list.get(i);
                            index = i;
                        }
                    }

                    callbacks.printOutput("Index: " + index);

                    screenshot_list.remove(elem);

                    callbacks.printOutput("Length of screenshots array: " + screenshot_list.size());


                }


            }
        };

        Action view_action = new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                callbacks.printOutput("View row");

                JTable table = (JTable) e.getSource();
                int modelRow = Integer.parseInt(e.getActionCommand());

                String poc_id = (String) table.getModel().getValueAt(table.convertRowIndexToModel(modelRow), 7);


                Screenshot elem = null;
                Integer index = -1;

                for (int i = 0, k = 0; i < screenshot_list.size(); i++) {

                    // if the index is
                    // the removal element index
                    if (screenshot_list.get(i).id.equals(poc_id)) {
                        callbacks.printOutput("Screenshot found!");
                        elem = screenshot_list.get(i);
                        index = i;
                    }
                }

                ImageIcon imageIcon = new ImageIcon(elem.image);

                JOptionPane.showOptionDialog(null, null, "Inspect screenshot", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, imageIcon, new Object[]{}, null);


            }
        };

        Action save_action = new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                callbacks.printOutput("Save row");

                JTable table = (JTable) e.getSource();
                int modelRow = Integer.parseInt(e.getActionCommand());

                String poc_id = (String) table.getModel().getValueAt(table.convertRowIndexToModel(modelRow), 7);


                Screenshot elem = null;
                Integer index = -1;

                for (int i = 0, k = 0; i < screenshot_list.size(); i++) {

                    // if the index is
                    // the removal element index
                    if (screenshot_list.get(i).id.equals(poc_id)) {
                        callbacks.printOutput("Screenshot found!");
                        elem = screenshot_list.get(i);
                        index = i;
                    }
                }


                JFrame parentFrame = new JFrame();

                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setSelectedFile(new File("screenshot.png"));
                fileChooser.setDialogTitle("Specify a file to save");

                int userSelection = fileChooser.showSaveDialog(parentFrame);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    System.out.println("Save as file: " + fileToSave.getAbsolutePath());
                    try {
                        ImageIO.write(elem.image, "png", new File(fileToSave.getAbsolutePath()));
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }


            }
        };

        Action copy_action = new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                callbacks.printOutput("Copy row");

                JTable table = (JTable) e.getSource();
                int modelRow = Integer.parseInt(e.getActionCommand());

                String poc_id = (String) table.getModel().getValueAt(table.convertRowIndexToModel(modelRow), 7);


                Screenshot elem = null;
                Integer index = -1;

                for (int i = 0, k = 0; i < screenshot_list.size(); i++) {

                    // if the index is
                    // the removal element index
                    if (screenshot_list.get(i).id.equals(poc_id)) {
                        callbacks.printOutput("Screenshot found!");
                        elem = screenshot_list.get(i);
                        index = i;
                    }
                }

                set_clipboard_screenshot(elem.image);

            }
        };

        ButtonColumn buttonColumn = new ButtonColumn(screenshots_table, delete, 6);
        buttonColumn = new ButtonColumn(screenshots_table, view_action, 3);

        buttonColumn = new ButtonColumn(screenshots_table, save_action, 4);

        buttonColumn = new ButtonColumn(screenshots_table, copy_action, 5);

    }

    public String generate_token() {
        String real_email = this.email.getText();
        String real_password = this.password.getText();
        JSONObject jo = new JSONObject();
        jo.put("name", "BurpSuite API token");
        jo.put("email", real_email);
        jo.put("password", real_password);
        jo.put("duration", 2592000);

        JSONObject result_json = pcf_request("api/v1/create_token", jo);

        if (result_json.has("access_token")) {
            token.setText(result_json.optString("access_token"));
            l_empty6.setText("Got API key for 30 days!");
        } else {
            l_empty6.setText("Wrong credentials!");
        }

        return "";
    }

    void pcf_get_projects() {
        String token_s = token.getText();
        JSONObject jo = new JSONObject();
        jo.put("access_token", token_s);

        JSONArray projects_json = pcf_request("api/v1/projects", jo).getJSONArray("projects");
        list_projects.removeAllItems();
        for (int i = 0; i < projects_json.length(); i++) {
            JSONObject current_project = projects_json.getJSONObject(i);
            if (current_project.getString("status").equals("active")) {
                list_projects.addItem(new ComboItem(current_project.getString("name") + " (" + current_project.getString("id") + ")", current_project.getString("id")));
            }
        }

        return;

    }

    public String pcf_add_host(String ip) {
        JSONObject host_obj = pcf_get_host_by_ip(ip);

        if (host_obj != null) {
            return host_obj.getString("id");
        }

        String project_uuid_s = ((ComboItem) list_projects.getSelectedItem()).getValue();
        JSONObject jo = new JSONObject();
        String access_token = this.token.getText();
        jo.put("access_token", access_token);
        jo.put("ip", ip);
        jo.put("description", "Added from BurpSuite");
        String path = "api/v1/project/" + project_uuid_s + "/host/new";
        return pcf_request(path, jo).getString("host_id");
    }

    public static String imgToBase64String(final RenderedImage img, final String formatName) {
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (final OutputStream b64os = Base64.getEncoder().wrap(os)) {
            ImageIO.write(img, formatName, b64os);
        } catch (final IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
        return os.toString();
    }

    public String pcf_add_screenshot(BufferedImage screenshot,String description, String issue_id, String port_id, String hostname_id) {


        String project_uuid_s = ((ComboItem) list_projects.getSelectedItem()).getValue();

        String b64content = imgToBase64String(screenshot, "png");

        JSONObject jo = new JSONObject();
        String access_token = this.token.getText();
        jo.put("access_token", access_token);
        jo.put("description", description);
        jo.put("type", "image");
        jo.put("b64content", b64content);
        if (!port_id.equals("") && !hostname_id.equals("")){
            jo.put("port_id", port_id);
            jo.put("hostname_id", hostname_id);
        }
        String path = "api/v1/project/" + project_uuid_s + "/issues/" + issue_id + "/poc/add";
        return pcf_request(path, jo).getString("poc_id");
    }

    public void upload_selected_screenshots(String issue_id, String port_id, String hostname_id){
        //screenshots_table
        Object[] columnData = new Object[screenshots_table.getRowCount()];
        Boolean is_selected = false;
        String description = "";
        String poc_id = "";

        int added = 0;

        for (int i = 0; i < screenshots_table.getRowCount(); i++) {  // Loop through the rows
            // Record the 5th column value (index 4)
            is_selected = (Boolean) screenshots_table.getModel().getValueAt(i, 0);
            description = (String) screenshots_table.getModel().getValueAt(i, 1);
            poc_id = (String) screenshots_table.getModel().getValueAt(i, 7);
            Integer index = -1;

            Screenshot screen_obj = null;

            if (is_selected) {

                //delete element from array
                for (int x = 0; x < screenshot_list.size(); x++) {

                    // if the index is
                    // the removal element index
                    if (screenshot_list.get(x).id.equals(poc_id)) {
                        callbacks.printOutput("Screenshot found!");
                        screen_obj = screenshot_list.get(i);
                    }
                }

                if (screen_obj != null) {
                    pcf_add_screenshot(screen_obj.image, description, issue_id, port_id, hostname_id);
                    added++;
                }
            }
        }

        callbacks.printOutput("Added "+added + " screenshots!");
    }

    public String pcf_add_hostname(String host_id, String hostname, String description) {

        String project_uuid_s = ((ComboItem) list_projects.getSelectedItem()).getValue();

        JSONObject jo = new JSONObject();
        String access_token = this.token.getText();
        jo.put("access_token", access_token);
        jo.put("host_id", host_id);
        jo.put("description", description);
        jo.put("hostname", hostname);

        String path = "api/v1/project/" + project_uuid_s + "/hostname/add";
        return pcf_request(path, jo).getString("id");
    }

    public BufferedImage loadImage(String fileName){

        BufferedImage buff = null;
        try {
            buff = ImageIO.read(getClass().getClassLoader().getResource(fileName));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        return buff;

    }

    public String pcf_add_port(String host_uuid, int port, String protocol) {
        String access_token = this.token.getText();
        String project_uuid_s = ((ComboItem) list_projects.getSelectedItem()).getValue();
        JSONObject jo = new JSONObject();
        jo.put("access_token", access_token);
        String path = "api/v1/project/" + project_uuid_s + "/host/" + host_uuid + "/info";
        JSONArray ports_list = pcf_request(path, jo).getJSONArray("ports");
        String port_uuid = "";
        for (int i = 0; i < ports_list.length(); i++) {
            JSONObject port_object = ports_list.getJSONObject(i);
            if (port_object.getInt("port") == port) {
                port_uuid = port_object.getString("id");
            }
        }

        if (port_uuid.equals("")) {
            jo = new JSONObject();
            jo.put("access_token", access_token);
            jo.put("port", port);
            jo.put("host_id", host_uuid);
            jo.put("description", "Added from BurpSuite");
            jo.put("service", protocol);
            jo.put("is_tcp", true);
            path = "api/v1/project/" + project_uuid_s + "/port/new";
            port_uuid = pcf_request(path, jo).getString("port_id");
        }
        return port_uuid;
    }

    public String pcf_add_hostname(String host_uuid, String hostname) {
        JSONArray hostnames_list = pcf_get_host_by_id(host_uuid).getJSONArray("hostnames");

        String hostname_uuid = "0";
        for (int i = 0; i < hostnames_list.length(); i++) {
            JSONObject hostname_object = hostnames_list.getJSONObject(i);
            if (hostname_object.getString("hostname").equals(hostname)) {
                hostname_uuid = hostname_object.getString("id");
            }
        }
        return hostname_uuid;
        //TODO: add hostname feature
        /*
        if (hostname_uuid.equals("")) {
            String project_uuid = ((ComboItem)list_projects.getSelectedItem()).getValue();
            JSONObject jo = new JSONObject();
            jo.put("access_token", token);
            jo.put("ip", ip);
            jo.put("description", "Added from BurpSuite");
            String path = "api/v1/project/" + project_uuid + "/host/new";
        }
        return pcf_request(path, jo).getString("host_id");*/
    }

    public String pcf_add_hostname(String ip) {
        String access_token = this.token.getText();
        String project_uuid_s = ((ComboItem) list_projects.getSelectedItem()).getValue();
        JSONObject jo = new JSONObject();
        jo.put("access_token", access_token);
        String path = "api/v1/project/" + project_uuid_s + "/hosts";
        JSONArray hosts_list = pcf_request(path, jo).getJSONArray("hosts");
        String host_uuid = "";
        for (int i = 0; i < hosts_list.length(); i++) {
            JSONObject host_object = hosts_list.getJSONObject(i);
            if (host_object.getString("ip").equals(ip)) {
                host_uuid = host_object.getString("id");
            }
        }

        if (host_uuid.equals("")) {
            jo = new JSONObject();
            jo.put("access_token", token);
            jo.put("ip", ip);
            jo.put("description", "Added from BurpSuite");
            path = "api/v1/project/" + project_uuid_s + "/host/new";
            host_uuid = pcf_request(path, jo).getString("host_id");
        }
        return host_uuid;
    }

    public JSONObject pcf_get_host_by_ip(String ip) {
        String access_token = this.token.getText();
        String project_uuid_s = ((ComboItem) list_projects.getSelectedItem()).getValue();
        JSONObject jo = new JSONObject();
        jo.put("access_token", access_token);
        String path = "api/v1/project/" + project_uuid_s + "/hosts";
        JSONArray hosts_list = pcf_request(path, jo).getJSONArray("hosts");
        String host_uuid = "";
        for (int i = 0; i < hosts_list.length(); i++) {
            JSONObject host_object = hosts_list.getJSONObject(i);
            if (host_object.getString("ip").equals(ip)) {
                return host_object;
            }
        }

        return null;
    }

    public JSONObject pcf_get_host_by_id(String host_uuid) {
        String access_token = this.token.getText();
        String project_uuid_s = ((ComboItem) list_projects.getSelectedItem()).getValue();
        JSONObject jo = new JSONObject();
        jo.put("access_token", access_token);
        String path = "api/v1/project/" + project_uuid_s + "/host/" + host_uuid + "/info";
        JSONObject host_object = pcf_request(path, jo);
        if (host_object.has("id")) {
            return host_object;
        }
        return null;
    }

    public String pcf_add_issue(String name, String description, String fix, String URL, String param,
                                Number cvss, JSONObject services, String technical, String risks, String references,
                                Boolean duplicates_find, String cve, String type, String status, Number cwe, String intruder) {

        JSONObject jo = new JSONObject();
        String access_token = this.token.getText();
        jo.put("access_token", access_token);
        jo.put("cvss", cvss);
        jo.put("name", name);
        jo.put("description", description);
        jo.put("fix", fix);
        jo.put("url_path", URL);
        jo.put("param", param);
        jo.put("services", services);
        jo.put("dublicate_find", duplicates_find);
        jo.put("technical", technical);
        jo.put("risks", risks);
        jo.put("references", references);
        jo.put("type", type);
        jo.put("status", status);
        jo.put("intruder", intruder);
        jo.put("cve", cve);
        jo.put("cwe", cwe);
        String path = "api/v1/project/" + ((ComboItem) list_projects.getSelectedItem()).getValue() + "/issues/create";
        String issue_uuid = pcf_request(path, jo).getString("issue_id");
        return issue_uuid;
    }


    public JSONObject pcf_request(String path, JSONObject json_obj) { //api/v1/create_token
        try {
            String url_string = this.URL_form.getText();
            if (!(url_string.endsWith("/"))) {
                url_string += "/";
            }
            url_string += path;

            String data = new String(json_obj.toString().getBytes());

            String basic_login = this.basic_auth_login.getText();
            String basic_password = this.basic_auth_password.getText();

            callbacks.printOutput("URL: " + url_string);
            callbacks.printOutput("Body: " + data);

            Properties props = System.getProperties();
            props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
            props.setProperty("com.sun.net.ssl.checkRevocation", Boolean.FALSE.toString());


            //######################################################################

            org.apache.http.ssl.SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();
            sslContextBuilder.loadTrustMaterial(new org.apache.http.conn.ssl.TrustSelfSignedStrategy());
            SSLContext sslContext = sslContextBuilder.build();
            org.apache.http.conn.ssl.SSLConnectionSocketFactory sslSocketFactory =
                    new SSLConnectionSocketFactory(sslContext, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

            HttpClientBuilder httpClientBuilder = HttpClients.custom().setSSLSocketFactory(sslSocketFactory);
            //CloseableHttpClient client = httpClientBuilder.build();


            SSLContextBuilder builder = new SSLContextBuilder();
            builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
            SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(builder.build(), NoopHostnameVerifier.INSTANCE);
            Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("http", new PlainConnectionSocketFactory())
                    .register("https", sslConnectionSocketFactory)
                    .build();

            PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(registry);
            cm.setMaxTotal(100);

            RequestConfig.Builder requestBuilder = RequestConfig.custom();
            requestBuilder.setConnectTimeout(5000);
            requestBuilder.setConnectionRequestTimeout(5000);

            //#################################################


            RequestConfig requestConfig = RequestConfig.custom()
                    // Determines the timeout in milliseconds until a connection is established.
                    .setConnectTimeout(5_000)
                    // Defines the socket timeout in milliseconds,
                    // which is the timeout for waiting for data or, put differently,
                    // a maximum period inactivity between two consecutive data packets).
                    .setSocketTimeout(5_000)
                    // Returns the timeout in milliseconds used when requesting a connection
                    // from the connection manager.
                    .setConnectionRequestTimeout(5_000)
                    .build();

            CloseableHttpClient client = HttpClients.custom()
                    .setSSLSocketFactory(sslConnectionSocketFactory)
                    .setConnectionManager(cm)
                    .setDefaultRequestConfig(requestConfig)
                    .build();

            //CloseableHttpClient client = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(url_string);
            httpPost.addHeader("Content-Type", "application/json");
            httpPost.setEntity(new StringEntity(data, "UTF-8"));


            if (!(basic_login.equals("") && basic_password.equals(""))) {
                String auth = basic_login + ":" + basic_password;
                byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes(StandardCharsets.UTF_8));
                String authHeaderValue = "Basic " + new String(encodedAuth);
                httpPost.addHeader("Authorization", authHeaderValue);
            }

            CloseableHttpResponse response = client.execute(httpPost);

            String result = EntityUtils.toString(response.getEntity());

            JSONObject result_json = new JSONObject(result);

            return result_json;
        } catch (Exception e) {
            //
            callbacks.printOutput(e.toString());
            JOptionPane.showMessageDialog(null, "Error during PCF request " + path + ": " + e.toString(),
                    "Pentest Collaboration Framework", JOptionPane.ERROR_MESSAGE);
        }
        return null;
    }

    private Object getKey(JSONArray array, String key) {
        Object value = null;
        for (int i = 0; i < array.length(); i++) {
            JSONObject item = array.getJSONObject(i);
            if (item.keySet().contains(key)) {
                value = item.get(key);
                break;
            }
        }

        return value;
    }

    class Service {

        public String ip = "";
        public String hostname = "";
        public Integer port = 80;
        public Boolean is_tcp = true;
        public String host_uuid = "";
        public String hostname_uuid = "";
        public String port_uuid = "";
        public String protocol = "http";

        public Boolean Main(String service_str) {

            try {
                protocol = service_str.split("://")[0];
                ip = service_str.split("://")[1].split(":")[0];
                port = Integer.valueOf(service_str.split(":")[2].split("\\(")[0]);
                if (service_str.contains("(") && service_str.contains(")")) {
                    hostname = service_str.split("\\(")[1].split("\\)")[0];
                }
                if (port < 0 || port > 65535) {
                    throw new Exception("Wrong port!");
                }

                if (!validate_ip(ip))
                    throw new Exception("Wrong ip!");


                // Check if ip exists
                JSONObject tmp = pcf_get_host_by_ip(ip);
                if (tmp != null)
                    host_uuid = tmp.getString("id");
                else {
                    // create new host
                    host_uuid = pcf_add_host(ip);
                }

                //check if port exists

                port_uuid = pcf_add_port(host_uuid, port, protocol);

                if (!hostname.equals("")) {
                    hostname_uuid = pcf_add_hostname(host_uuid, hostname, "Added from BurpSuite");
                }
                return true;

            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "One of services lines was wrong! Examples: http://1.1.1.1:80(google.com) or https://1.1.1.1:443",
                        "Pentest Collaboration Framework", JOptionPane.ERROR_MESSAGE);
                callbacks.printOutput(e.toString());
                return false;
            }

        }

        public boolean validate_ip(String ip) {
            Pattern PATTERN = Pattern.compile(
                    "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
            return PATTERN.matcher(ip).matches();
        }


    }

    class ComboItem {
        private String key;
        private String value;

        public ComboItem(String key, String value) {
            this.key = key;
            this.value = value;
        }

        @Override
        public String toString() {
            return key;
        }

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }
    }

    private void changeTabColour(JTabbedPane tabbedPane, final int tabIndex, boolean hasInteractions) {
        if (hasInteractions) {
            tabbedPane.setBackgroundAt(tabIndex, new Color(0xff6633));
        } else {
            tabbedPane.setBackgroundAt(tabIndex, defaultTabColour);
        }
    }

    private Color getDefaultTabColour() {
        if (running) {
            JTabbedPane tp = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
            int tIndex = getTabIndex(BurpExtender.this);
            if (tIndex > -1) {
                return tp.getBackgroundAt(tIndex);
            }
            return new Color(0x000000);
        }
        return null;
    }

    private int getTabIndex(ITab your_itab) {
        if (running) {
            JTabbedPane parent = (JTabbedPane) your_itab.getUiComponent().getParent();
            for (int i = 0; i < parent.getTabCount(); ++i) {
                if (parent.getTitleAt(i).contains("PCF")) {
                    return i;
                }
            }
        }
        return -1;
    }


    static String cwe_json = "{0: [], 1048832: [77, 78, 116], 1049088: [89, 94, 116], 1049104: [89, 94, 116], 1049216: [10, 11], 1049344: [22, 23, 35, 36], 1049600: [611], 1049856: [90, 116], 1050112: [94, 116, 159, 643], 1050368: [91, 116, 159, 611, 776], 1050624: [11], 1050880: [650], 1051136: [610, 918], 1051392: [22, 23, 35, 36], 1051648: [94, 116, 159], 1051904: [94, 95, 116], 1052160: [94, 95, 116], 1052416: [94, 95, 116], 1052432: [94, 95, 116], 1052448: [116, 159, 917], 1052672: [94, 95, 116], 1052800: [94, 95, 116], 1052928: [96, 116, 159], 2097408: [79, 80, 116, 159], 2097472: [444], 2097473: [444], 2097536: [436], 2097664: [113], 2097920: [79, 80, 116, 159], 2097928: [116, 159], 2097936: [79, 80, 116, 159], 2097937: [79, 80, 116, 159], 2097938: [79, 80, 116, 159], 2097942: [1321], 2097952: [94, 95, 116], 2097953: [94, 95, 116], 2097954: [94, 95, 116], 2097960: [16], 2097968: [89, 116, 159], 2097969: [89, 116, 159], 2097970: [89, 116, 159], 2097984: [345, 346, 441], 2097985: [345, 346, 441], 2097986: [345, 346, 441], 2098000: [22, 73], 2098001: [22, 73], 2098002: [22, 73], 2098016: [79, 116, 159], 2098017: [79, 116, 159], 2098018: [79, 116, 159], 2098032: [79, 116, 159], 2098033: [79, 116, 159], 2098034: [79, 116, 159], 2098176: [942], 2098432: [942], 2098688: [942], 2098689: [942], 2098690: [942], 2098691: [942], 2098944: [352], 2099200: [93, 159], 2099456: [345, 347], 2099457: [345], 2099458: [], 2099459: [], 2099460: [], 2099461: [], 3145984: [319], 3146240: [918, 406], 3146256: [918, 406], 3146272: [16, 406], 4194560: [16, 213], 4194576: [16], 4194592: [16], 4194816: [204], 4195072: [598], 4195328: [598], 4195456: [598], 4195584: [16], 4195840: [642], 4196096: [776], 4196352: [698], 4196608: [502], 4196864: [16], 4197120: [20, 116], 4197376: [20, 116], 4197632: [20], 4197888: [20], 4198144: [436], 5243008: [1104], 5243136: [601], 5243137: [601], 5243152: [601], 5243153: [601], 5243154: [601], 5243392: [614], 5243648: [16], 5243904: [200], 5244160: [829], 5244416: [16], 5244672: [200, 384, 598], 5244928: [200], 5245184: [287], 5245312: [434], 5245344: [693], 5245360: [16], 5245440: [16], 5245696: [565, 829], 5245697: [565, 829], 5245698: [565, 829], 5245952: [116], 5245953: [116], 5245954: [116], 5246208: [400], 5246209: [400], 5246210: [400], 5246464: [20], 5246465: [20], 5246466: [20], 5246720: [20], 5246721: [20], 5246722: [20], 5246976: [20], 5246977: [20], 5246978: [20], 5246979: [73, 20], 5246980: [73, 20], 5247232: [20], 5247233: [20], 5247234: [20], 5247488: [20], 5247489: [20], 5247490: [20], 5247744: [73, 20], 5247745: [73, 20], 5248000: [233, 20], 5248001: [233, 20], 5248256: [73, 20], 5248257: [73, 20], 6291584: [15, 497], 6291632: [18, 200, 388, 540, 541, 615], 6291672: [530], 6291712: [538, 548], 6291968: [200], 6292224: [200], 6292480: [200], 6292736: [200, 388], 6292816: [200, 388], 6292992: [200], 6293248: [200], 6293504: [200], 7340288: [524, 525], 7340544: [310, 311], 8388864: [436], 8389120: [16, 436], 8389376: [16, 436], 8389632: [16, 436], 8389888: [16], 16777472: [295, 326, 327], 16777728: [326], 16777984: [523], 16778240: [16, 319], 16778496: [912], 134217728: []}";

}


class Screenshot {

    public String description = "";
    public BufferedImage image = null;
    public Boolean is_selected = false;
    public JCheckBox checkbox = null;
    public String id = "";

    public void Main(String description_arg, BufferedImage image_arg) {
        description = description_arg;
        image = image_arg;
        checkbox = new JCheckBox("", true);
        id = random_string();
    }

    public void select() {
        is_selected = true;
    }

    public void deselect() {
        is_selected = false;
    }

    public String random_string() {
        byte[] array = new byte[20]; // length is bounded by 7
        new Random().nextBytes(array);
        return new String(array, Charset.forName("UTF-8"));
    }

}

class TransferableImage implements Transferable {

    Image i;

    public TransferableImage(Image i) {
        this.i = i;
    }

    public Object getTransferData(DataFlavor flavor)
            throws UnsupportedFlavorException, IOException {
        if (flavor.equals(DataFlavor.imageFlavor) && i != null) {
            return i;
        } else {
            throw new UnsupportedFlavorException(flavor);
        }
    }

    public DataFlavor[] getTransferDataFlavors() {
        DataFlavor[] flavors = new DataFlavor[1];
        flavors[0] = DataFlavor.imageFlavor;
        return flavors;
    }

    public boolean isDataFlavorSupported(DataFlavor flavor) {
        DataFlavor[] flavors = getTransferDataFlavors();
        for (int i = 0; i < flavors.length; i++) {
            if (flavor.equals(flavors[i])) {
                return true;
            }
        }

        return false;
    }
}


