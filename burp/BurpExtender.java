
package burp;

import org.apache.http.*;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;


public class BurpExtender implements burp.IBurpExtender, burp.ITab, burp.IContextMenuFactory {

    public PrintWriter stdout;

    private JPanel jPanel1;

    //buttons
    private JButton b_gen_token;
    private JButton b_check_token;
    private JButton b_save_settings;
    private JButton b_save_settings_no_password;
    private JButton b_load_settings;
    private JButton b_projects_list;

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

    ////Input fields
    final JTextArea URL_form = new JTextArea("http://127.0.0.1:5000/", 1, 20);
    final JTextArea basic_auth_login = new JTextArea("admin", 1, 20);
    final JTextArea basic_auth_password = new JTextArea("password", 1, 20);
    final JTextArea project_uuid = new JTextArea("aaaaaaaa-bbbb-cccc-dddd-aaaaaaaaaaaa", 1, 36);
    final JTextArea token = new JTextArea("aaaaaaaa-bbbb-cccc-dddd-aaaaaaaaaaaa", 1, 20);
    final JTextArea email = new JTextArea("root@localhost.com", 1, 20);
    final JTextArea password = new JTextArea("Qwerty1234", 1, 20);

    String[] projects = {};
    JComboBox list_projects = new JComboBox(projects);

    ////Labels
    final JLabel l_url = new JLabel("URL: ");
    final JLabel l_basic_auth_login = new JLabel("Basic login: ");
    final JLabel l_basic_auth_password = new JLabel(" Basic password: ");
    final JLabel l_project_uuid = new JLabel("Project UUID: ");
    final JLabel l_token = new JLabel("API token: ");
    final JLabel l_email = new JLabel("Email: ");
    final JLabel l_password = new JLabel(" Password: ");
    final JLabel l_header = new JLabel("Pentest Collaboration Framework");


    final JLabel l_empty1 = new JLabel(" ");
    final JLabel l_empty2 = new JLabel(" ");
    final JLabel l_empty3 = new JLabel(" ");
    final JLabel l_empty4 = new JLabel(" ");
    final JLabel l_empty5 = new JLabel(" ");
    final JLabel l_empty6 = new JLabel(" ");
    private burp.IBurpExtenderCallbacks callbacks;


    private burp.IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(final burp.IBurpExtenderCallbacks callbacks) {

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.registerContextMenuFactory(this);
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("PCF");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                jPanel1 = new JPanel();
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
                if (!callbacks.loadExtensionSetting("PCF_URL").equals("")) {
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
                b_save_settings = new JButton("\uD83D\uDCBE (+ \uD83D\uDD11)");
                b_save_settings_no_password = new JButton("\uD83D\uDCBE");
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

                jPanel1.add(boxVertical);


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
        basic_auth_login.setText(callbacks.loadExtensionSetting("PCF_BASIC_LOGIN"));
        URL_form.setText(callbacks.loadExtensionSetting("PCF_URL"));
        email.setText(callbacks.loadExtensionSetting("PCF_EMAIL"));
        token.setText(callbacks.loadExtensionSetting("PCF_TOKEN"));
        list_projects.removeAllItems();
        String project_uuid = callbacks.loadExtensionSetting("PCF_PROJECT");
        list_projects.addItem(new ComboItem("Saved project (" + project_uuid + ")", project_uuid));
        password.setText(callbacks.loadExtensionSetting("PCF_PASSWORD"));
        basic_auth_password.setText(callbacks.loadExtensionSetting("PCF_BASIC_PASSWORD"));
    }


    public List<JMenuItem> createMenuItems(final burp.IContextMenuInvocation invocation) {


        List<JMenuItem> listMenuItems = new ArrayList<>();
        // The menu is only displayed in the right-click menu of the Scanner tool
        if (invocation.getToolFlag() == burp.IBurpExtenderCallbacks.TOOL_SCANNER) {

            burp.IScanIssue[] ihrrs;
            ihrrs = invocation.getSelectedIssues();
            JMenuItem menuItem;
            menuItem = new JMenuItem("Add to PCF");
            menuItem.addActionListener(new MenuItemListener(ihrrs));
            listMenuItems.add(menuItem);
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

    class MenuItemListener implements ActionListener {

        private final burp.IScanIssue[] ihrrs;

        //private IHttpRequestResponse[] requestResponse;
        public MenuItemListener(burp.IScanIssue[] ihrrs) {
            this.ihrrs = ihrrs;
        }

        @Override
        public void actionPerformed(ActionEvent ae) {
            try {

                for (burp.IScanIssue issue_obj : this.ihrrs) {
                    String issue_name = issue_obj.getIssueName();
                    String issue_severity = issue_obj.getSeverity(); // "High", "Medium", "Low", "Information" or "False positive".
                    int issue_type = issue_obj.getIssueType();
                    String issue_background = issue_obj.getIssueBackground();
                    String issue_rem_background = issue_obj.getRemediationBackground();
                    String issue_details = issue_obj.getIssueDetail();
                    String issue_rem_details = issue_obj.getRemediationDetail();
                    burp.IHttpRequestResponse[] issue_http_messages;
                    issue_http_messages = issue_obj.getHttpMessages();
                    //burp.IHttpService issue_service = issue_obj.getHttpService();

                    callbacks.printOutput("Issue name: " + issue_name);
                    callbacks.printOutput("Severity: " + issue_severity);
                    callbacks.printOutput("Background: " + issue_background);
                    callbacks.printOutput("Rem Background: " + issue_rem_background);
                    callbacks.printOutput("Details: " + issue_details);
                    callbacks.printOutput("Rem details: " + issue_rem_details);

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

                    JSONObject services = new JSONObject();

                    for (burp.IHttpRequestResponse request : issue_http_messages) {
                        try {
                            burp.IHttpService service = request.getHttpService();
                            String ip = service.getHost();
                            InetAddress ip_obj = InetAddress.getByName(ip);

                            String real_ip = ip_obj.getHostAddress();
                            String real_hostname = "";
                            if (!real_ip.equals(ip)) {
                                real_hostname = ip_obj.getHostName();
                            }

                            String host_uuid = pcf_add_host(real_ip);
                            Integer port = service.getPort();
                            String protocol = service.getProtocol();
                            String port_uuid = pcf_add_port(host_uuid, port, protocol);

                            burp.IRequestInfo reqInfo = helpers.analyzeRequest(request);
                            burp.IResponseInfo resInfo = helpers.analyzeResponse(request.getResponse());
                            String req_path = reqInfo.getUrl().getPath();
                            List<String> req_hostnames = reqInfo.getHeaders();
                            String hostname = "";
                            String hostname_uuid = "0";
                            JSONArray hostnames_json = new JSONArray();
                            if (!real_hostname.equals("")) {
                                hostname_uuid = pcf_add_hostname(host_uuid, real_hostname,"");
                                hostnames_json.put(hostname_uuid);
                            } else {
                                for (String header : req_hostnames) {
                                    if (header.startsWith("Host: ")) {
                                        hostname = header.split("Host: ")[1].strip();
                                        try {
                                            hostname_uuid = pcf_add_hostname(host_uuid, hostname, "");
                                            hostnames_json.put(hostname_uuid);
                                        } catch (Exception e) {
                                        }
                                    }
                                }
                            }

                            if (hostname_uuid.equals("0")){
                                hostnames_json.put(hostname_uuid);
                            }

                            if (!services.has(port_uuid)) {
                                services.put(port_uuid, hostnames_json);
                            } else {
                                services.put(port_uuid, concat_json_Array(services.getJSONArray(port_uuid), hostnames_json));
                            }
                        } catch (Exception e) {

                        }
                    }

                    pcf_add_issue(issue_name, f_description, f_solution, "", "", cvss, services);

                }
            } catch (Exception e) {
                callbacks.printError(e.toString());
            }

        }
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
                                Number cvss, JSONObject services) {
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
        jo.put("dublicate_find", true);
        String path = "api/v1/project/" + ((ComboItem) list_projects.getSelectedItem()).getValue() + "/issues/create";
        String issue_uuid = pcf_request(path, jo).getString("issue_uuid");
        return issue_uuid;
    }


    public JSONObject pcf_request(String path, JSONObject json_obj) { //api/v1/create_token
        try {
            String url_string = this.URL_form.getText();
            if (!(url_string.endsWith("/"))) {
                url_string += "/";
            }
            url_string += path;

            String data = json_obj.toString();

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
            httpPost.setEntity(new StringEntity(data));


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
        }
        return null;
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

}