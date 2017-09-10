
import java.io.*;
import java.net.*;
import java.util.*;
import java.lang.*;
import java.awt.*;

public class ActiveClient extends MessageParserClient implements Runnable {

    public static String MonitorName;
    Thread runner;
    Socket toMonitor = null;
    public static int MONITOR_PORT;
    public static int LOCAL_PORT;
    public int SleepMode;
    int DELAY = 90000;  //Interval after which a new Active Client is started
    long prevTime,present;

    public ActiveClient() {
        super("[no-name]", "[no-password]");
        MonitorName="";
        toMonitor = null;
        MONITOR_PORT=0;
        LOCAL_PORT=0;
    }

    public ActiveClient(String mname, int p, int lp, int sm,
                        String name, String password) {
        super(name, password);
        try {

            System.out.println(" In Active Client Constructor.");
            SleepMode = sm;
            MonitorName = mname;
            MONITOR_PORT = p;
            LOCAL_PORT = lp;
        } catch (NullPointerException n) {
            System.out.println("Active Client [Constructor]: TIMEOUT Error: "+n);
        }
    }
    String command(BufferedReader bufferedReader) {
        String command = null;
        try {
            System.out.print("command>");
            command = bufferedReader.readLine();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return command;
    }

    public void start() {
        if (runner == null) {
            runner = new Thread(this);
            runner.start();
        }
    }

    public void run() {
        while(Thread.currentThread() == runner) {
            try {

                System.out.println("Active Client: Trying to establish a connection to monitor by creating a socket.");
                toMonitor = new Socket(MonitorName, MONITOR_PORT);
                System.out.println("Active Client: Connection accepted by Monitor.");
                out = new PrintWriter(toMonitor.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(toMonitor.getInputStream()));

                HOSTNAME = toMonitor.getLocalAddress().getHostName();
                CType = 0;   //Indicates Client
                HOST_PORT = LOCAL_PORT;
                if (!Login()) {
                    System.out.println("Active Client [run]: verification status = " + IsVerified);
                    System.out.println("Active Client [run]: Login failed!");
                    if (IsVerified == 0)
                    {
                        System.out.println("Active Client [run]: verification by client failed! QUITTING");
                        System.exit(1);
                    }
                }
                else
                {
                    System.out.println("Active Client [run]: success - Logged In!");
                    AutomaticSender();
                    this.present = System.currentTimeMillis();
                    if (this.present - this.prevTime > 2 * (long)this.DELAY) {
                        this.prevTime = this.present;
                        System.out.println("***************************");
                        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
                        do {
                            String string;
                            int n;
                            String string2;
                            String string3;
                            if ((string2 = this.command(bufferedReader)) == null) {
                                continue;
                            }
                            StringTokenizer stringTokenizer = new StringTokenizer(string2, " ");
                            String string4 = stringTokenizer.nextToken().toUpperCase();
                            if (string4.equals("SUBSET_A")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("SUBSET_A", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("SUBSET_K")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("SUBSET_K", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("SUBSET_J")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("SUBSET_J", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("AUTHORIZE_SET")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("AUTHORIZE_SET", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("MAKE_CERTIFICATE")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("MAKE_CERTIFICATE", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("GET_CERTIFICATE")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("GET_CERTIFICATE", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("PARTICIPANT_HOST_PORT")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("PARTICIPANT_HOST_PORT", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("PUBLIC_KEY")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("PUBLIC_KEY", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("ROUNDS")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("ROUNDS", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("TRANSFER_REQUEST")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("TRANSFER_REQUEST", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("TRANSFER_RESPONSE")) {
                                n = string2.indexOf(" ", 0);
                                string3 = string2.substring(n).trim();
                                if (!this.Execute("TRANSFER_RESPONSE", string3)) continue;
                                string = this.GetMonitorMessage();
                                continue;
                            }
                            if (string4.equals("CHANGE_PASSWORD")) {
                                this.ChangePassword();
                                continue;
                            }
                            if (string4.equals("GET_MONITOR_KEY")) {
                                this.GetMonitorPublicKey("GET_MONITOR_KEY");
                                continue;
                            }
                            if (string4.equals("HELP")) {
                                System.out.print("\tPARTICIPANT_STATUS\n\tGET_GAME_IDENTS\n\tRANDOM_PARTICIPANT_HOST_PORT\n\tGET_MONITOR_KEY\n\tQUIT\n\tSIGN_OFF\n\tTRANSFER_RESPONSE [accept | decline]\n\tTRANSFER_REQUEST <recipient> <points> FROM <sender>\n\tCHANGE_PASSWORD <old> <new>\n\tALIVE <cookie>\n\tPARTICIPANT_HOST_PORT <player>\n\tPUBLIC_KEY <ZeroKnow-v-value> <ZeroKnow-n-value>\n\tROUNDS <number>\n\tAUTHORIZE_SET <r1> ... <rn>\n\tSUBSET_A <a1> ... <ao>\n\tSUBSET_K <a1> ... <ao>\n\tSUBSET_J <a1> ... <ap>\n\tGET_CERTIFICATE <player>\n\tMAKE_CERTIFICATE <ZK-v-value> <ZK-n-value>\n");
                                continue;
                            }
                            if (!this.Execute(string4)) continue;
                            String string5 = this.GetMonitorMessage();
                        } while (true);
                    }
                    System.out.println("Active Client [run]: NOT YET TIME TO EXECUTE ANY OTHER COMMAND!");

                }
                System.out.println("***************************");
                if (Execute("GET_GAME_IDENTS")) {
                    String msg = GetMonitorMessage();
                    System.out.println("ActiveClient [GET_GAME_IDENTS]:\n\t"+msg);
                }
                if (Execute("RANDOM_PARTICIPANT_HOST_PORT")) {
                    String msg = GetMonitorMessage();
                    System.out.println("ActiveClient [RANDOM_PARTICIPANT_HOST_PORT]:\n\t"+msg);
                }
                if (Execute("PARTICIPANT_HOST_PORT", "FRANCO")) {
                    String msg = GetMonitorMessage();
                    System.out.println("ActiveClient [PARTICIPANT_HOST_PORT]:\n\t"+msg);
                }
                if (Execute("PARTICIPANT_STATUS")) {
                    String msg = GetMonitorMessage();
                    System.out.println("ActiveClient [PARTICIPANT_STATUS]:\n\t"+msg);
                }
                ChangePassword();
                System.out.println("Password:"+PASSWORD);

                toMonitor.close();
                out.close();
                in.close();
                try { runner.sleep(DELAY); } catch (Exception e) {}

            } catch (UnknownHostException e)
              {
                System.err.println("Unknown Host");
              }
              catch (IOException e) {
                  System.err.println("Active Client [run]: failed I/O for the connection to: " + e);
                  try {
                    toMonitor.close();
                    continue;
                } catch (IOException ioe) {
                      System.err.println("Failed to close the monitor:I/O Exception: "+ioe);
                } catch (NullPointerException n) {
                      System.out.println("Active Client [run]: TIMEOUT" +n);
                      try {
                          System.out.println("Active Client [run]: starting new session with client");

                          toMonitor.close();
                          continue;
                    } catch (IOException ioe)
                      {
                          System.err.println("Failed to close the monitor:I/O Exception: "+ioe);
                      }
                }
            }
        }
    }
}

