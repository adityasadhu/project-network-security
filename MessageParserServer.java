import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;



public class MessageParserServer {

    int COMMAND_LIMIT = 25;
    public int CType;
    public static String HOSTNAME;
    PrintWriter out = null;
    BufferedReader in = null;
    String mesg, sentmessage;
    String filename;
    StringTokenizer t;
	String IDENT = "CDARK-1";
    String PASSWORD = "";
    static String COOKIE = "";
    String PPCHECKSUM = "";
    int HOST_PORT;
    public static int IsVerified;
    static String passwordFileName;
    static SecureRandom sr;
    String RandomPassword;
    static boolean IsEncrypted;
    boolean prevent_encryption = false;
    static boolean dheOn;
    static boolean StartedEncryption;
    static DHKey dhk;
    static DHE dhe;
    Karn cipher = null;
    String recipient;

    //File I/O Declarations
    BufferedReader fIn = null;
    PrintWriter fOut = null;
    static String InputFileName = "Input.dat";
    static String ResourceFileName = "Resources.dat";
    String[] cmdArr = new String[COMMAND_LIMIT];

    static String MyKey;
    String MonitorKey;
    String first;
    ObjectInputStream oin = null;
    ObjectOutputStream oout = null;
    ZKPMain zkp=new ZKPMain();
    ZKPSender zpksender=new ZKPSender();


    MessageParserServer(String ident, String password) {

        String Str3;
        this.IDENT = ident;
        passwordFileName = new String("passwd.dat." + ident);
        this.GetIdentification();

        if (sr == null) {
            System.out.println("Message Parser Server: Generating the secure random:");
            sr = new SecureRandom();
        }

        if ((Str3 = this.GeneratePassword(sr)).trim().equals("") || Str3.trim().equals(null)) {
            this.RandomPassword = Str3.trim();
        }


    }

    public boolean Login() {

        boolean success = false;
        StartedEncryption = false;
		IsEncrypted=false;

        try {
            while (true) {



                System.out.println("In the Server Loop Sir.");

                this.mesg = this.GetMonitorMessage();
                if (this.CType == 1) {
                    System.out.println("Checking the monitor authenticity first.");
                    if (!this.IsMonitorAuthentic(this.mesg)) {
                        System.out.println("Monitor not authentic. exiting the code.");
                        return success;
                    }
                }

                IsVerified = 1;
                String str = this.GetNextCommand(this.mesg, "");
                if (str == null)
                    return false;

                if (str.trim().equals("IDENT")) {
                    if (!IsEncrypted && !this.prevent_encryption) {

                        if (!dheOn)
                            this.SetEncryption();

                        StartedEncryption = true;
                        dheOn = true;

                        System.out.println("Started Encryption.");
                    }

                    if (this.Execute(str)) {
                        System.out.println("Trying to execute Ident.");
                        this.mesg = this.GetMonitorMessage();
                        str = this.GetNextCommand(this.mesg, "");
                        System.out.println("Parsed Ident, Next Command should be:" + str);
                        if (str == null)
                            return false;


                        if (str.trim().equals("ALIVE")) {
                            System.out.println("Received Alive token from Monitor");
                            if (this.Execute(str)) {
                                this.mesg = this.GetMonitorMessage();
                                System.out.println("Alive has been verified" + mesg);
                                str = this.GetNextCommand(this.mesg, "");
                                System.out.println();
                                if (this.CType == 0) {
                                    if (str == null) {
                                        return true;
                                    }

                                    if (str.trim().equals("HOST_PORT")) {
                                        if (this.Execute(str)) {
                                            this.mesg = this.GetMonitorMessage();
                                            success = true;
                                            System.out.println("Message Parser Server [Login]: launching active client:\n\t" + this.mesg);
                                        }
                                    } else {
                                        success = true;
                                    }
                                } else if (this.CType == 1) {

                                    if (str.trim().equals("ROUNDS")) {


                                        recipient=mesg;

                                        System.out.println("IN rounds");

                                        if (this.Execute(str, "7")) {

                                            zkp.saveRounds("7");
                                            zpksender.getRounds(7);

                                            this.mesg = this.GetMonitorMessage();
                                            System.out.println("Message from Monitor:" + mesg);

                                            str = this.GetNextCommand(this.mesg, "");

                                            if (str.trim().equals("SUBSET_A")) {

                                                String result1 = mesg.substring("RESULT: AUTHORIZE_SET".length() + 1);
                                                int k = result1.indexOf("REQUIRE");
                                                String result = result1.substring(0, k);
                                                System.out.println("Value of RESULT" + result);
                                                zkp.saveSubsetA(result);

                                                System.out.println("Working something");

                                                if (this.Execute("SUBSET_A")) {

                                                    this.mesg = this.GetMonitorMessage();
                                                    System.out.println("Message from Monitor:" + mesg);

                                                    str = this.GetNextCommand(this.mesg, "");

                                                    if (str.trim().equals("TRANSFER_RESPONSE")) {

                                                        if (Execute(str)) {

                                                            this.mesg = this.GetMonitorMessage();
                                                            System.out.println("Message from Monitor:" + mesg);

                                                            str = this.GetNextCommand(this.mesg, "");

                                                            if (str.trim().equals("QUIT")) {

                                                                Execute("QUIT");


                                                                System.out.println("Successfully transfered Points.");
                                                            }
                                                        }


                                                    }

                                                }
                                            }


                                        }

                                    }



                                 else if (str.trim().equals("QUIT")) {
                                    if (this.Execute(str)) {
                                        System.out.println("Server is quitting normally");
                                        this.mesg = this.GetMonitorMessage();
                                        success = true;
                                    }


                                } else {
                                    success = true;
                                        }
                            }
                        } else {

                            str = this.GetNextCommand(this.mesg, "");

                            }

                        }


                    }


                }

            }

        } catch (NullPointerException n) {
            System.out.println("MessageParser [Login]: null pointer error " +
                    "at login:\n\t");
            n.printStackTrace();
            success = false;

        }

        return success;
    }


    public boolean WritePersonalData(String pwd, String cke) {
        System.out.println("Writing password and cookie to the file.");
        boolean success = false;
        PrintWriter printWriter = null;
        try {
            if (pwd != null && !pwd.equals("")) {
                System.out.println("Message Parser Server [WritePersonalData]: NEW PASSWORD = " + pwd);
                printWriter = new PrintWriter(new FileWriter(passwordFileName));
                printWriter.println("PASSWORD");
                printWriter.println(pwd);
            }
            if (cke != null && !cke.equals("")) {
                System.out.println("Message Parser Server [WritePersonalData]: NEW COOKIE = " + cke);
                printWriter.println("COOKIE");
                printWriter.flush();
                printWriter.println(cke);
                printWriter.flush();
            }
            printWriter.close();
            success = true;
            System.out.println("Successfully Wrote the Cookie and Password to the file.");
        } catch (IOException var5_5) {
            System.out.println("Message Parser Server [WritePersonalData]: error writing data password file:\n\t" + var5_5);
            printWriter.close();
            return success;
        } catch (NumberFormatException var5_6) {
            System.out.println("Message Parser Server [WritePersonalData]: number format error:\n\t" + var5_6);
        }
        return success;
    }


    public String GetNextCommand(String mesg, String sCommand) {
        try {
            String sDefault = "REQUIRE";
            if (!(sCommand.equals(""))) sDefault = sCommand;
            t = new StringTokenizer(mesg, " :\n");
            //Search for the REQUIRE Command
            String temp = t.nextToken();
            while (!(temp.trim().equals(sDefault.trim()))) temp = t.nextToken();
            temp = t.nextToken();
            System.out.println("MessageParserServer [getNextCommand]: returning:\n\t" +
                    temp);
            return temp;  //returns what the monitor wants
        } catch (NoSuchElementException e) {
            return null;
        }
    }


    public void ChangePassword() {
        GetIdentification(); //Gives u the previous values of Cookie and Password
        RandomPassword = this.GeneratePassword(sr);
        System.out.println("Message Parser Server: New Password:" + RandomPassword);
        String quer = "CHANGE_PASSWORD " + PASSWORD + " " + RandomPassword.trim();
        UpdatePassword(quer);
    }

    public void UpdatePassword(String cmd) {
        PrintWriter pw = null;
        try {
            if (cmd != null && !cmd.equals("")) {
                String temp1;
                SendIt(cmd);
                mesg = this.GetMonitorMessage();
                t = new StringTokenizer(mesg, " :\n");
                String temp2 = t.nextToken();
                if (temp2.equals("RESULT") && (temp1 = this.GetNextCommand(this.mesg, "CHANGE_PASSWORD")) != null && !temp1.equals("") && this.WritePersonalData(this.RandomPassword, temp1)) {
                    COOKIE = temp1;
                    this.PASSWORD = this.RandomPassword;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            pw.close();
        }

    }

    public void SendIt(String message) throws IOException {
        try {
            System.out.println("MessageParser Server [SendIt]: sent:\n\t" + message);
            if (IsEncrypted) {
                String string2;
                message = string2 = this.cipher.encrypt(message);
            }
            out.println(message);
            if (out.checkError() == true) throw (new IOException());
            out.flush();
            if (out.checkError() == true) throw (new IOException());
        } catch (IOException e) {
            e.printStackTrace();
        } //Bubble the Exception upwards
    }


    public String GetMonitorMessage() {
        String sMesg = "", decrypt = "";
        try {
            String temp = in.readLine();
            first = temp; // 1st
            if (IsEncrypted && StartedEncryption) {
                if (temp != null && !temp.trim().equals("")) {
                    decrypt = this.cipher.decrypt(temp.trim());
                } else {
                    decrypt = "";
                }
                sMesg = decrypt;
            } else {
                sMesg = temp;
                decrypt = temp;
            }
            if (StartedEncryption && !IsEncrypted) {
                MonitorKey = this.GetNextCommand(this.first, "IDENT");
                System.out.println("Monitor Key in Message Parser Server:" + MonitorKey);
                dhe.setExchangeKey(this.MonitorKey);
                BigInteger bigInteger = dhe.getSharedKey();
                System.out.println("Shared key in Message Parser Server:\n\t" + bigInteger);
                cipher = new Karn(bigInteger);
                IsEncrypted = true;
            }

            //After IDENT has been sent-to handle partially encrypted msg group
            while (!(decrypt.trim().equals("WAITING:"))) {
                temp = in.readLine();
                sMesg = sMesg.concat(" ");
                if (IsEncrypted && StartedEncryption) {
                    if (temp != null && !temp.trim().equals("")) {
                        decrypt = this.cipher.decrypt(temp.trim());
                    } else {
                        decrypt = "";
                    }
                    sMesg = sMesg.concat(decrypt);
                    continue;
                }
                decrypt = temp;
                sMesg = sMesg.concat(decrypt);
            } //sMesg now contains the Message Group sent by the Monitor
        } catch (IOException e) {
            System.out.println("MessageParser [getMonitorMessage]: error " +
                    "in GetMonitorMessage:\n\t" + e + this);
            sMesg = "";
        } catch (NullPointerException n) {
            sMesg = "";
        } catch (NumberFormatException o) {
            System.out.println("MessageParser [getMonitorMessage]: number " +
                    "format error:\n\t" + o + this);
            sMesg = "";
        } catch (NoSuchElementException ne) {
            System.out.println("MessageParser [getMonitorMessage]: no such " +
                    "element exception occurred:\n\t" + this);
        } catch (ArrayIndexOutOfBoundsException ae) {
            System.out.println("MessageParser [getMonitorMessage]: AIOB " +
                    "EXCEPTION!\n\t" + this);
            sMesg = "";
        }
        return sMesg;


    }


    public void SetEncryption() {
        System.out.println("Starting encryption dhe");
        try {
            if (dhk == null) {
                System.out.println("No Dh Key found. Getting dh Key for initial use");
                this.oin = new ObjectInputStream(new FileInputStream("DHKey"));
                dhk = (DHKey) this.oin.readObject();
                this.oin.close();
            }
            if (dhe == null) {
                System.out.println("Getting Dhe Object for use.");
                dhe = new DHE(dhk);
            }
            System.out.println("Get MyKey from key exchange using dhe.");
            MyKey = dhe.getExchangeKey();
            System.out.println("Message Parser Server [SetEncryption]: my key:\n\t" + MyKey);
        } catch (Exception var1_1) {
            System.out.println("Message Parser Server [SetEncryption]: error:\n\t" + var1_1);
        }
    }

    public boolean IsMonitorAuthentic(String string) {
        System.out.println("Checking for monitor authenticity:");
        boolean success = false;
        this.PPCHECKSUM = this.GetNextCommand(string, "PARTICIPANT_PASSWORD_CHECKSUM");
        System.out.println("Received the checksum: " + this.PPCHECKSUM);
        try {
            if (this.PPCHECKSUM != null) {
                if (!this.Verify(this.PASSWORD, this.PPCHECKSUM)) {
                    System.out.println("MONITOR is not authorized");
                    IsVerified = 0;
                    success = false;
                } else {
                    System.out.println("monitor successfully verified!");
                    success = true;
                }
            }
        } catch (NoSuchAlgorithmException var3_3) {
            System.out.println("Message Parser Server [IsMonitorAuthentic]: error verifying:\n\t" + var3_3);
            IsVerified = 0;
        }
        return success;
    }

    // to be learnt
    public boolean Verify(String string, String string2) throws NoSuchAlgorithmException {
        System.out.println("In Verify Function.");
        boolean success = false;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            string = string.toUpperCase();
            byte[] arrby = string.getBytes();
            messageDigest.update(arrby);
            BigInteger bigInteger = new BigInteger(1, messageDigest.digest());
            System.out.println("Message Parser Server [Verify]: original chksum: " + string2);
            System.out.println("Message Parser Server [Verify]: calculated chksum from password: " + bigInteger.toString(16));
            if (bigInteger.toString(16).equals(string2.trim())) {
                return true;
            }
            return false;
        } catch (NoSuchAlgorithmException var4_5) {
            return false;
        }
    }

    //Handle Directives and Execute appropriate commands with one argument

    public boolean Execute(String sentmessage, String arg) {
        boolean success = false;
        try {
            if (sentmessage.trim().equals("PARTICIPANT_HOST_PORT")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("TRANSFER_REQUEST")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("TRANSFER_RESPONSE")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("ROUNDS")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("PUBLIC_KEY")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("PARTICIPANT_HOST_PORT")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("GET_CERTIFICATE")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("MAKE_CERTIFICATE")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("AUTHORIZE_SET")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("SUBSET_J")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("SUBSET_K")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("SUBSET_A")) {
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(arg);
                SendIt(sentmessage);
                success = true;
            }
        } catch (IOException e) {
            e.printStackTrace();
            success = false;
        } catch (NullPointerException e) {
            e.printStackTrace();
            success = false;
        }
        return success;
    }


    public boolean Execute(String sentmessage) {
        boolean success = false;
        try {
            if (sentmessage.trim().equals("IDENT")) {

                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(this.IDENT);
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(MyKey);
                System.out.print("Message Parser Server [Execute]: sent IDENT:\n\t" + sentmessage + "\n");
                this.SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("PASSWORD")) {

                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(this.PASSWORD);
                System.out.println("Message Parser Server [Execute]: sent PASSWORD:\n\t" + sentmessage);
                this.SendIt(sentmessage.trim());
                success = true;
            } else if (sentmessage.trim().equals("HOST_PORT")) {

                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(HOSTNAME);
                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(String.valueOf(this.HOST_PORT));
                System.out.println("Message Parser Server [Execute]: sent HOST_PORT:\n\t" + sentmessage);
                this.SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("ALIVE")) {

                sentmessage = sentmessage.concat(" ");
                sentmessage = sentmessage.concat(COOKIE);
                this.SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("QUIT")) {

                this.SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("PARTICIPANT_STATUS")) {

                this.SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("GET_GAME_IDENTS")) {
                this.SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("RANDOM_PARTICIPANT_HOST_PORT")) {
                this.SendIt(sentmessage);
                success = true;
            }
             else if (sentmessage.trim().equals("TRANSFER_REQUEST")) {
                sentmessage = sentmessage.concat(sentmessage);
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("TRANSFER_RESPONSE")) {
                sentmessage="";
                System.out.println("Value of recipient is:"+recipient);
                System.out.println("1st code:"+recipient.contains("CDARK-1"));
                System.out.println("2st code:"+recipient.contains("CDARK-2"));
                System.out.println("3st code:"+(recipient.contains("CDARK-3") && (recipient.contains("CDARK-2"))));
                System.out.println("4st code:"+(recipient.contains("CDARK-3") && (recipient.contains("CDARK-1"))));
                System.out.println("5st code:"+(recipient.contains("CDARK-2") && (recipient.contains("CDARK-1"))));
                System.out.println("6st code:"+recipient.contains("CDARK-1"));

                if((recipient.contains("CDARK-1") && recipient.contains("CDARK-2") )|| (recipient.contains("CDARK-1") && recipient.contains("CDARK-3") ) || (recipient.contains("KALAN") && recipient.contains("JAABHI") )) {
                    sentmessage = sentmessage.concat("TRANSFER_RESPONSE ACCEPT");
                }
                else
                    sentmessage = sentmessage.concat("TRANSFER_RESPONSE DECLINE");
                /*sentmessage = sentmessage.concat("TRANSFER_RESPONSE ACCEPT");*/
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("ROUNDS")) {
                sentmessage = sentmessage.concat("3");
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("PUBLIC_KEY")) {
                sentmessage = sentmessage.concat(zkp.getPublicKey());
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("GET_CERTIFICATE")) {
                sentmessage = sentmessage.concat("KALAN");
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("MAKE_CERTIFICATE")) {
                sentmessage = sentmessage.concat("40 60");
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("AUTHORIZE_SET")) {
                sentmessage = sentmessage.concat(zkp.getAuthorizeSet());
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("SUBSET_J")) {
                sentmessage = sentmessage.concat(zkp.getSubsetJ());
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("SUBSET_K")) {
                sentmessage = sentmessage.concat(zkp.getSubsetK());
                SendIt(sentmessage);
                success = true;
            } else if (sentmessage.trim().equals("SUBSET_A")) {
                sentmessage="";
                sentmessage = sentmessage.concat(zpksender.getSubsetA());
                System.out.println("Subset_A Function message value"+sentmessage);
                SendIt(sentmessage);
                success = true;
            }
        }
        catch (IOException e) {
            e.printStackTrace();
            success = false;
        }
        catch (NullPointerException e) {
            e.printStackTrace();
            success = false;
        }
        return success;
    }

    public void GetMonitorPublicKey(String string) {
        PrintWriter printWriter = null;
        try {
            String string2;
            if (string == null || string.equals("")) return;
            this.SendIt(string);
            this.mesg = this.GetMonitorMessage();
            this.t = new StringTokenizer(this.mesg, " :\n");
            String string3 = this.t.nextToken();
            if (string3.equals("RESULT") && (string2 = this.GetNextCommand(this.mesg, "MONITOR_KEY")) != null && string2.equals("")) return;
        }
        catch (IOException var3_4) {
            System.out.println("Message Parser Server [GetMonitorPublicKey]: io exception error:\n\t" + var3_4);
            printWriter.close();
            return;
        }
        catch (NoSuchElementException var3_5) {
            System.out.println("Message Parser: Server [GetMonitorPublicKey]: error in getting monitor's public key!");
        }
    }



    /* verified method */
    public void GetIdentification() {
        System.out.println("Message Parser Server [GetIndentification]:");
        BufferedReader bufferedReader = null;
        try {

            bufferedReader = new BufferedReader(new FileReader(passwordFileName));
            String string = bufferedReader.readLine();
            if (string.equalsIgnoreCase("PASSWORD")) {
                string = bufferedReader.readLine();
                if (string != null && !string.equals("")) {
                    System.out.println("Message Parser Server [GetIndentification]: obtained password from the file: " + string);
                }
                this.PASSWORD = string.trim();
                string = bufferedReader.readLine();
                if (string.equalsIgnoreCase("COOKIE")) {
                    string = bufferedReader.readLine();
                }
                if (string != null && !string.equals("")) {
                    System.out.println("Message Parser Server [GetIndentification]: obtained COOKIE from file: " + string);
                }
                COOKIE = string.trim();
            }
            bufferedReader.close();
        }
        catch (IOException var2_3) {
            System.out.println("Message Parser Server [GetIndentification]: error getting data from password file:\n\t" + var2_3);
        }
    }

    public String GeneratePassword(SecureRandom secureRandom) {
        System.out.println("In Message Parser Server: Generating Password.");
        BigInteger bigInteger = new BigInteger(128, secureRandom);
        System.out.println("In Message Parser Server generated random password:\n\t" + bigInteger.abs().toString(16));
        return bigInteger.abs().toString(16);
    }

}
