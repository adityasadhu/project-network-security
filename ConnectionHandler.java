
import java.io.*;
import java.net.*;
import java.util.*;
import java.lang.*;

class ConnectionHandler extends MessageParserServer implements Runnable {
    private Socket incoming;
    private int counter;
    Thread runner;

    public ConnectionHandler (Socket i, int c, String name, String password) {
        super(name, password);
        System.out.println(" Connection Handler [ Constructor ] : Trying to handle a connection.");
        incoming = i;  counter = c;
    }

    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(incoming.getInputStream()));
            out = new PrintWriter(incoming.getOutputStream(),true);

            boolean done = false;
            HOST_PORT = PassiveServer.LOCAL_PORT;
            CType = 1;  //Indicates Server
            System.out.println("Running a thread from Passive Server to handle the connection.");
            if (Login()) {
                System.out.println("ConnectionHandler [run]: Connection successly run by Connection Handler");
            } else {
                System.out.println("Server could not log in.");
                if (IsVerified != 1) { }
            }
            incoming.close();
        } catch (IOException e) {
        } catch (NullPointerException n) {
        }
    }

    public void start() {
        if (runner == null) {
            runner = new Thread(this);
            runner.start();
        }
    }
}
