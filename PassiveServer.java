import java.io.*;
import java.net.*;
import java.util.*;
import java.lang.*;

public class PassiveServer implements Runnable{

    ServerSocket s = null;
    public static int MONITOR_PORT;
    public static int LOCAL_PORT;
    Thread runner;
    String IDENT;
    String PASSWORD;

    public PassiveServer(int p, int lp, String name, String password) {
        IDENT = name;
        PASSWORD = password;
        try {
            System.out.println("Passive Server [ Constructor ] : Creating a server Socket");
            s = new ServerSocket(p);
            MONITOR_PORT = p;
            LOCAL_PORT=lp;
            int i = 1;
        } catch (IOException e) {
        }
    }

    public void start() {
        if (runner == null) {
            runner = new Thread(this);
            runner.start();
        }
    }

    public void run() {
        try {
            int i = 1;
            for (;;) {
                Socket incoming =  s.accept();
                new ConnectionHandler(incoming,i,IDENT,PASSWORD).start();
                //Spawn a new thread for each new connection
                i++;
            }
        } catch (Exception e) {
            System.out.println("Server [run]: Error in Server: "  + e);
        }
    }
}
