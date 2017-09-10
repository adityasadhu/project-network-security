

import java.io.*;
import java.net.*;
import java.util.*;
import java.lang.*;
import java.awt.*;


public class MakeTransfers extends ActiveClient{

    Initiator zkp=new Initiator();
    Sender snd=new Sender();

    void initiate(){

        try {
            while (true) {
                System.out.println("Initiating Points Transfer:");


                Thread.sleep(60000);
                sentmessage = cipher.encrypt("TRANSFER_REQUEST CDARK-1 100 FROM CDARK-2");

                SendIt(sentmessage);

                Thread.sleep(10000);

                this.mesg = this.GetMonitorMessage();
                String str = this.GetNextCommand(this.mesg, "");

                System.out.println("Next message expected is:" + str);

                sentmessage = cipher.encrypt(zkp.getPublicKey());

                SendIt(sentmessage);

                Thread.sleep(10000);


                this.mesg = this.GetMonitorMessage();
                str = this.GetNextCommand(this.mesg, "");

                System.out.println("Next message expected is:" + str);

                sentmessage = cipher.encrypt(zkp.getAuthorizeSet());

                SendIt(sentmessage);

                Thread.sleep(10000);

                this.mesg = this.GetMonitorMessage();
                str = this.GetNextCommand(this.mesg, "");

                System.out.println("Next message expected is:" + str);

                sentmessage = cipher.encrypt(zkp.getSubsetK());

                SendIt(sentmessage);

                this.mesg = this.GetMonitorMessage();
                str = this.GetNextCommand(this.mesg, "");

                System.out.println("Next message expected is:" + str);

                sentmessage = cipher.encrypt(zkp.getSubsetJ());

                SendIt(sentmessage);

                System.out.println("Transfer should be completed by the sender");


            }

        }catch(Exception e){

                e.printStackTrace();
            }


        }




    void receive(){

        try {
            while (true) {



                Thread.sleep(60000);

                do {
                    this.mesg = this.GetMonitorMessage();

                }while(mesg.equals("IDENT"));
                System.out.println("Received a transfer request:");

                String str = this.GetNextCommand(this.mesg, "");

                sentmessage = cipher.encrypt(IDENT);

                SendIt(sentmessage);

                this.mesg = this.GetMonitorMessage();

                str = this.GetNextCommand(this.mesg, "");

                System.out.println("Next message expected is:" + str);

                sentmessage = cipher.encrypt(COOKIE);

                SendIt(sentmessage);

                Thread.sleep(10000);

                this.mesg = this.GetMonitorMessage();

                System.out.println("Next message expected is:" + str);

                sentmessage = cipher.encrypt(Integer.toString(snd.rounds));

                SendIt(sentmessage);

                Thread.sleep(10000);

                this.mesg = this.GetMonitorMessage();

                str = this.GetNextCommand(this.mesg, "");

                snd.saveAuthorizeSet(str);


                sentmessage = cipher.encrypt(snd.getSubsetA());

                SendIt(sentmessage);

                this.mesg = this.GetMonitorMessage();
                str = this.GetNextCommand(this.mesg, "");

                System.out.println("Next message expected is:" + str);

                if(str.equals("TRANSFER_RESPONSE"))
                sentmessage = cipher.encrypt(snd.response());

                SendIt(sentmessage);

                System.out.println("Transfer should be completed by the sender");


            }

        }catch(Exception e){

            e.printStackTrace();
        }


    }

    public static void main(String args[]){

        MakeTransfers mk=new MakeTransfers();
        mk.receive();
    }


    }




