package com.example.getauditreport;



import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class ReportGenerate {
    public  static void run(Context context){
        final Handler handler = new Handler(Looper.getMainLooper());
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                writeLogs(context);
                generate(context);
            }
        }, 60000);
    }



    private  static void writeLogs(Context context) {
        StringBuilder log = new StringBuilder();

        FileOutputStream fos;
        try {
            //Thread.sleep(60000);
            Process process = Runtime.getRuntime().exec("logcat -d");
            BufferedReader bufferedReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));


            String line;
            while ((line = bufferedReader.readLine()) != null) {
                if(line.contains("CleverTap")){
                    log.append(line);
                    log.append("\n");
                }
            }
            Log.w("Logfetch", log.toString());

            fos = context.openFileOutput("logs.txt", context.MODE_PRIVATE);
            fos.write(log.toString().getBytes());
            Toast.makeText(context, "Saved to " + context.getFilesDir() + "/" + "logs.txt",
                    Toast.LENGTH_LONG).show();
            Log.w("filepath",context.getFilesDir().toString());
        } catch (IOException e) {
            Thread.currentThread().interrupt();
        }
    }

    private  static void generate(Context context) {
        File file = new File(context.getFilesDir() ,"logs.txt");
        FileOutputStream fos;
        String  id= " ", auto_integrate = " ",sdk_version = " ",sdk_initialize=" ",push_token = " ",onUserLogin = " ",details=" ";
        String [] temp1;
        ArrayList<String> listeners = new ArrayList<String>();
        Map<String,String> evtName = new HashMap<>();
        ArrayList<String> evtData = new ArrayList<String>();
        String arr [] = new String[0];
        String [] user_details = new String[0] ;
        String [] queued_user_details = new String[0];

        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            fos = context.openFileOutput("AuditReport.txt", Context.MODE_PRIVATE);
            fos.write("AUDIT REPORT\n\n".getBytes());
            while ((line = br.readLine()) != null) {
                //TO CHECK INTEGRATION
                if(line.contains("Activity Lifecycle Callback")){
                    arr = line.split("CleverTap:");
                    auto_integrate = arr[1];

                }

                //Log.w("checkstring",auto_integrate);
                //TO CHECK INITIALIZATION
                if(line.contains("CleverTap SDK initialized with accountId")) {
                    arr = line.split("CleverTap:");
                    sdk_initialize = arr[1];
                }
                // TO GET THE CTID
                if(line.contains("Send queue contains")) {
                    arr = line.split("items:");
                    arr = arr[1].split("\"g\":");
                    arr = arr[1].split(",");
                    id = arr[0].substring(1, arr[0].length() - 1);
                }

                //TO GET THE SDK VERSION
                if(line.contains("SDK Version Code is")) {
                    arr = line.split("CleverTap:");
                    arr = arr[1].split("SDK Version Code is ");
                    sdk_version = arr[1];
                }
                //TO GET ALL LISTENERS
                if(line.contains("present")){
                    arr = line.split("CleverTap:");
                    if(!listeners.contains(arr[1]))
                        listeners.add(arr[1]);
                }

                //TO PRINT EVENT AND EVENT DETAILS
                if(line.contains("Send queue contains")){
                    arr = line.split("items:");
                    String val = arr[1].substring(2,arr[1].length()-1);
                    arr = val.split("\\{|\\}");
                    for(int i =0;i<arr.length;i++){
                        if(arr[i].contains("evtName")) {
                            temp1 = arr[i].split(",|:");
                            evtData.add(arr[i+1]);
                            for(String j : evtData){
                                evtName.put(temp1[1],j);
                            }
                        }
                    }

                }
                //TO GET PUSH TOKEN
                if( line.contains("Send queue contains") && line.contains("action")){
                    arr = line.split("register");
                    arr = arr[1].split("\"id\":");
                    arr = arr[1].split(",");
                    push_token = arr[0];
                }

                //ON USER LOGIN AND USER DETAILS
                if(line.contains("onUserLogin")){
                    onUserLogin = "OnUerLogin is used ";
                    arr = line.split("onUserLogin:");
                    arr = arr[1].split("\\{|\\}");
                    arr[1] = arr[1].replaceAll("\\s","");
                    user_details = arr[1].split(",");

                }
                else if(line.contains("Send queue contains") && line.contains("profile")) {
                    arr = line.split("\"profile\":");
                    for(int i=0;i<arr.length;i++){
                        if(arr[i].contains("Email")){
                            details = arr[i].substring(1,arr[i].length()-2);
                            queued_user_details = details.split(",");
                        }
                    }
                }

            }

            //*************** FILE FORMATTING ******************
            fos.write("**** ACTIVITY LIFECYCLE CALLBACK ****\n".getBytes());
            fos.write(auto_integrate.getBytes());
            fos.write("\n\n\n**** SDK INITIALIZED ****\n".getBytes());
            fos.write(sdk_initialize.getBytes());
            fos.write("\n\n\n**** LISTENERS ****\n".getBytes());
            for(int i =0;i<listeners.size();i++){
                fos.write(listeners.get(i).getBytes());
                fos.write("\n".getBytes());
            }
            fos.write("\n\n**** PUSH TOKEN ****\n".getBytes());
            fos.write("Token Id : ".getBytes());
            fos.write(push_token.getBytes());

            fos.write("\n\n\n**** META DATA ****\n".getBytes());
            fos.write("SDK Version : ".getBytes());
            fos.write(sdk_version.getBytes());
            fos.write("\nCTID : ".getBytes());
            fos.write(id.getBytes());

            fos.write("\n\n\n**** IDENTITY MANAGEMENT ****\n".getBytes());
            fos.write("onUserLogin : ".getBytes());
            fos.write(onUserLogin.getBytes());
            fos.write("\n\n\n**** PROFILE DETAILS ****\n".getBytes());
            if(user_details.length==0){
                for (int i = 0; i < queued_user_details.length; i++) {
                    if(queued_user_details[i].endsWith("}") && queued_user_details[i].startsWith("\"")){
                        queued_user_details[i] = queued_user_details[i].substring(0,queued_user_details[i].length()-1);
                    }
                    if(queued_user_details[i].startsWith("\"")){
                        String s2="";
                        queued_user_details[i] = queued_user_details[i].substring(1,queued_user_details[i].length());
                        int index = queued_user_details[i].indexOf(":");
                        if(queued_user_details[i].endsWith("\"")){
                            queued_user_details[i] = queued_user_details[i].substring(0,queued_user_details[i].length()-1);
                        }
                        String s1 =queued_user_details[i].substring(0,index-1);
                        s2 = queued_user_details[i].substring(index+1,queued_user_details[i].length()-0);
                        if(s2.startsWith("\"")){
                            s2 = s2.substring(1,s2.length()-0);
                        }
                        queued_user_details[i] = s1+" : "+s2;
                        //Log.w("checkstring",queued_user_details[i]);
                    }
                    //Log.w("checkstring",queued_user_details[i]);
                    fos.write(queued_user_details[i].getBytes());
                    fos.write("\n".getBytes());
                }
            }
            else{
                fos.write("onUserLogin method details\n".getBytes());
                for (int i = 0; i < user_details.length; i++) {
                    fos.write(user_details[i].getBytes());
                    fos.write("\n".getBytes());
                }

            }
            fos.write("\n\n\n**** ACTIVITY ****\n".getBytes());
            for(Map.Entry<String, String> m:evtName.entrySet()){
                fos.write(("Event Name : "+m.getKey().substring(1,m.getKey().length()-1)).getBytes());
                fos.write("\nProperties : ".getBytes());
                String [] values = m.getValue().split(",");
                //fos.write(m.getValue().getBytes());
                for(int i =0;i<values.length;i++){
                        if(values[i].startsWith("\"")){
                            String s2="";
                            values[i] = values[i].substring(1,values[i].length()-0);
                            int index = values[i].indexOf(":");
                            if(values[i].endsWith("\"")){
                                values[i] = values[i].substring(0,values[i].length()-1);
                            }
                            String s1 =values[i].substring(0,index-1);

                            s2 = values[i].substring(index+1,values[i].length()-0);
                            if(s2.startsWith("\"")){
                                s2 = s2.substring(1,s2.length()-0);
                            }
                            values[i] = s1+" : "+s2;
                            //Log.w("checkstring",s1+ " : "+s2);
                        }
                        //Log.w("checkstring",values[i]);
                        fos.write(values[i].getBytes());
                        fos.write(" | ".getBytes());
                }
                fos.write("\n".getBytes());
            }
            br.close();
            evtData.clear();
            evtName.clear();
        }
        catch (IOException e) {
            //You'll need to add proper error handling here
        }
        file.delete();
        if(file.exists()){
            if(file.exists()){
                context.deleteFile(file.getName());
            }       }

    }

}
