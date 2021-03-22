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
        String  id= " ", auto_integrate = " ",sdk_version = " ",sdk_initialize=" ",push_token = " ",onUserlogin = " ",details=" ";
        String [] temp1, temp2 ;
        ArrayList<String> listeners = new ArrayList<String>();
        Map<String,String> evtName = new HashMap<>();
        ArrayList<String> evtData = new ArrayList<String>();
        HashMap<String,String> keyval = new HashMap<String,String>();
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
                    //Log.w("checkstring", arr[0]);
                    id = arr[0].substring(1, arr[0].length() - 1);
                    Log.w("checkstring", id);

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
                    listeners.add(arr[1]);
                }

                //TO PRINT EVENT AND EVENT DETAILS
                if(line.contains("Send queue contains")){
                    arr = line.split("items:");
                    String val = arr[1].substring(2,arr[1].length()-1);
                    //Log.w("checkstring",val);
                    //arr = val.split(":|,");
                    arr = val.split("\\{|\\}");
                    for(int i =0;i<arr.length;i++){
                        //Log.w("checkstring",arr[i]);
                        if(arr[i].contains("evtName")) {
                            temp1 = arr[i].split(",|:");
                            evtData.add(arr[i+1]);
                            //Log.w("checkstring",temp1[1]);
                            for(String j : evtData){
                                evtName.put(temp1[1],j);
                            }

                        }
                    }

                }
                //TO GET PUSH TOKEN
                if(line.contains("action")){
                    arr = line.split("register");
                    arr = arr[1].split("id");
                    arr = arr[1].split(":|,");
                    //Log.w("checkstring",arr[1]+":"+arr[2]);
                    push_token = arr[1]+":"+arr[2];
                    //Log.w("checkstring",push_token);
                }


                if(line.contains("onUserLogin")){
                    onUserlogin = "OnUerLogin is used ";
                    arr = line.split("onUserLogin:");
                    arr = arr[1].split("\\{|\\}");
                    user_details = arr[1].split(",");

                }
                else if(line.contains("Send queue contains")  && line.contains("Employed")) {
                    arr = line.split("\"profile\":");
                    //Log.w("checkstring",arr[1]);
                    details = arr[1].substring(2, arr[1].length() - 1);
                    queued_user_details = details.split(",");

                }

            }

            //*************** FILE FORMATTING ******************
            fos.write("**** ACTIVITY LIFECYCLE CALLBACK ****\n".getBytes());
            fos.write(auto_integrate.getBytes());
            //Log.w("checkstring", auto_integrate);
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
            fos.write(onUserlogin.getBytes());
            fos.write("\n\n\n**** PROFILE DETAILS ****\n".getBytes());
            if(user_details.length==0){
                for (int i = 0; i < queued_user_details.length; i++) {
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
                fos.write(("Event Name : "+m.getKey()).getBytes());
                //Log.w("checkstring",values.getClass().getName());
                fos.write("\nProperties : ".getBytes());
                fos.write(m.getValue().getBytes());
                fos.write("\n".getBytes());
            }
            br.close();
            evtData.clear();
            evtName.clear();
        }
        catch (IOException e) {
            //You'll need to add proper error handling here
        }

    }

}
