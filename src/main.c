/*
  SDK for IoTConnect
  
  This IoTConnect SDK will help you to update your Sensors data on IoTConnect cloud(Azure)
  In this example file Humidity, Temperature and Gyroscope(x,y,z) random data published on our cloud at real time

  For run this example you have to include/import "IoTConnect.cpp" or "IoTConnect.h"
  you will need wifi connection for publishing data to IoTCOnnect ..
  For the secure MQTT connection here we are using "X.509 certificats" 
  
  for more help and informationvisit https://help.iotconnect.io SDK section

    modified 02/Sept/2020
*/

/*
Hope you have installed the node SDK as guided on SDK documentation. 
*/


#include "IoTConnect_Config.h"
#include "main.h"


/* Initialize AT communications */
int at_comms_init(void)
{
	int err;
	err = at_cmd_init();
	if (err) {
		printk("Failed to initialize AT commands, err %d\n", err);
		return err;
	}
	err = at_notif_init();
	if (err) {
		printk("Failed to initialize AT notifications, err %d\n", err);
		return err;
	}
	return 0;
}


void main(void){  
    int err, count=0;  
    err = bsdlib_init();
    if (err) {
	printk("Failed to initialize bsdlib!");
	return ;
	}
    
    err = at_comms_init();
    if (err) {
	return ;
	}

    err = provision_certificates();
    if (err) {
	return ;
	}

    printk("Waiting for network.. ");
    err = lte_lc_init_and_connect();
    if (err) {
	printk("Failed to connect to the LTE network, err %d\n", err);
	return ;
	}
    printk("OK\n");
/*
## Prerequisite params to run this sampel code input in IoTConnect_config.h

- IOTCONNECT_DEVICE_CP_ID              :: It need to get from the IoTConnect platform. 
- IOTCONNECT_DEVICE_UNIQUE_ID          :: Its device ID which register on IotConnect platform and also its status has Active and Acquired
- IOTCONNECT_DEVICE_ENV                :: You need to pass respective environment of IoTConnecct platform
Note : 
*/
    err = IoTConnect_init(IOTCONNECT_DEVICE_CP_ID, IOTCONNECT_DEVICE_UNIQUE_ID, IOTCONNECT_DEVICE_ENV, Device_CallBack, Twin_CallBack);
    if (err) {
	printk("Failed to Init IoTConnect SDK");
	return ;
	}

/*
Type    : Public Method "IoTConnect_connect()"
Usage   : To connect with IoTConnect MQTT broker
*/
    IoTConnect_connect();

/*
Type    : Public Method "getAllTwins()"
Usage   : To get all the twin properies Desired and Reported
Output  : All twin property will receive in above callback function "twinUpdateCallback()"
*/
    //getAllTwins()


    while(count < 10){

        MQTT_looP();
        
        // all sensors data will be formed in JSON format and will be publied by SendData() function 
        Attribute_json_Data = Sensor_data();

/*
Type    : Public Method "sendData()"
Usage   : To publish the D2C data 
Output  : 
Input   : Predefined data object 
*/
		SendData(Attribute_json_Data);
		k_sleep(15000);
		count++ ;   
      }

/*
Type    : Public Method "IoTConnect_abort()"
Usage   : Disconnect the device from cloud
Output  : 
Input   : 
Note : It will disconnect the device after defined time 
*/ 
      err = IoTConnect_abort();
      if (err) {
          printk("Failed to Abord IoTConnect SDK");
          return ;
          }
     return ;
}





char *key = "twin01", *value = NULL;
/*
Type    : Callback Function "Twin_CallBack()"
Usage   : Manage twin properties as per business logic to update the twin reported property
Output  : Receive twin properties Desired, Reported
Input   : 
*/
void Twin_CallBack(char *topic, char *payload) {      
    printk("\n Twin_msg payload is >>  %s", payload);

    if(! strncmp(topic,"$iothub/twin/PATCH/properties/",30)){   
        cJSON *root = cJSON_Parse(payload);        
        cJSON *P = cJSON_GetObjectItemCaseSensitive(root, "desired");
        value = (cJSON_GetObjectItem(P, key))->valuestring;
		
/*
Type    : Public Method "updateTwin()"
Usage   : Upate the twin reported property
Output  : 
Input   : "key" and "value" as below
          // String key = "<< Desired property key >>"; // Desired proeprty key received from Twin callback message
          // String value = "<< Desired Property value >>"; // Value of respective desired property
*/    
        UpdateTwin(key,value);
    }
    else{
        printk("\n Twin_msg on topic >> %s and payload is >>  %s", topic, payload);
    
    }
}


/*
Type    : Callback Function "Device_CallBack()"
Usage   : Firmware will receive commands from cloud. You can manage your business logic as per received command.
Output  : Receive device command, firmware command and other device initialize error response
Input   :  
*/
void Device_CallBack(char *topic, char *payload) {      
    
    cJSON *Ack_Json;
    int Status = 0,mt=0;
    char *cmd_ackID, *Cmd_value, *Ack_Json_Data;
    printk("\n Cmd_msg >>  %s",payload);   
     
    cJSON *root = cJSON_Parse(payload);
    cmd_ackID = (cJSON_GetObjectItem(root, "ackId"))->valuestring;
    Cmd_value = (cJSON_GetObjectItem(root, "cmdType"))->valuestring;
    if( !strcmp(Cmd_value,"0x01") ){Status = 6; mt = 5;}
    else if( !strcmp(Cmd_value,"0x02") ) {Status = 7; mt = 11;}
    else { };
    Ack_Json = cJSON_CreateObject();
    if (Ack_Json == NULL){
        printk("\nUnable to allocate Ack_Json Object in Device_CallBack");
        return ;    
    }
    cJSON_AddStringToObject(Ack_Json, "ackId",cmd_ackID);
    cJSON_AddStringToObject(Ack_Json, "msg","");
    cJSON_AddStringToObject(Ack_Json, "childId","");
    cJSON_AddNumberToObject(Ack_Json, "st", Status);

    Ack_Json_Data = cJSON_PrintUnformatted(Ack_Json);
    
    // Sending ACk of command with Json(String), msg Type(int) and Current Time(String)  
    SendAck(Ack_Json_Data, Get_Time(), mt);
    cJSON_Delete(Ack_Json);
 }



// All Sensor telemetry data formation here in JSON 
char *Sensor_data(void){

    cJSON *Attribute_json = NULL;
    cJSON *Device_data1 = NULL;
    cJSON *Data = NULL, *Data1= NULL;

    Attribute_json = cJSON_CreateArray();
    if (Attribute_json == NULL){
        printk("Unable to allocate Attribute_json Object\n");
        return ;    
      }
      cJSON_AddItemToArray(Attribute_json, Device_data1 = cJSON_CreateObject());
      cJSON_AddStringToObject(Device_data1, "uniqueId",IOTCONNECT_DEVICE_UNIQUE_ID);
      cJSON_AddStringToObject(Device_data1, "time", Get_Time());
      cJSON_AddItemToObject(Device_data1, "data", Data = cJSON_CreateObject());
      cJSON_AddStringToObject(Data,"Humidity", "Black" );
      cJSON_AddNumberToObject(Data, "Temperature",  18);
      cJSON_AddItemToObject(Data, "Gyroscope", Data1 = cJSON_CreateObject());
      cJSON_AddNumberToObject(Data1, "x",  128);
      cJSON_AddStringToObject(Data1, "y", "Black" );
      cJSON_AddNumberToObject(Data1, "z",  318);
      
      char *msg = cJSON_PrintUnformatted(Attribute_json);
      cJSON_Delete(Attribute_json);
      return  msg;
}
