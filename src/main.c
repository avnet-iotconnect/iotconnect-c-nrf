/********************************************************************************************
  SDK for IoTConnect
  
  This IoTConnect SDK will help you to update your Sensors data on IoTConnect cloud(AWS)
  In this example file Humidity, Temperature and Gyroscope(x,y,z) random data published on our cloud at real time

  For run this example you have to include/import "IoTConnect.cpp" or "IoTConnect.h"
  you will need wifi connection for publishing data to IoTCOnnect ..
  For the secure MQTT connection here we are using "X.509 certificats" 
  
  for more help and informationvisit https://help.iotconnect.io SDK section

    modified 23/12/2024
********************************************************************************************/

/********************************************************************************************
Hope you have installed the node SDK as guided on SDK documentation. 
********************************************************************************************/

#include "IoTConnect_Config.h"
#include "main.h"


/* Initialize AT communications */
int at_comms_init(void)
{

    int err;
	err = nrf_modem_lib_init();
	if (err) {
		printk("FIRMWARE : Modem library initialization failed, error: %d\n", err);
		return 0;
	}
}


void main(void)
{  
    int err;
    
    err = at_comms_init();
    if (err) 
    {
	    return ;
	}

    err = provision_certificates();
    if (err) 
    {
	    return ;
	}

    printk("FIRMWARE : Waiting for network.. \n");

    err = lte_lc_init_and_connect();
    if (err == 0) 
    {
        printk("FIRMWARE : LTE initialization and connection successful\n");
    }
    else 
    {
        printk("FIRMWARE : LTE initialization and connection failed with error code: %d\n", err);
        if (err == -EFAULT) 
        {
            printk("FIRMWARE : Error: AT command failed\n");
        } 
        else if (err == -ETIMEDOUT) 
        {
            printk("FIRMWARE : Error: Connection attempt timed out\n");
        } 
        else if (err == -EINPROGRESS) 
        {
            printk("FIRMWARE : Error: Connection establishment already in progress\n");
        } 
        else 
        {
            printk("FIRMWARE : Unknown error\n");
        }
    }


    printk("FIRMWARE : OK\n");


    /********************************************************************************************
    ## Prerequisite params to run this sampel code input in IoTConnect_config.h

    - IOTCONNECT_DEVICE_CP_ID              :: It need to get from the IoTConnect platform. 
    - IOTCONNECT_DEVICE_UNIQUE_ID          :: Its device ID which register on IotConnect platform and also its status has Active and Acquired
    - IOTCONNECT_DEVICE_ENV                :: You need to pass respective environment of IoTConnecct platform
    Note : 
    ********************************************************************************************/
    k_msleep(2000);

    err = IoTConnect_Init(IOTCONNECT_DEVICE_CP_ID, IOTCONNECT_DEVICE_UNIQUE_ID, IOTCONNECT_DEVICE_ENV, Device_CallBack, Twin_CallBack);

    if (err) 
    {
        printk("FIRMWARE : Failed to Init IoTConnect SDK\n");
        return ;
	}

    printk("FIRMWARE : Init IoTConnect SDK SUCCESS\n");

    /********************************************************************************************
    Type    : Public Method "IoTConnect_Connect()"
    Usage   : To connect with IoTConnect MQTT broker
    ********************************************************************************************/
    reinit:
        if(IoTConnect_Connect() != 0)
        {
            printk("FIRMWARE : Error : IoTConnect_Connect Fail\n");
        }

    /********************************************************************************************
    Type    : Public Method "getAllTwins()"
    Usage   : To get all the twin properies Desired and Reported
    Output  : All twin property will receive in above callback function "twinUpdateCallback()"
    ********************************************************************************************/


    while(1)
    {
        if(MQTT_Status() == 0)
        {
            // all sensors data will be formed in JSON format and will be publied by SendData() function 
            Attribute_json_Data = Sensor_data();

            /********************************************************************************************
            Type    : Public Method "sendData()"
            Usage   : To publish the D2C data 
            Output  : 
            Input   : Predefined data object 
            ********************************************************************************************/
            if(SendData(Attribute_json_Data) != 0)
            {
                printk("FIRMWARE : Error : Attribute_json_Data Send Data\n");
            }
        }
        else
        {
            printk("FIRMWARE : MQTT Connection Failed\n");
            //TODO: Break the loop, wait for internet connectivity, start form reinit goto handler
            printk("FIRMWARE : Waiting for 15 sec\n Trying to reinit IotConnect MQTT Connection\n");
            k_msleep(15000);
            
            goto reinit;
        }
        k_msleep(5000);
    }


    /********************************************************************************************
    Type    : Public Method "IoTConnect_Abort()"
    Usage   : Disconnect the device from cloud
    Output  : 
    Input   : 
    Note : It will disconnect the device after defined time 
    ********************************************************************************************/ 
    err = IoTConnect_Abort();
    if (err)
    {
        printk("FIRMWARE : Failed to Abort IoTConnect SDK\n");
        return ;
    }
}


/*******************************************************************************************
Type    : Callback Function "TwinUpdateCallback()"
Usage   : Manage twin properties as per business logic to update the twin reported property
Output  : Receive twin properties Desired, Reported
Input   : 
********************************************************************************************/
void Twin_CallBack(char *topic, char *payload)
{      
    char *key = NULL, *value = NULL;
    int device_type;
    printk("FIRMWARE : Twin/Shadow Callback\r\n");
    printk("FIRMWARE : Twin/Shadow Topic: %s\r\n", topic);
    printk("FIRMWARE : Twin/Shadow Payload: %s\r\n", payload);
    
    cJSON *root = cJSON_Parse(payload);        
    cJSON *D = cJSON_GetObjectItem(root, "desired");
    if(D) 
    {
        cJSON *device = D->child;
        while (device) 
        {
            if (!strcmp(device->string, "$version")) 
            {}
            else 
            {
                key = device->string;
                device_type = device->type;
                if(device_type == 8)
                { 
                    int  int_val;
                    double diff, flot_val;
                    flot_val = (cJSON_GetObjectItem(D, key))->valuedouble;
                    int_val = flot_val;
                    diff = flot_val - int_val;
                    if (diff > 0) {} 
                    if (diff <= 0)
                    {
                        printk("FIRMWARE : int value: %d\n", (cJSON_GetObjectItem(D, key))->valueint);
                        UpdateTwin_Int(key, int_val);
                    }
                }
                if (device_type == 16)
                {
                    value = (cJSON_GetObjectItem(D, key))->valuestring;
                    printk("FIRMWARE : string value: %s\n", value);
                    UpdateTwin_Str(key,value);
                }
                if (device_type == 4 || device_type == 64)
                {
                    printk("FIRMWARE : Removed twin %s has value NULL\n", key);
                }
            }
            device = device->next;
        }		
    }
}


/********************************************************************************************
Type    : Callback Function "Device_CallBack()"
Usage   : Firmware will receive commands from cloud. You can manage your business logic as per received command.
Output  : Receive device command, firmware command and other device initialize error response
Input   :  
********************************************************************************************/
void Device_CallBack(char *topic, char *payload)
{      
    printk("FIRMWARE : Device Callback\r\n");
    printk("FIRMWARE : Topic: %s\r\n", topic);
    
    cJSON *Ack_Json, *sub_value, *in_url;
    int Status = 0,msgType=0;
    char *cmd_ackID = NULL;
    char *Ack_Json_Data = NULL;

    cJSON *root = cJSON_Parse(payload);

    if(cJSON_HasObjectItem(root, "ct"))
    {
        int ct_value = (cJSON_GetObjectItem(root, "ct")->valueint);
        if(cJSON_HasObjectItem(root, "ack"))
        {
            cmd_ackID = (cJSON_GetObjectItem(root, "ack")->valuestring);
        }

        if(ct_value == 0){
            Status = 2,msgType = 0;
            printk("FIRMWARE : Command Payload: %s\r\n", payload);
        }
        if(ct_value == 1){
            Status = 5,msgType = 1;

            sub_value = cJSON_GetObjectItem(root,"urls");
            if(cJSON_IsArray(sub_value)){
                int url_count = cJSON_GetArraySize(sub_value);
                for(int i = 0; i < url_count; i++)
                {
                    in_url = cJSON_GetArrayItem(sub_value, i);

                    char* OTA_url = cJSON_GetObjectItem(in_url, "url")->valuestring;
                    printk("FIRMWARE : OTA URL : %s\r\n", OTA_url);
                }
            }
        }
        if(ct_value == 2){
            Status = 2,msgType = 2;
            printk("FIRMWARE : Module Command Payload: %s\r\n", payload);
        }
    }

    Ack_Json = cJSON_CreateObject();
    if (Ack_Json == NULL)
	{
        printk("FIRMWARE : Unable to allocate Ack_Json Object in Device_CallBack\n");
        return ;    
    }
    cJSON_AddStringToObject(Ack_Json, "ack",cmd_ackID);
    cJSON_AddNumberToObject(Ack_Json, "type", msgType);
    cJSON_AddNumberToObject(Ack_Json, "st", Status);
    cJSON_AddStringToObject(Ack_Json, "msg","Not Implemented");

    Ack_Json_Data = cJSON_PrintUnformatted(Ack_Json);

    /*
    Type    : Public Method "sendAck()"
    Usage   : Send firmware command received acknowledgement to cloud
      - status Type
		st = 2; // Device command Ack status 
        st = 1; // Device command Ack status Failed
		st = 5; // firmware OTA command Ack status 
        st = 1; // firmware OTA command Ack status Failed
      - Message Type
		msgType = 0; // for device command 
        msgType = 1; // for Firmware command
        msgType = 2; // for Module command
    */ 

    if(!SendAck(Ack_Json_Data, msgType))
    {
        printk("FIRMWARE : Send Command ACK Success\n");
    }else{
        printk("FIRMWARE : Send Command ACK Fail\n");
    }
}


// All Sensor telemetry data formation here in JSON 
char *Sensor_data(void)
{

    cJSON *Attribute_json = NULL;
    cJSON *Device_data1 = NULL;
    cJSON *Data = NULL;
    cJSON *Data1 = NULL;

    Attribute_json = cJSON_CreateArray();
    if (Attribute_json == NULL)
    {
        printk("FIRMWARE : Unable to allocate Attribute_json Object\n");
        return NULL;    
    }

    cJSON_AddItemToArray(Attribute_json, Device_data1 = cJSON_CreateObject());
    cJSON_AddStringToObject(Device_data1, "uniqueId",IOTCONNECT_DEVICE_UNIQUE_ID);
    cJSON_AddStringToObject(Device_data1, "time", Get_Time());
    cJSON_AddItemToObject(Device_data1, "data", Data = cJSON_CreateObject());
    cJSON_AddNumberToObject(Data,"Humidity",30);
    cJSON_AddNumberToObject(Data, "Temperature",18);
    cJSON_AddItemToObject(Data, "Gyroscope", Data1 = cJSON_CreateObject());
    cJSON_AddNumberToObject(Data1,"X",128);
    cJSON_AddNumberToObject(Data1,"Y",148);
    cJSON_AddNumberToObject(Data1,"Z",318);
    cJSON_AddNumberToObject(Data, "Temperature",64);
    
    char *msg = cJSON_PrintUnformatted(Attribute_json);
    cJSON_Delete(Attribute_json);
    return  msg;
}