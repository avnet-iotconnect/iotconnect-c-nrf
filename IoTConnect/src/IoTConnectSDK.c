#include <string.h>
#include <zephyr/kernel.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include "cJSON.h"
#include <modem/lte_lc.h>
#include <modem/pdn.h>
#include <date_time.h>

#include <zephyr/logging/log.h> 
#include <modem/modem_key_mgmt.h>
#include <zephyr/net/mqtt.h>
#include "../src/IoTConnectSDK.h"
#include "../cert/certificates.h"

LOG_MODULE_REGISTER(Logs2); 


static sec_tag_t sec_tag_list[] = { CONFIG_SEC_TAG };
static struct mqtt_client client;
static struct sockaddr_storage broker;
static bool connected;
static struct pollfd fds;
uint16_t midNum = 0;


#define CONFIG_PROVISION_CERTIFICATES
#define CONFIG_BSD_LIBRARY
#define CONFIG_MQTT_LIB_TLS
#if defined(CONFIG_MQTT_LIB_TLS)

#endif
/* Buffers for MQTT client. */
static uint8_t rxBuffer[MAXLINE];
static uint8_t txBuffer[MAXLINE];
static uint8_t payloadBuf[MAXLINE];
//BUILD_ASSERT_MSG(sizeof(CLOUD_CA_CERTIFICATE) < KB(4), "Certificate too large");
BUILD_ASSERT(sizeof(CLOUD_CA_CERTIFICATE) < KB(4), "Certificate too large");

typedef struct
{
    char *cpId;
    char *dtg;
    char *dvc_id[10];
    char *tg[10];
    int rc;
    int ee;
    int at;
    int ec;
    int hb;
    int hb_ct;
    struct meta_data 
    {
        int at;
        int df;
        int start_hb;
        int hb_event;
        char *cd;
        // JsonObject gtw;
        char *tg;
        char *g;
        int edge;
    } meta;

    struct has_data 
    {
        int d;      //If 1 – Gateway Device can send 204 message to get all child devices
        int attr;   //If 1 – Device can send 201 message to get all attribute details
        int sett;   //If 1 – Device can send 202 message to get updates on settings/twins
        int rule;      //If 1 – Edge Device can send 203 message to get all rules
        int ota;    //If 1 – Device can send 205 message to get pending OTA
    } has;

    struct ota 
    {
        bool force;
        char *guid;
        //String urls[5];
    } OTA;

    struct protocol_new 
    {
        char *name;
        char *host;
        int   port;
        char *Id;
        char *username;
        char *pwd;  
        char *pubTopic;
        char *di;
        char *ack_pub;
        char *hb_topic;
        char *subTopic;
        char *pubShadow;
        char *subShadow;
        char *pubAllShadow;
        char *subAllShadow;
    } Broker;

}Sync_Resp_new;

Sync_Resp_new SYNC_resp_new;


char recvBuf[MAXLINE];
char sendBuf[2048 + 1];
char *CPID =NULL, *BASEURL =NULL;
char *ENVT =NULL, *UNIQUEID =NULL;
// char *Base_url;
//char *Dpayload = " ", *Tpayload =NULL;
// static bool pubAck;
bool Flag_99 = true;
char LastTime[25] = "1970-01-01T00:00:00.000Z";

#if defined(CONFIG_PROVISION_CERTIFICATES)
#define MAX_OF_2 MAX(sizeof(CLOUD_CA_CERTIFICATE),\
		     sizeof(CLOUD_CLIENT_PRIVATE_KEY))
#define MAX_LEN MAX(MAX_OF_2, sizeof(CLOUD_CLIENT_PUBLIC_CERTIFICATE))
static uint8_t certificates[][MAX_LEN] = {{CLOUD_CA_CERTIFICATE},
				       {CLOUD_CLIENT_PRIVATE_KEY},
				       {CLOUD_CLIENT_PUBLIC_CERTIFICATE} };
static const size_t certLen[] = {
	sizeof(CLOUD_CA_CERTIFICATE) - 1, sizeof(CLOUD_CLIENT_PRIVATE_KEY) - 1,
	sizeof(CLOUD_CLIENT_PUBLIC_CERTIFICATE) - 1
};

int provision_certificates(void)
{
	int err;

    nrf_sec_tag_t sec_tag = 1;
    enum modem_key_mgmt_cred_type credentials[] = {
            MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
            MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT,
            MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT,
    };

    /* Delete certificates up to 5 certs from the modem storage for our sec key
     * in case there are any other remaining */
    for (int index = 0; index < 5; index++) 
    {
        (void) modem_key_mgmt_delete(sec_tag, index);
        
        printk("modem_key_mgmt_delete(%d, %d) => result=%d\n", sec_tag, index, err);

        printk("modem_key_mgmt_delete(%d, %d) => result=%d\n", sec_tag, index, err);
    }

    /* Write certificates */
    for (enum modem_key_mgmt_cred_type type = 0; type < ARRAY_SIZE(credentials); type++) 
    {
        err |= modem_key_mgmt_write(sec_tag, credentials[type], certificates[type], strlen(certificates[type]));
        LOG_INF("modem_key_mgmt_write => result=%d\n", err);
    }

	return 0;
}
#endif

char Date[25] = "20   ";
static char timebuf[sizeof "2011-10-08T07:07:01.000Z"];
int64_t currentTimeInms;

char *Get_Time(void)
{
	struct timespec tp = { 0 };
	struct tm ltm = { 0 };
	int err;

    err = date_time_now(&currentTimeInms);

    tp.tv_sec = currentTimeInms / 1000;
    localtime_r(&tp.tv_sec, &ltm);
	snprintk(Date, 25, "%04u-%02u-%02uT%02u:%02u:%02u.000Z",
		ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday,
		ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
    return Date;
} 


/****************************************************
    Function to publish data on the configured topic
*****************************************************/
int data_publish(struct mqtt_client *c, char *topic, enum mqtt_qos qos,
	uint8_t *data, size_t len)
{
	struct mqtt_publish_param param;

	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = topic;
	param.message.topic.topic.size = strlen(param.message.topic.topic.utf8);
	param.message.payload.data = data;
	param.message.payload.len = len;
	param.message_id = ++midNum; //sys_rand32_get();
	param.dup_flag = 0;
	param.retain_flag = 0;

	return mqtt_publish(c, &param);
}


/****************************************************
    Function to subscribe to the configured topic
*****************************************************/
int subscribe(void)
{
	struct mqtt_topic subscribe_topic[3] = {
		{.topic = {
			.utf8 = SYNC_resp_new.Broker.subTopic,
			.size = strlen(SYNC_resp_new.Broker.subTopic)
		    },
		.qos = MQTT_QOS_1_AT_LEAST_ONCE
        },
        {.topic = {
			.utf8 = SYNC_resp_new.Broker.subShadow,
			.size = strlen(SYNC_resp_new.Broker.subShadow)
		            },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        },
        {.topic = {
			.utf8 = SYNC_resp_new.Broker.subAllShadow,
			.size = strlen(SYNC_resp_new.Broker.subAllShadow)
		    },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        }
	};

	const struct mqtt_subscription_list subscription_list = {
		.list = &subscribe_topic,
		.list_count = ARRAY_SIZE(subscribe_topic),
		.message_id = 1234
	};

    int err;

    err = mqtt_subscribe(&client, &subscription_list);

    // //publish 201 to get attr if att == 1
    // if(SYNC_resp_new.has.attr == 1)
    // {
    //     printk("Sending 201 Command for GET Attribute\r\n");
    //     char *get_json = "{\"mt\":201}";
    //     data_publish(&client, SYNC_resp_new.Broker.di, 1, get_json, strlen(get_json));
    // }


	return err;
}


/**********************************************
    Function to read the published payload
***********************************************/
int publish_get_payload(struct mqtt_client *c, size_t length)
{
	uint8_t *buf = payloadBuf;
	uint8_t *end = buf + length;

	if (length > sizeof(payloadBuf)) 
    {
		return -EMSGSIZE;
	}

	while (buf < end) 
    {
		int ret = mqtt_read_publish_payload(c, buf, end - buf);

		if (ret < 0) 
        {
			int err;

			if (ret != -EAGAIN) 
            {
				return ret;
			}

            err = poll(&fds, 1, 30);
			if (err > 0 && (fds.revents & POLLIN) == POLLIN) 
            {
				continue;
			} 
            else 
            {
				return -EIO;
			}
		}

		if (ret == 0) 
        {
			return -EIO;
		}

		buf += ret;
	}

	return 0;
}


/**********************************************
            MQTT client event handler
***********************************************/
void mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt)
{
	int err;
	switch (evt->type) 
    {
        case MQTT_EVT_CONNACK:
            if (evt->result != 0) {
                printk("INFO_SDK [%s-%d] : MQTT connect failed %d\n", __func__, __LINE__, evt->result);
                break;
            }

            connected = true;
            printk("INFO_SDK [%s-%d] : MQTT client connected!\n", __func__, __LINE__);
            subscribe();
            break;

        case MQTT_EVT_DISCONNECT:
            printk("INFO_SDK [%s-%d] : MQTT client disconnected %d\n", __func__, __LINE__, evt->result);

            err = mqtt_disconnect(c);
            if (err) {
                printk("ERR_SDK [%s-%d] : Could not disconnect: %d\n", __func__, __LINE__, err);
            }

            connected = false;
            break;

        case MQTT_EVT_PUBLISH: {
            const struct mqtt_publish_param *pubpara;
            memset(&pubpara, 0, sizeof(pubpara));
            pubpara = &evt->param.publish;
                    
            printk("INFO_SDK [%s:%d] : MQTT PUBLISH result=%d len=%d\n", __func__,
                __LINE__, evt->result, pubpara->message.payload.len);
            err = publish_get_payload(c, pubpara->message.payload.len);

            if (pubpara->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE)
            {
                const struct mqtt_puback_param ack = {
                    .message_id = pubpara->message_id
                };
 
                /* Send acknowledgment. */
                mqtt_publish_qos1_ack(&client, &ack);
		    }

            if (err >= 0)
            {
                data_print("Received: ", payloadBuf, pubpara->message.topic.topic.utf8, pubpara->message.payload.len);
            } 
            else 
            {
                printk("ERR_SDK [%s-%d] : mqtt_read_publish_payload: Failed! %d\n", __func__, __LINE__, err);
                printk("ERR_SDK [%s-%d] : Disconnecting MQTT client...\n", __func__, __LINE__);

                err = mqtt_disconnect(c);
                if (err) 
                {
                    printk("ERR_SDK [%s-%d] : Could not disconnect: %d\n", __func__, __LINE__, err);
                }
            }
            
        } break;

        case MQTT_EVT_PUBACK:
            if (evt->result != 0) 
            {
                printk("ERR_SDK [%s-%d] : MQTT PUBACK error %d\n", __func__, __LINE__, evt->result);
                break;
            }
            printk("INFO_SDK [%s-%d] : PUBACK packet id: %u\n", __func__, __LINE__, evt->param.puback.message_id);
            break;

        case MQTT_EVT_SUBACK:
            if (evt->result != 0) 
            {
                printk("ERR_SDK [%s-%d] : MQTT SUBACK error %d\n", __func__, __LINE__, evt->result);
                break;
            }
            printk("INFO_SDK [%s-%d] : SUBACK packet id: %u\n", __func__, __LINE__, evt->param.suback.message_id);
            break;

        default:
            printk("INFO_SDK [%s-%d] : default: %d\n", __func__, __LINE__, evt->type);
            break;
	}
}

/**********************************************
            MQTT Broker Init
***********************************************/
void broker_init(void)
{
	int err;
	struct addrinfo *result;
	struct addrinfo *addr;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	};

    // DNS getaddrinfo
	err = getaddrinfo(SYNC_resp_new.Broker.host, NULL, &hints, &result);
	
	if (err) {
        printk("ERR_SDK [%s-%d] : getaddrinfo failed %d\n", __func__, __LINE__, err);
		return;
	}

	addr = result;
	err = -ENOENT;

	
	while (addr != NULL) {
		if (addr->ai_addrlen == sizeof(struct sockaddr_in)) {
			struct sockaddr_in *broker4 =
				((struct sockaddr_in *)&broker);
			char ipv4_addr[NET_IPV4_ADDR_LEN];

			broker4->sin_addr.s_addr =
				((struct sockaddr_in *)addr->ai_addr)
				->sin_addr.s_addr;
			broker4->sin_family = AF_INET;
			broker4->sin_port = htons(IOTCONNECT_SERVER_MQTT_PORT);

			inet_ntop(AF_INET, &broker4->sin_addr.s_addr,
				  ipv4_addr, sizeof(ipv4_addr));
            printk("INFO_SDK [%s-%d] : IPv4 Address found %s\n", __func__, __LINE__, ipv4_addr);

			break;
		} else {
			printk("INFO_SDK [%s-%d] : ai_addrlen = %u should be %u or %u\n",
                __func__, __LINE__,
				(unsigned int)addr->ai_addrlen,
				(unsigned int)sizeof(struct sockaddr_in),
				(unsigned int)sizeof(struct sockaddr_in6));
		}

		addr = addr->ai_next;
		break;
	}

	
	freeaddrinfo(result);
}


/**********************************************
            MQTT client Init
***********************************************/

#if 1 //was_mod
struct mqtt_utf8 mqtt_user_name;
struct mqtt_utf8 mqtt_password;
#endif

void client_init(struct mqtt_client *client)
{
	mqtt_client_init(client);

	broker_init();

	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;

    if((SYNC_resp_new.meta.at == 3) || (SYNC_resp_new.meta.at == 2))
    {    
        client->client_id.utf8 = SYNC_resp_new.Broker.Id;
        client->client_id.size = strlen(client->client_id.utf8);
       
        mqtt_user_name.utf8 = SYNC_resp_new.Broker.username;
        mqtt_user_name.size = strlen(mqtt_user_name.utf8);
          
        client->user_name = &mqtt_user_name;
        client->password = NULL;
    }
    else if(SYNC_resp_new.meta.at == 1)
    {
        client->client_id.utf8 =  SYNC_resp_new.Broker.Id;
        client->client_id.size =  strlen(client->client_id.utf8);

        mqtt_user_name.utf8 = SYNC_resp_new.Broker.username;
        mqtt_user_name.size = strlen(mqtt_user_name.utf8);


        mqtt_password.utf8 = SYNC_resp_new.Broker.pwd;
        mqtt_password.size = strlen(SYNC_resp_new.Broker.pwd);
          
        client->user_name = &mqtt_user_name;
        client->password = &mqtt_password;
    }
	client->protocol_version = MQTT_VERSION_3_1_1;

	client->rx_buf = rxBuffer;
	client->rx_buf_size = sizeof(rxBuffer);
	client->tx_buf = txBuffer;
	client->tx_buf_size = sizeof(txBuffer);
	
    #if defined(CONFIG_MQTT_LIB_TLS)
        struct mqtt_sec_config *tls_config = &client->transport.tls.config;

        client->transport.type = MQTT_TRANSPORT_SECURE;
    #if 1 //wads_mod
        tls_config->peer_verify = 1;
    #else
        tls_config->peer_verify = 2;
    #endif  
        tls_config->cipher_count = 0;
        tls_config->cipher_list = NULL;
        tls_config->sec_tag_count = ARRAY_SIZE(sec_tag_list);
        tls_config->sec_tag_list = sec_tag_list;
        tls_config->hostname = SYNC_resp_new.Broker.host;
    #else
        client->transport.type = MQTT_TRANSPORT_NON_SECURE;
    #endif
}

int fds_init(struct mqtt_client *c)
{
	if (c->transport.type == MQTT_TRANSPORT_NON_SECURE) 
    {
		fds.fd = c->transport.tcp.sock;
	} 
    else 
    {
        #if defined(CONFIG_MQTT_LIB_TLS)
            fds.fd = c->transport.tls.sock;
        #else
                return -ENOTSUP;
        #endif
	}

	fds.events = POLLIN;

	return 0;
}


/**********************************************
        MQTT will work in while loop
***********************************************/
int MQTT_Status(void)
{
    int err = 0;

    err = poll(&fds, 1, mqtt_keepalive_time_left(&client));
    if (err < 0)
    {
        printk("ERR_SDK [%s-%d] : ERROR: poll %d\n", __func__, __LINE__, err);
        return 1;
	}

    err = mqtt_live(&client);
    if ((err != 0) && (err != -EAGAIN)) 
    {
        printk("ERR_SDK [%s-%d] : ERROR: mqtt_live %d\n", __func__, __LINE__, err);
        return 1;
	}

    if ((fds.revents & POLLIN) == POLLIN) 
    {
        err = mqtt_input(&client);
	    if (err != 0) 
        {
            printk("ERR_SDK [%s-%d] : ERROR: mqtt_input %d\n", __func__, __LINE__, err);
            return 1;
		}
	}
    
    if ((fds.revents & POLLERR) == POLLERR)
    {
        printk("ERR_SDK [%s-%d] : Socket Error : POLLERR\n", __func__, __LINE__);
        return 1;
	}

    if ((fds.revents & POLLHUP ) == POLLHUP ) 
    {
        printk("ERR_SDK [%s-%d] : Socket Error : POLLHUP\n", __func__, __LINE__);
        return 1;
	}
    
    if ((fds.revents & POLLNVAL) == POLLNVAL) 
    {
        printk("ERR_SDK [%s-%d] : Socket Error : POLLNVAL\n", __func__, __LINE__);
        return 1;
	}
    
    return 0;
}


/**********************************************
            Start the MQTT protocol
***********************************************/
int MQTT_Init()
{
	int err;
        
    client.broker = SYNC_resp_new.Broker.host;
    client.client_id.utf8 = SYNC_resp_new.Broker.Id;
    client.user_name = SYNC_resp_new.Broker.username;

    if(&client == NULL)
    {
        printk("ERR_SDK [%s-%d] : MQTT Client NULL\n", __func__, __LINE__);
        return 1;
    }
            
    client_init(&client);

	err = mqtt_connect(&client);
	if (err != 0)
    {
        printk("ERR_SDK [%s-%d] : mqtt_connect : Fail %d\n", __func__, __LINE__, err);
		return 1;
	}


	err = fds_init(&client);
	if (err != 0)
    {
        printk("ERR_SDK [%s-%d] : fds_init : Error %d\n", __func__, __LINE__, err);
		return 1;
	}

    return 0;
}


/**********************************************
    Initialization of IoTConnect SDK
***********************************************/
int IoTConnect_Init(char *cpID, char *UniqueID, char *Env,IOTConnectCallback CallBack, IOTConnectCallback TwinCallBack)
{
    int retry;
    int res;
    char *syncResp = NULL;
    char *baseUrl = NULL;

    printk("INFO_SDK [%s-%d] : Start IoTConnect_Init\n", __func__, __LINE__);

    if((strlen(cpID) == 0)||(strlen(UniqueID) == 0)||(strlen(Env) == 0))
    {
        printk("ERR_SDK [%s-%d] : CPID | Unique ID | ENV can not be blank\n", __func__, __LINE__);
        return 1;
    }
    
    if(Flag_99)
    {
        k_msleep(200);
        baseUrl = get_base_url(HTTPS_HOSTNAME,cpID,Env);
        if (baseUrl == NULL)
        {
            printk("ERR_SDK [%s-%d] : Base Url is NULL\n", __func__, __LINE__);
            return 1;
        }
            
        k_msleep(200);
        syncResp = Sync_call(cpID, UniqueID, baseUrl);
        if (syncResp == NULL)
        {
            printk("ERR_SDK [%s-%d] : sync_resp\n", __func__, __LINE__); 
            return 1;
        }
        
        ENVT = Env;
        CPID = cpID;
        BASEURL = baseUrl;
        UNIQUEID = UniqueID;
        
        res = Save_Sync_Responce(syncResp);

        if ( !SYNC_resp_new.ec)
        {
            return 0;
        }      
        else
        {
            return 1;
        }                     

    }
    return 1;
}


/**********************************************
    Start MQTT init and connect with client
***********************************************/
int IoTConnect_Connect()
{
    if(MQTT_Init() == 0)
    {
        printk("INFO_SDK [%s-%d] : [%s-%s] MQTT Init : Success\n", __func__, __LINE__, CPID, UNIQUEID);
    }
    else
    {
        printk("ERR_SDK [%s-%d] : [%s-%s] MQTT Init : Fail\n", __func__, __LINE__, CPID, UNIQUEID);
        return 1;
    }
    k_msleep(100);


    // //publish 201 to get attr if att == 1
    // if(SYNC_resp_new.has.attr == 1)
    // {
    //     char *get_json = "{\"mt\":201}";
    //     data_publish(&client, SYNC_resp_new.Broker.di, 0, get_json, strlen(get_json));
    // }

    // //publish 202 to get setting if set == 1
    // if(SYNC_resp_new.has.sett == 1)
    // {
    //     char *get_json = "{\"mt\":202}";
    //     data_publish(&client, SYNC_resp_new.Broker.di, 0, get_json, strlen(get_json));
    // }

    // //publish 203 to get rule if r == 1
    // if(SYNC_resp_new.has.rule == 1)
    // {
    //     char *get_json = "{\"mt\":203}";
    //     data_publish(&client, SYNC_resp_new.Broker.di, 0, get_json, strlen(get_json));
    // }

    // //publish 204 to gw c device  if d == 1
    // if(SYNC_resp_new.has.d == 1)
    // {
    //     char *get_json = "{\"mt\":204}";
    //     data_publish(&client, SYNC_resp_new.Broker.di, 0, get_json, strlen(get_json));
    // }

    // //publish 205 to get ota if ota == 1
    // if(SYNC_resp_new.has.ota == 1)
    // {
    //     char *get_json = "{\"mt\":205}";
    //     data_publish(&client, SYNC_resp_new.Broker.di, 0, get_json, strlen(get_json));
    // }

    return 0;
}


/******************************************
    Setup TLS options on a given socket
*******************************************/
int tls_setup(int fd)
{
	int err;
	int verify;

	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};
        
    enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = OPTIONAL;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) 
    {
        printk("ERR_SDK [%s-%d] : Failed to setup peer verification, err %d\n", __func__, __LINE__, errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) 
    {
        printk("ERR_SDK [%s-%d] : Failed to setup TLS sec tag, err %d\n", __func__, __LINE__, errno);
		return err;
	}

	return 0;
}


/**************************************************************
    you need to pass cpid , env and the HOST at GET_TEMPLATE
***************************************************************/
#define GET_TEMPLATE                                            \
	"GET /api/v2.1/dsdk/cpid/%s/env/%s HTTP/1.1\r\n"            \
	"Host: %s\r\n"                                              \
	"Content-Type: application/json; charset=utf-8\r\n"         \
    "Connection: close\r\n\r\n"

char* get_base_url(char*Host, char *cpid, char *env)
{
    int err, fd, bytes;
    char *p;
    size_t off;
    struct addrinfo *IoT_res;
    struct addrinfo IoT_hints = {
            .ai_flags = AI_NUMERICSERV,
            .ai_socktype = SOCK_STREAM,
    };  
    char *baseUrl = NULL;
    char peer_addr[INET6_ADDRSTRLEN];

    printk("INFO_SDK [%s-%d] : Get URL address ...\n", __func__, __LINE__);

    err = getaddrinfo(HTTPS_HOSTNAME, HTTPS_PORT, &IoT_hints, &IoT_res);
	if (err) 
    {
        printk("ERR_SDK [%s-%d] : getaddrinfo() failed, err %d\n", __func__, __LINE__, errno);
		return NULL;
	} 
   
    inet_ntop(IoT_res->ai_family, &((struct sockaddr_in *)(IoT_res->ai_addr))->sin_addr, peer_addr,
			INET6_ADDRSTRLEN);
    printk("INFO_SDK [%s-%d] : Resolved %s (%s)\n", __func__, __LINE__, peer_addr, net_family2str(IoT_res->ai_family));


    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (fd == -1) 
    {
        printk("ERR_SDK [%s-%d] : Failed to open socket!\n", __func__, __LINE__);
        goto clean_up;
    }
    err = tls_setup(fd);
    if (err) 
    {
        goto clean_up;
    }

    printk("INFO_SDK [%s-%d] : Connecting to %s:%d\n\n", __func__, __LINE__, HTTPS_HOSTNAME, ntohs(((struct sockaddr_in *)(IoT_res->ai_addr))->sin_port));
    err = connect(fd, IoT_res->ai_addr, IoT_res->ai_addrlen);
    if (err) 
    {
        printk("ERR_SDK [%s-%d] : connect() failed, err %d\n", __func__, __LINE__, errno);
        goto clean_up;
    }
    printk("INFO_SDK [%s-%d] :   .. OK\n", __func__, __LINE__);
    int HTTP_HEAD_LEN = snprintk(sendBuf,
	    500, /*total length should not exceed MTU size*/
	    GET_TEMPLATE, cpid, env,
	    HTTPS_HOSTNAME
            );
    off = 0;  
    do {
            bytes = send(fd, &sendBuf[off], HTTP_HEAD_LEN - off, 0);
            if (bytes < 0) 
            {
                printk("ERR_SDK [%s-%d] : send() failed, err %d\n", __func__, __LINE__, errno);
                goto clean_up;
            }
            off += bytes;
	} while (off < HTTP_HEAD_LEN);

    off = 0;
    do {
            bytes = recv(fd, &recvBuf[off], MAXLINE - off, 0);
            if (bytes < 0) 
            {
                printk("ERR_SDK [%s-%d] : recv() failed, err %d\n", __func__, __LINE__, errno);
                goto clean_up;
            }
            off += bytes;
	} while (bytes != 0 );

    p = strstr(recvBuf, "\r\n{");
    cJSON *root = cJSON_Parse(p);
    if(root == NULL)
    {
        printk("ERR_SDK [%s-%d] : This is NOT json format", __func__, __LINE__);
        return NULL;
	} 

    
    cJSON *baseData = NULL;
    baseData = cJSON_GetObjectItem(root, "d");  // JSON : d
    baseUrl = cJSON_GetObjectItem(baseData, "bu")->valuestring; // JSON : d : bu
    char *PF = NULL;
    PF = cJSON_GetObjectItem(baseData, "pf")->valuestring; // JSON : d : pf
    close(fd);
    cJSON_Delete(root);

    if (baseUrl != NULL)
    {
        return baseUrl;
    }
    else
    {
        printk("ERR_SDK [%s-%d] : Base_URL not found.", __func__, __LINE__);
        return NULL;
    }
    
    clean_up:
        freeaddrinfo(IoT_res);
        return baseUrl;
}


/********************************************************************
    you need to pass remain_url , Unique Id, host
*********************************************************************/
#define GET_SYNC_TEMPLATE                                       \
	"GET /%s/uid/%s HTTP/1.1\r\n"                               \
	"Host: %s\r\n"                                              \
	"Content-Type: application/json; charset=utf-8\r\n"         \
    "Connection: close\r\n\r\n"

/***************************************************************
    This templates can be used for raw HTTP headers 
    in case that the platform doesn't GET/POST functionality
    you need to pass URL returned from discovery host,
    host form discovery host, post_data_lan and post_data
****************************************************************/

char* Sync_call(char *cpid, char *uniqueid, char *baseUrl)
{
    int err;
    int fdP;
    char *synCallResp = NULL;
    int bytes;
    size_t off;
    struct addrinfo *res;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };  
    char peer_addr[INET6_ADDRSTRLEN];
    
    char *agentHost = NULL;
    char *agentPath = NULL;
    agentHost = strtok(baseUrl, "/");
    agentHost = strtok(NULL, "/");
    agentPath = strtok(NULL, "");

    if (agentHost == NULL) {
        printk("ERR_SDK [%s-%d] : AgentHost not found.", __func__, __LINE__);
    }

    err = getaddrinfo(agentHost, HTTPS_PORT, &hints, &res);
	if (err) {
        printk("ERR_SDK [%s-%d] : getaddrinfo() failed, err %d\n", __func__, __LINE__, errno);
		return 0;
	} 
   
    inet_ntop(res->ai_family, &((struct sockaddr_in *)(res->ai_addr))->sin_addr, peer_addr, INET6_ADDRSTRLEN);
    printk("INFO_SDK [%s-%d] : Resolved %s (%s)\n", __func__, __LINE__, peer_addr, net_family2str(res->ai_family));


    fdP = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (fdP == -1) {
        printk("ERR_SDK [%s-%d] : Failed to open socket!\n", __func__, __LINE__);
        goto clean_up;
    }
    err = tls_setup(fdP);
    if (err) {
        goto clean_up;
    }

    printk("INFO_SDK [%s-%d] : Connecting to %s:%d\n", __func__, __LINE__, agentHost, ntohs(((struct sockaddr_in *)(res->ai_addr))->sin_port));
    err = connect(fdP, res->ai_addr, res->ai_addrlen);
    if (err) {
        printk("ERR_SDK [%s-%d] : connect() failed, err: %d\n", __func__, __LINE__, errno);
        goto clean_up;
    }
    printk("INFO_SDK [%s-%d] :   .. OK\n", __func__, __LINE__);
    //char sendBuf[2047 + 1];
    int HTTP_HEAD_LEN = snprintf(sendBuf, sizeof(sendBuf), GET_SYNC_TEMPLATE, agentPath, uniqueid, agentHost);

    off = 0;  
    do {
        bytes = send(fdP, &sendBuf[off], HTTP_HEAD_LEN - off, 0);
        if (bytes < 0) {
            printk("ERR_SDK [%s-%d] : send() failed, err %d\n", __func__, __LINE__, errno);
            goto clean_up;
        }
        off += bytes;
	} while (off < HTTP_HEAD_LEN);

    off = 0;
    do {
        bytes = recv(fdP, &recvBuf[off], MAXLINE - off, 0);
        if (bytes < 0) {
            printk("ERR_SDK [%s-%d] : recv() failed, err %d\n", __func__, __LINE__, errno);
            goto clean_up;
        }
        off += bytes;
	} while (bytes != 0 );

    k_msleep(500);

    synCallResp = strstr(recvBuf, "\r\n{");

    return synCallResp;

clean_up:
	freeaddrinfo(res);
    close(fdP);
    return synCallResp;
}


/*************************************************
    Save syncResp in cache memory of device 
*************************************************/
int Save_Sync_Responce(char *syncData)
{
    cJSON *root = NULL;
    cJSON *Sync_data = NULL;
    cJSON *Sync_meta = NULL;
    cJSON *Sync_has = NULL;
    cJSON *Sync_para = NULL;
    cJSON *mqtt_topics = NULL;
    cJSON *shadow_topics = NULL;
    root = cJSON_Parse(syncData);

    k_msleep(100);

    // Received JSON
    // JSON : d
    Sync_data = cJSON_GetObjectItemCaseSensitive(root, "d"); 
    // JSON : d : ec
    SYNC_resp_new.ec = cJSON_GetObjectItem(Sync_data, "ec")->valueint;

    if(SYNC_resp_new.ec == 0)
    {
        printk("INFO_SDK [%s-%d] : Device Registered Successfully...\n", __func__, __LINE__);

        // from JSON >> META parameters data
        // JSON : d : meta
        Sync_meta = cJSON_GetObjectItemCaseSensitive(Sync_data, "meta"); 
        // JSON : d : meta : at
        SYNC_resp_new.meta.at = cJSON_GetObjectItem(Sync_meta, "at")->valueint; 
        // JSON : d : meta : df
        SYNC_resp_new.meta.df = cJSON_GetObjectItem(Sync_meta, "df")->valueint; 
 
        // from JSON >> HAS parameters data
        // JSON : d : has
        Sync_has = cJSON_GetObjectItemCaseSensitive(Sync_data, "has"); // JSON : d : has

        // JSON : d : has : d
        SYNC_resp_new.has.d = cJSON_GetObjectItem(Sync_has, "d")->valueint; 
        // JSON : d : has : attr
        SYNC_resp_new.has.attr = cJSON_GetObjectItem(Sync_has, "attr")->valueint; 
        // JSON : d : has : set
        SYNC_resp_new.has.sett = cJSON_GetObjectItem(Sync_has, "set")->valueint; 
        // JSON : d : has : r
        SYNC_resp_new.has.rule = cJSON_GetObjectItem(Sync_has, "r")->valueint; 
        // JSON : d : has : ota
        SYNC_resp_new.has.ota = cJSON_GetObjectItem(Sync_has, "ota")->valueint; 
    
        // from JSON >> MQTT connection parameters data
        // JSON : d : p
        Sync_para = cJSON_GetObjectItemCaseSensitive(Sync_data, "p"); 
        // JSON : d : p : n
        SYNC_resp_new.Broker.name = cJSON_GetObjectItem(Sync_para, "n")->valuestring; 
        // JSON : d : p : h
        SYNC_resp_new.Broker.host = cJSON_GetObjectItem(Sync_para, "h")->valuestring; 
        // JSON : d : p : p
        SYNC_resp_new.Broker.port = cJSON_GetObjectItem(Sync_para, "p")->valueint; 
        // JSON : d : p : id
        SYNC_resp_new.Broker.Id = cJSON_GetObjectItem(Sync_para, "id")->valuestring; 
        // JSON : d : p : un
        SYNC_resp_new.Broker.username = cJSON_GetObjectItem(Sync_para, "un")->valuestring; 
        
        if(cJSON_HasObjectItem(Sync_para, "pwd"))
        {
            // JSON : d : p : pwd
            SYNC_resp_new.Broker.pwd = cJSON_GetObjectItem(Sync_para, "pwd")->valuestring; 
        }

        // from JSON >> MQTT pub/sub parameters data
        // JSON : d : p : topics
        mqtt_topics = cJSON_GetObjectItemCaseSensitive(Sync_para, "topics"); 
        // JSON : d : p : topics : rpt
        SYNC_resp_new.Broker.pubTopic = cJSON_GetObjectItem(mqtt_topics, "rpt")->valuestring; 
        // JSON : d : p : topics : ack
        SYNC_resp_new.Broker.ack_pub = cJSON_GetObjectItem(mqtt_topics, "ack")->valuestring; 
        // JSON : d : p : topics : hb
        SYNC_resp_new.Broker.hb_topic = cJSON_GetObjectItem(mqtt_topics, "hb")->valuestring; 
        // JSON : d : p : topics : di
        SYNC_resp_new.Broker.di = cJSON_GetObjectItem(mqtt_topics, "di")->valuestring; 
        // JSON : d : p : topics : c2d
        SYNC_resp_new.Broker.subTopic = cJSON_GetObjectItem(mqtt_topics, "c2d")->valuestring; 

        if(cJSON_HasObjectItem(mqtt_topics, "set"))
        {
            // JSON : d : p : topics : set
            shadow_topics = cJSON_GetObjectItemCaseSensitive(mqtt_topics, "set"); 
            // JSON : d : p : topics : set : pub
            SYNC_resp_new.Broker.pubShadow = cJSON_GetObjectItem(shadow_topics, "pub")->valuestring; 
            // JSON : d : p : topics : set : sub
            SYNC_resp_new.Broker.subShadow = cJSON_GetObjectItem(shadow_topics, "sub")->valuestring; 
            // JSON : d : p : topics : set : pubForAll
            SYNC_resp_new.Broker.pubAllShadow = cJSON_GetObjectItem(shadow_topics, "pubForAll")->valuestring; 
            // JSON : d : p : topics : set : subForAll
            SYNC_resp_new.Broker.subAllShadow = cJSON_GetObjectItem(shadow_topics, "subForAll")->valuestring; 
        }
    }
    else if(SYNC_resp_new.ec == 1)
    {
        printk("INFO_SDK [%s-%d] : Device_Not_Register\n", __func__, __LINE__);
    }
    else if(SYNC_resp_new.ec == 2)
    {
        printk("INFO_SDK [%s-%d] : Auto_Register\n", __func__, __LINE__);
    }
    else if(SYNC_resp_new.ec == 3)
    {
        printk("INFO_SDK [%s-%d] : Device_Not_Found\n", __func__, __LINE__);
    }
    else if(SYNC_resp_new.ec == 4)
    {
        printk("INFO_SDK [%s-%d] : Device_Inactive\n", __func__, __LINE__);
    }
    else if(SYNC_resp_new.ec == 5)
    {
        printk("INFO_SDK [%s-%d] : Object_Moved\n", __func__, __LINE__);
    }
    else if(SYNC_resp_new.ec == 6)
    {
        printk("INFO_SDK [%s-%d] : Cpid_Not_Found\n", __func__, __LINE__);
    }
    else
    {
        printk("INFO_SDK [%s-%d] : No Device_status has been matched..!\n", __func__, __LINE__);
    }

    return 0;

}


/*************************************************
        Received data in callback from C2D 
*************************************************/
void data_print(uint8_t *prefix, uint8_t *data, char *topic, size_t len)
{
    char buf[len];
    cJSON *root,*root2;
    char *SMS;
    memcpy(buf, data, len);
    if (strlen(buf) > 5)
    {
        if(! strncmp(topic, SYNC_resp_new.Broker.subShadow, strlen(SYNC_resp_new.Broker.subShadow)))
        {        
            printk("INFO_SDK [%s-%d] : Shadow DATA\n", __func__, __LINE__);
            
            root = cJSON_CreateObject();
            root2 = cJSON_Parse(buf);
            cJSON_AddItemToObject(root,"desired",root2);
            cJSON_AddStringToObject(root,"uniqueId",UNIQUEID);
            SMS = cJSON_PrintUnformatted(root);   
            (*Twin_CallBack)(topic, SMS);
            k_msleep(10);
            
            cJSON_Delete(root);
            free(SMS);
        }
        else if(! strncmp(topic, SYNC_resp_new.Broker.subAllShadow, strlen(SYNC_resp_new.Broker.subAllShadow)))
        {        
            printk("INFO_SDK [%s-%d] : ALL Shadow DATA\n", __func__, __LINE__);
            root = cJSON_Parse(buf);
            cJSON_AddStringToObject(root,"uniqueId",UNIQUEID);
            SMS = cJSON_PrintUnformatted(root);         
            (*Twin_CallBack)(topic, SMS);
            k_msleep(10);
            
            cJSON_Delete(root);
            free(SMS);
        }
        else 
        {
            root = cJSON_Parse(buf);

            if(cJSON_HasObjectItem(root, "ct"))
            {
                int ct_value = (cJSON_GetObjectItem(root, "ct")->valueint);
                switch (ct_value) 
                {
                    case 0://Device command
                    printk("INFO_SDK [%s-%d] : Device Commad Received : %s\n", __func__, __LINE__, buf);
                    (*Device_CallBack)(topic, buf);
                    break;

                    case 1://OTA Command
                    printk("INFO_SDK [%s-%d] : OTA Command Received : : %s\n", __func__, __LINE__, buf);
                    (*Device_CallBack)(topic, buf);
                    break;

                    case 2://Module Command
                    printk("INFO_SDK [%s-%d] : Module Commad Received : %s\n", __func__, __LINE__, buf);
                    (*Device_CallBack)(topic, buf);
                    break;

                    case 101://Refresh Attribute
                    printk("INFO_SDK [%s-%d] : Refresh Attribute : %s\n", __func__, __LINE__, buf);
                    break;

                    case 102://Refresh Setting/Twin
                    printk("INFO_SDK [%s-%d] : Refresh Twin : %s\n", __func__, __LINE__, buf);
                    break;

                    case 104://Refresh Child Device
                    printk("INFO_SDK [%s-%d] : Refresh Child Device : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 105://Data Frequency Change
                    printk("INFO_SDK [%s-%d] : Data Frequency Change : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 106://Device Deleted
                    printk("INFO_SDK [%s-%d] : Device Delete : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 107://Device Disabled
                    printk("INFO_SDK [%s-%d] : Device Disable : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 108://Device Released
                    printk("INFO_SDK [%s-%d] : On Close : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 109://Stop Operation
                    printk("INFO_SDK [%s-%d] : Stop Operation : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 110://Start Heartbeat
                    printk("INFO_SDK [%s-%d] : Start Heartbeat : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 111://Stop Heartbeat
                    printk("INFO_SDK [%s-%d] : Stop Heartbeat : %s\n", __func__, __LINE__, buf);
                    break;
            
                    case 116://Device connection status command
                    printk("INFO_SDK [%s-%d] : Device connection status Commad Received : %s\n", __func__, __LINE__, buf);
                    (*Device_CallBack)(topic, buf);
                    break;
            
                    default:;
                }
            }
            else
            {
                root2 = (cJSON_GetObjectItem(root, "d"));
                int ctValue = (cJSON_GetObjectItem(root2, "ct")->valueint);

                if(ctValue == 201)
                {
                    printk("INFO_SDK [%s-%d] : Attribute Received : %s\n", __func__, __LINE__, buf);
                }
                if(ctValue == 202)
                {
                    printk("INFO_SDK [%s-%d] : Twin Received : %s\n", __func__, __LINE__, buf);
                }
                if(ctValue == 204)
                {
                    printk("INFO_SDK [%s-%d] : Child Received : %s\n", __func__, __LINE__, buf);
                }
            }
       }
    }
}


/*************************************************
        Get All twin property from C2D
*************************************************/
int getAllTwins(void)
{
    if ( ! data_publish(&client,"", 1, " ", strlen(" ")))
    {
        printk("INFO_SDK [%s-%d] : getAllTwins Publish : Success\n", __func__, __LINE__);
    }
    else
    {
        printk("ERR_SDK [%s-%d] : getAllTwins Publish : Fail\n", __func__, __LINE__);
        return 1;
    }
    return 0;
}


/*************************************************
        Disconnect SDk from IoTConnect
*************************************************/
int IoTConnect_Abort(void)
{
   printk("INFO_SDK [%s-%d] : SDK is Disconnected From IoTConnect\n", __func__, __LINE__);
   int sd = mqtt_disconnect(&client);
   Flag_99 = false;
   k_msleep(100);
   printk("INFO_SDK [%s-%d] : MQTT Disconnection %d\r\n", __func__, __LINE__, sd);
   return 0;
}


/*************************************************
        Get Sensor data and send to cloud
*************************************************/
int errPub;
int SendData(char *attributeJsonData)
{
    int err;
    if(Flag_99 && connected)
    { 
        char *NowTime = Get_Time();
        long int Timediff = GetTimeDiff(NowTime, LastTime);
        if (SYNC_resp_new.meta.df < Timediff) 
        {
            if(!SYNC_resp_new.ec)
            {
                cJSON *To_HUB_json, *sdk, *device, *device2, *data1, *Device_data1;
                char *hubJsonData = " ";
                cJSON *root = cJSON_Parse(attributeJsonData);
                To_HUB_json = cJSON_CreateObject();
                if (To_HUB_json == NULL)
                {
                    printk("ERR_SDK [%s-%d] : Unable to allocate To_HUB_json Object\n", __func__, __LINE__);
                    return 1;
                }

                cJSON *parameter = cJSON_GetArrayItem(root, 0);

                cJSON_AddItemToObject(To_HUB_json, "d", device = cJSON_CreateArray());
                cJSON_AddStringToObject(To_HUB_json, "dt", cJSON_GetObjectItem(parameter, "time")->valuestring);

                int parametersCount = cJSON_GetArraySize(root);    

                for (int i = 0; i < parametersCount; i++) 
                {
                    cJSON *parameter = cJSON_GetArrayItem(root, i);
                    cJSON_AddItemToArray(device, Device_data1 = cJSON_CreateObject());
                    cJSON_AddStringToObject(Device_data1, "id", cJSON_GetObjectItem(parameter, "uniqueId")->valuestring);
                    cJSON_AddStringToObject(Device_data1, "dt", cJSON_GetObjectItem(parameter, "time")->valuestring);
                    cJSON_AddStringToObject(Device_data1, "tg", "");
                    data1 = cJSON_GetObjectItem(parameter, "data");
                    cJSON_AddItemToObject(Device_data1, "d", data1);
                }
                hubJsonData =  cJSON_PrintUnformatted(To_HUB_json);
                cJSON_Delete(To_HUB_json);
                printk("INFO_SDK [%s-%d] : Publishing data...\n", __func__, __LINE__);
                errPub = data_publish(&client, SYNC_resp_new.Broker.pubTopic, 1, hubJsonData, strlen(hubJsonData));

                for(int ss=0;ss<25;ss++)
                    LastTime[ss] = NowTime[ss];
                k_msleep(10);
  
                if ( errPub == 0)
                {
                    printk("INFO_SDK [%s-%d] : Publish data id %d : Success\n", __func__, __LINE__, midNum);
                } 
                else
                {
                    printk("ERR_SDK [%s-%d] : Publish data err %d : Fail\n", __func__, __LINE__, errPub);
                }
            }
        }
    }
    else
    {
        printk("INFO_SDK [%s-%d] : Device already disconnected\n", __func__, __LINE__);
        return 1;
    }
    return 0;
}
  

/**********************************************************
        calculate the difference between two datetime
***********************************************************/
int GetTimeDiff(char newTime[25], char oldTime[25])
{
    // Create a newTm, oldTm struct to hold the parsed new and old date and time
    struct tm newTm, oldTm;
 
    // Parse the new date&time input string
    if (strptime(newTime, "%Y-%m-%dT%H:%M:%S.000Z", &newTm) == NULL) {
        printk("ERR_SDK [%s-%d] : Failed to parse date string\n", __func__, __LINE__);
        return 1;
    }
 
    // Convert newTm struct to epoch time
    time_t newEpochTime = mktime(&newTm);
 
    if (newEpochTime == -1) {
        printk("ERR_SDK [%s-%d] : Failed to convert newTm struct to epoch time\n", __func__, __LINE__);
        return 1;
    }

    // Parse the old date&time input string
    if (strptime(oldTime, "%Y-%m-%dT%H:%M:%S.000Z", &oldTm) == NULL) {
        printk("ERR_SDK [%s-%d] : Failed to parse date string\n", __func__, __LINE__);
        return 1;
    }
 
    // Convert oldTm struct to epoch time
    time_t oldEpochTime = mktime(&oldTm);
 
    if (oldEpochTime == -1) {
        printk("ERR_SDK [%s-%d] : Failed to convert oldTm struct to epoch time\n", __func__, __LINE__);
        return 1;
    }
 
    int timeDiff = (newEpochTime - oldEpochTime);
    printk("INFO_SDK [%s-%d] : Time Difference : %d\n", __func__, __LINE__, timeDiff);
    return timeDiff;
}


/*************************************************
    This will UpdateTwin String property to IoTConnect
*************************************************/
int UpdateTwin_Str(char *key,char *value)
{
    char *twinJsonData;
    cJSON *root = cJSON_CreateObject();

    if (root == NULL)
    {
        printk("ERR_SDK [%s-%d] : Unable to allocate Update Twin Object\n",__func__, __LINE__);
        return 1;    
    }

    cJSON_AddStringToObject(root, key, value);
    twinJsonData = cJSON_PrintUnformatted(root);
 
    if ( ! data_publish(&client, SYNC_resp_new.Broker.pubShadow, 0, twinJsonData, strlen(twinJsonData)))
    {
        printk("INFO_SDK [%s-%d] : Twin Update Data Publish : Success\n",__func__, __LINE__);
    }
    else{
        printk("ERR_SDK [%s-%d] : Twin Update Data Publish : Fail\n",__func__, __LINE__);
        return 1;
    }

    cJSON_Delete(root);
    free(twinJsonData);

    return 0;
}


/*************************************************
    This will UpdateTwin Integer property to IoTConnect
*************************************************/
int UpdateTwin_Int(char *key, int value){
    char *twinJsonData;
    cJSON *root;
    root  = cJSON_CreateObject();

    if (root == NULL)
    {
        printk("ERR_SDK [%s-%d] : Unable to allocate Update Twin Object\n",__func__, __LINE__);
        return 1;    
    }

    cJSON_AddNumberToObject(root, key, value);
    twinJsonData = cJSON_PrintUnformatted(root);

 
    if ( ! data_publish(&client, SYNC_resp_new.Broker.pubShadow, 0, twinJsonData, strlen(twinJsonData)))
    {
        printk("INFO_SDK [%s-%d] : Twin Update Data Publish : Success\n",__func__, __LINE__);
    }
    else{
        printk("ERR_SDK [%s-%d] : Twin Update Data Publish : Fail\n",__func__, __LINE__);
        return 1;
    }

    cJSON_Delete(root);
    free(twinJsonData);

    return 0;
}


/**************************************************
    this will send the ACK of receiving Commands
**************************************************/
int SendAck(char *ackData, int messageType)
{
    cJSON *ackJson;
    char *ackJsonData;
    ackJson = cJSON_CreateObject();
    if (ackJson == NULL)
    {
        printk("ERR_SDK [%s-%d] : Unable to allocate ackJson Object in SendAck\n",__func__, __LINE__);
        return 1;    
    }

    cJSON_AddStringToObject(ackJson, "dt",Get_Time());
    cJSON *root = cJSON_Parse(ackData);
    cJSON_AddItemToObject(ackJson, "d", root);
    ackJsonData = cJSON_PrintUnformatted(ackJson);

    cJSON_Delete(root);
    cJSON_Delete(ackJson);

    if ( ! data_publish(&client, SYNC_resp_new.Broker.ack_pub, 1, ackJsonData, strlen(ackJsonData)))
    {
        printk("INFO_SDK [%s-%d] : Ack_Json_Data Publish : Success\n\n",__func__, __LINE__);
    }
    else
    {
        printk("ERR_SDK [%s-%d] : Ack_Json_Data Publish : Fail\n",__func__, __LINE__);
        return 1;
    }

    return 0;
}
