#include <string.h>
#include <zephyr/kernel.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <zephyr/net/socket.h>
//#include <net/bsdlib.h>
#include <zephyr/net/tls_credentials.h>
#include "cJSON.h"
#include <modem/lte_lc.h>
#include <modem/pdn.h>
#include <date_time.h>

//#include <at_cmd.h>
//#include <at_notif.h>
#include <zephyr/logging/log.h> 
#include <modem/modem_key_mgmt.h>
#include <zephyr/net/mqtt.h>
#include "../src/IoTConnectSDK.h"
#include "../cert/certificates.h"

LOG_MODULE_REGISTER(Logs2); 


static sec_tag_t sec_tag_list[] = { CONFIG_SEC_TAG };
struct mqtt_client client;
static struct sockaddr_storage broker;
static bool connected;
static struct pollfd fds;
struct Sync_Resp SYNC_resp;
uint16_t mid_num = 0;


#define CONFIG_PROVISION_CERTIFICATES
#define CONFIG_BSD_LIBRARY
#define CONFIG_MQTT_LIB_TLS
#if defined(CONFIG_MQTT_LIB_TLS)

#endif
/* Buffers for MQTT client. */
static uint8_t rx_buffer[MAXLINE];
static uint8_t tx_buffer[MAXLINE];
static uint8_t payload_buf[MAXLINE];
//BUILD_ASSERT_MSG(sizeof(CLOUD_CA_CERTIFICATE) < KB(4), "Certificate too large");
BUILD_ASSERT(sizeof(CLOUD_CA_CERTIFICATE) < KB(4), "Certificate too large");

typedef struct Sync_Resp{
    char *cpId;
    const char *dtg;      //root..info
    int ee;
    int rc;
    int at;
    int ds;
    int df;
    struct protocol{
          char *name;
          char *host;
          char *Client_Id;    //data..protocol
          char *user_name;
          char *pass;
          char *pub_Topic;
          char *sub_Topic;
        } Broker;
};


char recv_buf[MAXLINE];
char send_buf[2048 + 1];
char *CPID =NULL, *Burl =NULL;
char *ENVT =NULL, *uniqueID =NULL;
char *Sync_call_resp;
char *Base_url;
//char *Dpayload = " ", *Tpayload =NULL;
static bool pubAck;
bool Flag_99 = true;
char LastTime[25] = "1970-01-01T00:00:00.000Z";
//char* const Discovery = "discovery.iotconnect.io";
char* const httpAPIVersion = "2016-02-03";

char* const  twinPropertyPubTopic ="$iothub/twin/PATCH/properties/reported/?$rid=1";
char* const  twinPropertySubTopic ="$iothub/twin/PATCH/properties/desired/#";
char* const  twinResponsePubTopic ="$iothub/twin/GET/?$rid=0";
char* const  twinResponseSubTopic ="$iothub/twin/res/#";



#if defined(CONFIG_PROVISION_CERTIFICATES)
#define MAX_OF_2 MAX(sizeof(CLOUD_CA_CERTIFICATE),\
		     sizeof(CLOUD_CLIENT_PRIVATE_KEY))
#define MAX_LEN MAX(MAX_OF_2, sizeof(CLOUD_CLIENT_PUBLIC_CERTIFICATE))
static uint8_t certificates[][MAX_LEN] = {{CLOUD_CA_CERTIFICATE},
				       {CLOUD_CLIENT_PRIVATE_KEY},
				       {CLOUD_CLIENT_PUBLIC_CERTIFICATE} };
static const size_t cert_len[] = {
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
int64_t current_time_ms;

char *Get_Time(void)
{
	struct timespec tp = { 0 };
	struct tm ltm = { 0 };
	int err;

    err = date_time_now(&current_time_ms);

    tp.tv_sec = current_time_ms / 1000;
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
	param.message_id = ++mid_num; //sys_rand32_get();
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
			.utf8 = SYNC_resp.Broker.sub_Topic,
			.size = strlen(SYNC_resp.Broker.sub_Topic)
		    },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        },
        {.topic = {
			.utf8 = twinPropertySubTopic,
			.size = strlen(twinPropertySubTopic)
		            },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        },
        {.topic = {
			.utf8 = twinResponseSubTopic,
			.size = strlen(twinResponseSubTopic)
		    },
		    .qos = MQTT_QOS_1_AT_LEAST_ONCE
        }
	};

	const struct mqtt_subscription_list subscription_list = {
		.list = &subscribe_topic,
		.list_count = ARRAY_SIZE(subscribe_topic),
		.message_id = 1234
	};


	return mqtt_subscribe(&client, &subscription_list);
}


/**********************************************
    Function to read the published payload
***********************************************/
int publish_get_payload(struct mqtt_client *c, size_t length)
{
	uint8_t *buf = payload_buf;
	uint8_t *end = buf + length;

	if (length > sizeof(payload_buf)) 
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

			printk("mqtt_read_publish_payload: EAGAIN\n");

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
                printk("MQTT connect failed %d\n", evt->result);
                break;
            }

            connected = true;
            printk("[%s:%d] MQTT client connected!\n", __func__, __LINE__);
            subscribe();
            break;

        case MQTT_EVT_DISCONNECT:
            printk("[%s:%d] MQTT client disconnected %d\n", __func__,
                __LINE__, evt->result);

            err = mqtt_disconnect(c);
            if (err) {
                printk("Could not disconnect: %d\n", err);
            }

            connected = false;
            break;

        case MQTT_EVT_PUBLISH: {
            const struct mqtt_publish_param *p = &evt->param.publish;
                    
            printk("[%s:%d] MQTT PUBLISH result=%d len=%d\n", __func__,
                __LINE__, evt->result, p->message.payload.len);
            err = publish_get_payload(c, p->message.payload.len);
            if (err >= 0)
            {
                data_print("Received: ", payload_buf, p->message.topic.topic.utf8,
                    p->message.payload.len);

            } 
            else 
            {
                printk("mqtt_read_publish_payload: Failed! %d\n", err);
                printk("Disconnecting MQTT client...\n");

                err = mqtt_disconnect(c);
                if (err) 
                {
                    printk("Could not disconnect: %d\n", err);
                }
            }
        } break;

        case MQTT_EVT_PUBACK:
            if (evt->result != 0) 
            {
                printk("MQTT PUBACK error %d\n", evt->result);
                break;
            }
            printk("[%s:%d] PUBACK packet id: %u\n", __func__, __LINE__, evt->param.puback.message_id);
            break;

        case MQTT_EVT_SUBACK:
            if (evt->result != 0) 
            {
                printk("MQTT SUBACK error %d\n", evt->result);
                break;
            }
            printk("[%s:%d] SUBACK packet id: %u\n", __func__, __LINE__, evt->param.suback.message_id);
            break;

        default:
            printk("[%s:%d] default: %d\n", __func__, __LINE__,	evt->type);
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
	err = getaddrinfo(SYNC_resp.Broker.host, NULL, &hints, &result);
	
	if (err) {
		printk("ERROR: getaddrinfo failed %d\n", err);

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
			printk("\nIPv4 Address found %s\n", ipv4_addr);

			break;
		} else {
			printk("ai_addrlen = %u should be %u or %u\n",
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

    if((SYNC_resp.at == 3) || (SYNC_resp.at == 2))
    {    
        client->client_id.utf8 = SYNC_resp.Broker.Client_Id;
        client->client_id.size = strlen(client->client_id.utf8);
       
        mqtt_user_name.utf8 = SYNC_resp.Broker.user_name;
        mqtt_user_name.size = strlen(mqtt_user_name.utf8);
          
        client->user_name = &mqtt_user_name;
        client->password = NULL;
    }
    else if(SYNC_resp.at == 1)
    {
        client->client_id.utf8 =  SYNC_resp.Broker.Client_Id;
        client->client_id.size =  strlen(client->client_id.utf8);

        mqtt_user_name.utf8 = SYNC_resp.Broker.user_name;
        mqtt_user_name.size = strlen(mqtt_user_name.utf8);


        mqtt_password.utf8 = SYNC_resp.Broker.pass;
        mqtt_password.size = strlen(SYNC_resp.Broker.pass);
          
        client->user_name = &mqtt_user_name;
        client->password = &mqtt_password;
    }
	client->protocol_version = MQTT_VERSION_3_1_1;

	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);
	
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
        tls_config->hostname = SYNC_resp.Broker.host;
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
        printk("ERROR: poll %d\n", errno);
        return -1;
	}

    err = mqtt_live(&client);
    if ((err != 0) && (err != -EAGAIN)) 
    {
        printk("ERROR: mqtt_live %d\n", err);
        return -1;
	}

    if ((fds.revents & POLLIN) == POLLIN) 
    {
        err = mqtt_input(&client);
	    if (err != 0) 
        {
            printk("ERROR: mqtt_input %d\n", err);
            return -1;
		}
	}

    if ((fds.revents & POLLERR) == POLLERR)
    {
        printk("Socket Error : POLLERR\n");
        return -1;
	}

    if ((fds.revents & POLLHUP ) == POLLHUP ) 
    {
        printk("Socket Error : POLLHUP \n");
        return -1;
	}

    if ((fds.revents & POLLNVAL) == POLLNVAL) 
    {
        printk("Socket Error : POLLNVAL\n");
        return -1;
	}

    return 0;
}


/**********************************************
            Start the MQTT protocol
***********************************************/
int MQTT_Init()
{

	int err;
        
    client.broker = SYNC_resp.Broker.host;
    client.client_id.utf8 = SYNC_resp.Broker.Client_Id; 
    client.user_name = SYNC_resp.Broker.user_name;

    if(&client == NULL)
    {
        printk("MQTT Client NULL\n");
        return -1;
    }
            
    client_init(&client);

	err = mqtt_connect(&client);
	if (err != 0)
    {
		printk("ERROR: mqtt_connect %d\n", err);
		return -1;
	}


	err = fds_init(&client);
	if (err != 0)
    {
		printk("ERROR: fds_init %d\n", err);
		return -1;
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
    char *sync_resp;

    printk("Start IoTConnect_Init\n");
    
    if(Flag_99)
    {
        k_msleep(200);
        Base_url = get_base_url(HTTPS_HOSTNAME,cpID,Env);
        if (Base_url == NULL)
        {
            printk("Base_url is NULL");
            return -1;
        }
            
        k_msleep(200);
        sync_resp = Sync_call(cpID, UniqueID, Base_url);
        if (sync_resp == NULL)
        {
            printk("[error] sync_resp");
            return -1;
        }
        
        ENVT = Env;
        CPID = cpID;
        Burl = Base_url;
        uniqueID = UniqueID;
        
        res = Save_Sync_Responce(sync_resp);

        if ( !SYNC_resp.ds)
        {
            return 0;
        }      
        else
        {
            return -1;
        }                     

    }
}


/**********************************************
    Start MQTT init and connect with client
***********************************************/
int IoTConnect_Connect()
{
    if(MQTT_Init() == 0)
    {
        printk("MQTT_Init SUCCESS");
    }
    else
    {
        printk("MQTT_Init FAIL");
        return -1;
    }
    k_msleep(100);

    return MQTT_Status();
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
		printk("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) 
    {
		printk("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	return 0;
}


/**************************************************************
    you need to pass cpid , env and the HOST at GET_TEMPLATE
***************************************************************/
#define GET_TEMPLATE                                                              \
	"GET /api/sdk/cpid/%s/lang/M_C/ver/2.0/env/%s HTTP/1.1\r\n"               \
	"Host: %s\r\n"                                                            \
	"Content-Type: application/json; charset=utf-8\r\n"                       \
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
    char *Base_URL = NULL;
    char peer_addr[INET6_ADDRSTRLEN];

    printk("Get URL address ...\n");

    err = getaddrinfo(HTTPS_HOSTNAME, HTTPS_PORT, &IoT_hints, &IoT_res);
	if (err) 
    {
		printk("getaddrinfo() failed, err %d\n", errno);
		return NULL;
	} 
   
    inet_ntop(IoT_res->ai_family, &((struct sockaddr_in *)(IoT_res->ai_addr))->sin_addr, peer_addr,
			INET6_ADDRSTRLEN);
	printk("Resolved %s (%s)\n", peer_addr, net_family2str(IoT_res->ai_family));


    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (fd == -1) 
    {
        printk("Failed to open socket!\n");
        goto clean_up;
    }
    err = tls_setup(fd);
    if (err) 
    {
        goto clean_up;
    }

    printk("Connecting to %s:%d\n", HTTPS_HOSTNAME,	ntohs(((struct sockaddr_in *)(IoT_res->ai_addr))->sin_port));
    err = connect(fd, IoT_res->ai_addr, IoT_res->ai_addrlen);
    if (err) 
    {
        printk("connect() failed, err: %d\n", errno);
        goto clean_up;
    }
    printk("  .. OK\n");
    int HTTP_HEAD_LEN = snprintk(send_buf,
	    500, /*total length should not exceed MTU size*/
	    GET_TEMPLATE, cpid, env,
	    HTTPS_HOSTNAME
            );
    off = 0;  
    do {
            bytes = send(fd, &send_buf[off], HTTP_HEAD_LEN - off, 0);
            if (bytes < 0) 
            {
                printk("send() failed, err %d\n", errno);
                goto clean_up;
            }
            off += bytes;
	} while (off < HTTP_HEAD_LEN);

    off = 0;
    do {
            bytes = recv(fd, &recv_buf[off], MAXLINE - off, 0);
            if (bytes < 0) 
            {
                printk("recv() failed, err %d\n", errno);
                goto clean_up;
            }
            off += bytes;
	} while (bytes != 0 );

    p = strstr(recv_buf, "\r\n{");
    cJSON *root = cJSON_Parse(p);
    if(root == NULL)
    {
        printk("This is NOT json format  -> (%s) error(%d) ", __func__, __LINE__);
        return NULL;
	} 
    else 
    {
		printk("This is json format");
	}
    
    Base_URL = (cJSON_GetObjectItem(root, "baseUrl"))->valuestring;
    close(fd);

    if (Base_URL != NULL)
    {
        strcat(Base_URL,"sync");
        return Base_URL;
    }
    else
    {
        return NULL;
    }
    
    clean_up:
        freeaddrinfo(IoT_res);
        cJSON_Delete(root);
        return Base_URL;
}


/********************************************************************
    you need to pass remain_url ,host, post_data_lan and post_data
*********************************************************************/
#define POST_TEMPLATE                                                         \
	"POST /api/2.0/agent/sync? HTTP/1.1\r\n"                              \
	"Host: %s\r\n"                                                        \
	"Content-Type: application/json; charset=utf-8\r\n"                   \
        "Connection: keep-alive\r\n"                                          \
        "Content-length: %d\r\n\r\n"                                          \
	"%s"


/***************************************************************
    This templates can be used for raw HTTP headers 
    in case that the platform doesn't GET/POST functionality
    you need to pass URL returned from discovery host,
    host form discovery host, post_data_lan and post_data
****************************************************************/
#define IOTCONNECT_SYNC_HEADER_TEMPLATE \
    "POST /api/2.0/agent/sync? HTTP/1.1\r\n" \
    "Host: %s\r\n" \
    "Content-Type: application/json; charset=utf-8\r\n" \
    "Connection: close\r\n" \
    "Content-length: %d\r\n" \
    "\r\n" \
    "%s"

// You will typically use this JSON post data to get mqtt client information
#define IOTCONNECT_DISCOVERY_PROTOCOL_POST_DATA_TEMPLATE "{\"cpId\":\"%s\",\"uniqueId\":\"%s\",\"option\":{\"attribute\":false,\"setting\":false,\"protocol\":true,\"device\":false,\"sdkConfig\":false,\"rule\":false}}"

// add 1 for string terminator
#define IOTCONNECT_DISCOVERY_PROTOCOL_POST_DATA_MAX_LEN (\
    sizeof(IOTCONNECT_DISCOVERY_PROTOCOL_POST_DATA_TEMPLATE) + \
    CONFIG_IOTCONNECT_DUID_MAX_LEN + CONFIG_IOTCONNECT_CPID_MAX_LEN \
    )

char* Sync_call(char *cpid, char *uniqueid, char *base_url)
{
    int err;
    int fdP;
    int bytes;
    size_t off;
    struct addrinfo *res;
    struct addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
    };  
    
    char *AgentHost ;
    for(int a=0;a<3;a++)
        AgentHost = strsep(&base_url,"//");

    err = getaddrinfo(AgentHost, NULL, &hints, &res);
    k_msleep(1000);
    ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(IOTCONNECT_SERVER_HTTP_PORT);
    fdP =socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (fdP == -1) {
            printk("Failed to open SYNC socket!\n");
            goto clean_up;
    }

    err = tls_setup(fdP);
    if (err) {
            goto clean_up;
    }
   printk("\n\nConnecting to %s", AgentHost);
    err = connect(fdP, res->ai_addr, res->ai_addrlen);
    if (err) {
            printk("connect() failed, err: %d\n", errno);
            goto clean_up;
    }
    printk("  .. OK\n");

    char post_data[800];
    int http_post = snprintk(post_data,
                                500, /*total length should not exceed MTU size*/
                                IOTCONNECT_DISCOVERY_PROTOCOL_POST_DATA_TEMPLATE,
                                cpid,
                                uniqueid
    );

    if (!http_post){
        printk("error in post value \n");
    }

    int HTTP_POST_LEN = snprintk(send_buf,
	                            1024, /*total length should not exceed MTU size*/
	                            IOTCONNECT_SYNC_HEADER_TEMPLATE, AgentHost,
	                            strlen(post_data), post_data
           );
    off = 0;  // 
    do {
            bytes = send(fdP, &send_buf[off], HTTP_POST_LEN - off, 0);
             if (bytes < 0) {
                    printk("send() failed, err %d\n", errno);
                    goto clean_up;
            }
            off += bytes;
	} while (off < HTTP_POST_LEN);

      off = 0;
    do {
            bytes = recv(fdP, &recv_buf[off], MAXLINE - off, 0);
            if (bytes < 0) {
                    printk("recv() failed, err %d\n", errno);
                    goto clean_up;
            }
            off += bytes;
            if (off >= 1025)
             break;
	} while (bytes != 0); /* peer closed connection */ 

    Sync_call_resp = strstr(recv_buf, "\r\n{");

    clean_up:
        freeaddrinfo(res);
        close(fdP);
        return Sync_call_resp;
}


/*************************************************
    Save syncResp in cache memory of device 
*************************************************/
int Save_Sync_Responce(char *sync_data)
{
    cJSON *root = NULL;
    cJSON *Sync_Res_Json = NULL;
    cJSON *P = NULL,*sc = NULL;
    root = cJSON_Parse(sync_data);

    Sync_Res_Json = cJSON_GetObjectItemCaseSensitive(root, "d");
    SYNC_resp.ds = (cJSON_GetObjectItem(Sync_Res_Json, "ds"))->valueint;
    printk("\n\tDevice : %s Status :",uniqueID);  
    if(SYNC_resp.ds == 0)
    {
        printk("  .. OK");
        SYNC_resp.cpId = (cJSON_GetObjectItem(Sync_Res_Json, "cpId"))->valuestring;
        SYNC_resp.dtg = (cJSON_GetObjectItem(Sync_Res_Json, "dtg"))->valuestring;
        SYNC_resp.ee = (cJSON_GetObjectItem(Sync_Res_Json, "ee"))->valueint;
        SYNC_resp.rc = (cJSON_GetObjectItem(Sync_Res_Json, "rc"))->valueint;
        SYNC_resp.at = (cJSON_GetObjectItem(Sync_Res_Json, "at"))->valueint;
        sc = cJSON_GetObjectItemCaseSensitive(Sync_Res_Json, "sc");
        SYNC_resp.df = (cJSON_GetObjectItem(sc, "df"))->valueint;
        P = cJSON_GetObjectItemCaseSensitive(Sync_Res_Json, "p");
        SYNC_resp.Broker.name = (cJSON_GetObjectItem(P, "n"))->valuestring;
        SYNC_resp.Broker.Client_Id = (cJSON_GetObjectItem(P, "id"))->valuestring;
        SYNC_resp.Broker.host = (cJSON_GetObjectItem(P, "h"))->valuestring;
        SYNC_resp.Broker.user_name = (cJSON_GetObjectItem(P, "un"))->valuestring;
        SYNC_resp.Broker.pass = (cJSON_GetObjectItem(P, "pwd"))->valuestring;
        SYNC_resp.Broker.sub_Topic = (cJSON_GetObjectItem(P, "sub"))->valuestring;
        SYNC_resp.Broker.pub_Topic = (cJSON_GetObjectItem(P, "pub"))->valuestring;
        printk("\n\tSync_Response_Data Saved");
    }
    else if(SYNC_resp.ds == 1)
    {
        printk("  Device_Not_Register \n");
    }
    else if(SYNC_resp.ds == 2)
    {
        printk("  Auto_Register \n");
    }
    else if(SYNC_resp.ds == 3)
    {
        printk("  Device_Not_Found \n");
    }
    else if(SYNC_resp.ds == 4)
    {
        printk("  Device_Inactive \n");
    }
    else if(SYNC_resp.ds == 5)
    {
        printk("  Object_Moved \n");
    }
    else if(SYNC_resp.ds == 6)
    {
        printk("  Cpid_Not_Found \n");
    }
    else
    {
        printk("  No Device_status has been matched..! 000\n");
    }
    if (SYNC_resp.Broker.host[0] != NULL)
        return 1;
    else
        return 0;

}


/*************************************************
        Received data in callback from C2D 
*************************************************/
void data_print(uint8_t *prefix, uint8_t *data, char *topic, size_t len)
{
    char buf[len + 1];
    cJSON *root,*root2,*data_R;
    char *SMS, *cmd;
    memcpy(buf, data, len);
    buf[len] = 0;
    if (strlen(buf) > 5)
    {
        if(! strncmp(topic,"$iothub/twin/res/",17))
        {        
            root = cJSON_Parse(buf);
            cJSON_AddStringToObject(root,"uniqueId",uniqueID);
            SMS = cJSON_PrintUnformatted(root);         
            (*Twin_CallBack)(topic, SMS);
            k_msleep(10);
            
            cJSON_Delete(root);
            free(SMS);
        }
        else if(! strncmp(topic,"$iothub/twin/PATCH/properties/",30))
        {        
            root = cJSON_CreateObject();
            root2 = cJSON_Parse(buf);
            cJSON_AddItemToObject(root,"desired",root2);
            cJSON_AddStringToObject(root,"uniqueId",uniqueID);
            SMS = cJSON_PrintUnformatted(root);   
            (*Twin_CallBack)(topic, SMS);
            k_msleep(10);
            
            cJSON_Delete(root);
            free(SMS);
        }
        else 
        {
            root = cJSON_Parse(buf);
            cmd = (cJSON_GetObjectItem(root, "cmdType"))->valuestring;
            if( (!strcmp(cmd,"0x01")) || ( !strcmp(cmd,"0x02")) )
            {
                data_R = cJSON_GetObjectItemCaseSensitive(root, "data");
                SMS = cJSON_PrintUnformatted(data_R);
                (*Device_CallBack)(topic, SMS);
                k_msleep(10);
                
                cJSON_Delete(root);
                free(SMS);
            }
            else 
            {
                Received_cmd(buf);         
            }
            k_msleep(10);
       }
    }
    else ;
}


/*************************************************
        Get All twin property from C2D
*************************************************/
int getAllTwins(void)
{
    if ( ! data_publish(&client,twinResponsePubTopic, 1, " ", strlen(" ")))
    {
        printk("\n\t getAllTwins Publish ");
    }
    else
    {
        printk("\n\t getAllTwins Publish Failed");
        return -1;
    }
    return 0;
}


/*************************************************
        Disconnect SDk from IoTConnect
*************************************************/
int IoTConnect_Abort(void)
{
   printk("\n\t:: SDK is Disconnected From IoTConnect ::");
   int sd = mqtt_disconnect(&client);  Flag_99 = false;  k_msleep(100);
   printk("\n\n\tdisconnection %d",sd);
   return 0 ;
   
}


/*************************************************
        Get Sensor data and send to cloud
*************************************************/
int errPub;
int SendData(char *Attribute_json_Data)
{
    int err;
    if(Flag_99 && connected)
    { 
        char *NowTime = Get_Time();
        long int Timediff = GetTimeDiff(NowTime, LastTime);
        if (SYNC_resp.df < Timediff) 
        {
            if(!SYNC_resp.ds)
            {
                cJSON *To_HUB_json, *sdk, *device, *device2, *data1, *Device_data1;
                char *To_HUB_json_data = " ";
                cJSON *root = cJSON_Parse(Attribute_json_Data);
                To_HUB_json = cJSON_CreateObject();
                if (To_HUB_json == NULL)
                {
                  printk("Unable to allocate To_HUB_json Object\n");
                  return -1;    
                }
                cJSON_AddStringToObject(To_HUB_json, "cpId", SYNC_resp.cpId);
                cJSON_AddStringToObject(To_HUB_json, "dtg", SYNC_resp.dtg);
                cJSON *parameter = cJSON_GetArrayItem(root, 0);

                cJSON_AddStringToObject(To_HUB_json, "t", cJSON_GetObjectItem(parameter, "time")->valuestring);
                cJSON_AddNumberToObject(To_HUB_json, "mt", 0);
                cJSON_AddItemToObject(To_HUB_json, "sdk", sdk = cJSON_CreateObject());
                cJSON_AddStringToObject(sdk,"l","M_C");
                cJSON_AddStringToObject(sdk,"v","2.0");
                cJSON_AddStringToObject(sdk,"e",ENVT);
                cJSON_AddItemToObject(To_HUB_json, "d", device = cJSON_CreateArray());

                int parameters_count = cJSON_GetArraySize(root);    

                for (int i = 0; i < parameters_count; i++) 
                {
                    cJSON *parameter = cJSON_GetArrayItem(root, i);
                    cJSON_AddItemToArray(device, Device_data1 = cJSON_CreateObject());
                    cJSON_AddStringToObject(Device_data1, "id", cJSON_GetObjectItem(parameter, "uniqueId")->valuestring);
                    cJSON_AddStringToObject(Device_data1, "dt", cJSON_GetObjectItem(parameter, "time")->valuestring);
                    cJSON_AddStringToObject(Device_data1, "tg", "");
                    cJSON_AddItemToObject(Device_data1, "d", device2 = cJSON_CreateArray());
                    data1 = cJSON_GetObjectItem(parameter, "data");
                    cJSON_AddItemToArray(device2,data1);
                }
                To_HUB_json_data =  cJSON_PrintUnformatted(To_HUB_json);
                cJSON_Delete(To_HUB_json);
                printk("\r\n\tPublishing data...\n");
                errPub = data_publish(&client, SYNC_resp.Broker.pub_Topic, 1, To_HUB_json_data, strlen(To_HUB_json_data));

                for(int ss=0;ss<25;ss++)
                    LastTime[ss] = NowTime[ss];
                k_msleep(10);
  
                if ( errPub == 0)
                {
                    printk("\r\n\tINFO_SD01 [%s %s] : publish data id %d\n",CPID, uniqueID, mid_num);
                    pubAck = false;
                    return 0;
                } 
                else
                {
                    printk("\r\n\tERR_SD01 [%s %s] : Publish data failed err %d: MQTT connection not found\n", CPID, uniqueID, errPub);
                    return -1;
                }

                return -1;

            }
        }
        return -1;
    }
    
    else
    {
        printk("\r\n\tINFO_DC01 [%s-%s] : Device already disconnected",CPID,uniqueID);
        return -1;
    }
    return 0;
}
  

/**********************************************************
        calculate the difference between two datetime
***********************************************************/
int GetTimeDiff(char newT[25], char oldT[25])
{
    // Create a newTm, oldTm struct to hold the parsed new and old date and time
    struct tm newTm, oldTm;
 
    // Parse the new date&time input string
    if (strptime(newT, "%Y-%m-%dT%H:%M:%S.000Z", &newTm) == NULL) {
        printk(stderr, "[GetTimeDiff] : Failed to parse date string\n");
        return 1;
    }
 
    // Convert newTm struct to epoch time
    time_t new_epoch_time = mktime(&newTm);
 
    if (new_epoch_time == -1) {
        printk(stderr, "[GetTimeDiff] : Failed to convert newTm struct to epoch time\n");
        return 1;
    }

    // Parse the old date&time input string
    if (strptime(oldT, "%Y-%m-%dT%H:%M:%S.000Z", &oldTm) == NULL) {
        printk(stderr, "[GetTimeDiff] : Failed to parse date string\n");
        return 1;
    }
 
    // Convert oldTm struct to epoch time
    time_t old_epoch_time = mktime(&oldTm);
 
    if (old_epoch_time == -1) {
        printk(stderr, "[GetTimeDiff] : Failed to convert oldTm struct to epoch time\n");
        return 1;
    }
 
    int time_diff = (new_epoch_time - old_epoch_time);
    printk("Time Diff : %d\r\n",time_diff);
    return time_diff;
}


/*************************************************
    This will UpdateTwin property to IoTConnect
*************************************************/
int UpdateTwin(char *key,char *value)
{
    char *Twin_Json_Data;
    cJSON *root = cJSON_CreateObject();

    if(root == NULL)
    {
        return 1;
    }

    cJSON_AddStringToObject(root, key, value);
    Twin_Json_Data = cJSON_PrintUnformatted(root);
 
    if ( ! data_publish(&client, twinPropertyPubTopic, 0, Twin_Json_Data, strlen(Twin_Json_Data)))
    {
        printk("\n\t Twin_Update_Data Publish ");
    }

    cJSON_Delete(root);
    free(Twin_Json_Data);

    return 0;
}


/*************************************************
    This will UpdateTwin property to IoTConnect
*************************************************/
int UpdateTwin_Int(char *key, int value){
    char *Twin_Json_Data;
    cJSON *root;
    root  = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, key, value);
    Twin_Json_Data = cJSON_PrintUnformatted(root);
 
    if ( ! data_publish(&client, twinPropertyPubTopic, 0, Twin_Json_Data, strlen(Twin_Json_Data))){
        printf("\n\t Twin_Update_Data Publish ");
        }

    cJSON_Delete(root);
    free(Twin_Json_Data);
}


/*************************************
    Received command to control SDK
*************************************/
void Received_cmd(char *in_cmd)
{

    char *cmdValue, payLoad;
    cJSON * root = cJSON_Parse(in_cmd);

    cmdValue = (cJSON_GetObjectItem(root, "cmdType"))->valuestring;
    if( !strcmp(cmdValue,"0x10"))
    {
        printk("Get Response code for Attribute Changed");
        return ;
    }

    else if( !strcmp(cmdValue,"0x11"))
    {
        printk("Get Response code for Setting Changed");
        return ;
    }

    else if( !strcmp(cmdValue,"0x12"))
    {
        printk("Get Response code for MQTT Password Changed");
        mqtt_disconnect(&client);  k_msleep(100);
        payLoad = Sync_call(CPID,uniqueID,Burl);
        Save_Sync_Responce(payLoad);MQTT_Init();
        
    }
    else if( !strcmp(cmdValue,"0x13"))
    {
        printk("Get Response code for Device Changed");
        return ;
    }
    else if( !strcmp(cmdValue,"0x15"))
    {
        printk("Get Response code for Rule Changed");
        return ;
    }
    else if( !strcmp(cmdValue,"0x99"))
    {
        printk("\n\t:: SDK is Disconnected From IoTConnect ::");
        printk("\n\t:: SDK is Disconnected From IoTConnect ::");
        mqtt_disconnect(&client);  Flag_99 = false;
        return ;
    }
}


/**************************************************
    this will send the ACK of receiving Commands
**************************************************/
int SendAck(char *Ack_Data, int messageType)
{
    cJSON *Ack_Json2,*sdk_info,*device_input;
    char *Ack_Json_Data;
    Ack_Json2 = cJSON_CreateObject();
    if (Ack_Json2 == NULL)
    {
        printk("\nUnable to allocate Ack_Json2 Object in SendAck");
        return -1;    
    }

    cJSON_AddStringToObject(Ack_Json2, "uniqueId",uniqueID);
    cJSON_AddStringToObject(Ack_Json2, "cpId",CPID);
    cJSON_AddStringToObject(Ack_Json2, "t",Get_Time());
    cJSON_AddNumberToObject(Ack_Json2, "mt",messageType);
    cJSON_AddItemToObject(Ack_Json2, "sdk", sdk_info = cJSON_CreateObject());
    cJSON_AddStringToObject(sdk_info, "l","M_C");
    cJSON_AddStringToObject(sdk_info, "v","2.0");
    cJSON_AddStringToObject(sdk_info, "e",ENVT);
    cJSON *root = cJSON_Parse(Ack_Data);
    cJSON_AddItemToObject(Ack_Json2, "d", root);
    Ack_Json_Data = cJSON_PrintUnformatted(Ack_Json2);

    cJSON_Delete(root);

    if ( ! data_publish(&client, SYNC_resp.Broker.pub_Topic, 1, Ack_Json_Data, strlen(Ack_Json_Data)))
    {
        printk("\n\t Ack_Json_Data Publish\n");
    }
    else
    {
        printk("\n\t Ack_Json_Data not Publish\n");
        return -1;
    }

    return 0;
}