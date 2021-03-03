#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/encoding.h>
#include <aws/common/logging.h>

#include <json-c/json.h>

#include <linux/vm_sockets.h>
#include <sys/socket.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include <errno.h>
#include <unistd.h>
#include <dirent.h> 
#define SERVICE_PORT 3000
#define PROXY_PORT 8000
#define BUF_SIZE 2000000
AWS_STATIC_STRING_FROM_LITERAL(default_region, "us-west-2");

//unsigned char * HARD_DATAKEY = (unsigned char *) "Deeplearningisnotoriouslyreferredtoasablackboxtechnique,andwithreasonablecause.WhiletraditionalstatisticallearningmethodslikeregressionandBayesianmodelinghelpresearchersdrawdirectconnectionsbetweenfeaturesandpredictions,deepneuralnetworksrequirecomplexcomp";
//unsigned char * HARD_IV = (unsigned char *) "ositionsofmanytomanyfunctions.Layeredarchitecturesenableuniversalapproximationbutmakeitdifficulttorecognizeandreacttocostlymista";


enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond, label, msg)                                                                                      \
    if (cond) {                                                                                                        \
        err_msg = NULL;                                                                                                \
        if (msg != NULL) {                                                                                             \
            fprintf(stderr, "%s\n", msg);                                                                              \
            err_msg = msg;                                                                                             \
        }                                                                                                              \
        goto label;                                                                                                    \
    }

#define break_on(cond)                                                                                                 \
    if (cond) {                                                                                                        \
        break;                                                                                                         \
    }

struct app_ctx {
    /* Allocator to use for memory allocations. */
    struct aws_allocator *allocator;
    /* KMS region to use. */
    const struct aws_string *region;
    /* vsock port on which to open service. */
    uint32_t port;
    /* vsock port on which vsock-proxy is available in parent. */
    uint32_t proxy_port;
};

static void s_usage(int exit_code) {
    fprintf(stderr, "usage: enclave_server [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS\n");
    fprintf(stderr, "    --port PORT: Await new connections on PORT. Default: 3000\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 2000\n");
    fprintf(stderr, "    --help: Display this message and exit");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'p'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {NULL, 0, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->port = SERVICE_PORT;
    ctx->proxy_port = PROXY_PORT;
    ctx->region = NULL;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "r:p:x:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'r': {
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            }
            case 'p':
                ctx->port = atoi(aws_cli_optarg);
                break;
            case 'x':
                ctx->proxy_port = atoi(aws_cli_optarg);
                break;
            case 'h':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
                break;
        }
    }
}

struct aws_credentials *s_read_credentials(struct aws_allocator *allocator, struct json_object *object) {
    struct aws_credentials *credentials = NULL;

    struct json_object *aws_access_key_id = json_object_object_get(object, "AwsAccessKeyId");
    struct json_object *aws_secret_access_key = json_object_object_get(object, "AwsSecretAccessKey");
    struct json_object *aws_session_token = json_object_object_get(object, "AwsSessionToken");

    if (aws_access_key_id == NULL || aws_secret_access_key == NULL ||
        !json_object_is_type(aws_access_key_id, json_type_string) ||
        !json_object_is_type(aws_secret_access_key, json_type_string)) {
        fprintf(stderr, "Error parsing JSON object: credentials not correct");
        return NULL;
    }

    if (aws_session_token != NULL && !json_object_is_type(aws_access_key_id, json_type_string)) {
        fprintf(stderr, "Error parsing JSON object: credentials not correct");
        return NULL;
    }

    credentials = aws_credentials_new(
        allocator,
        aws_byte_cursor_from_c_str(json_object_get_string(aws_access_key_id)),
        aws_byte_cursor_from_c_str(json_object_get_string(aws_secret_access_key)),
        aws_byte_cursor_from_c_str(json_object_get_string(aws_session_token)),
        UINT64_MAX);

    return credentials;
}

/**
 * This function returns the AWS region the client will use, with the following
 * rules:
 * 1. If a region is already set at the start of this program it will return it, unless
 * the client also wants to set a region, in which case it will return NULL, since
 * the client and the enclave collide in requirements.
 * 2. If a region is not set at the start of this program, and the client sets one,
 * then the client one is returned, if it's correctly set by the client.
 * 3. If no region is set at either the start of this program, nor by the client,
 * then default_region is returned.
 */
struct aws_string *s_read_region(struct app_ctx *ctx, struct json_object *object) {
    struct json_object *aws_region = json_object_object_get(object, "AwsRegion");
    /* Neither is set, so use default_region */
    if (aws_region == NULL && ctx->region == NULL) {
       return aws_string_clone_or_reuse(ctx->allocator, default_region);
    }

    /* Both are set, don't allow it. */
    if (aws_region != NULL && ctx->region != NULL) {
        return NULL;
    }

    /* Enclave is set. */
    if (aws_region == NULL && ctx->region != NULL) {
        return aws_string_clone_or_reuse(ctx->allocator, ctx->region);
    }

    /* AwsRegion is set, verify it. */
    if (!json_object_is_type(aws_region, json_type_string))
        return NULL;

    return aws_string_new_from_c_str(ctx->allocator, json_object_get_string(aws_region));
}

ssize_t s_write_all(int peer_fd, const char *msg, size_t msg_len) {
    size_t total_sent = 0;
    while (total_sent < msg_len) {
        ssize_t sent = write(peer_fd, msg + total_sent, msg_len - total_sent);
        if (sent <= 0 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        } else if (sent < 0) {
            return -1;
        } else {
            total_sent += sent;
        }
    }
    return total_sent;
}

int s_send_status(int peer_fd, int status, const char *msg) {
    struct json_object *status_object = json_object_new_object();
    if (status_object == NULL) {
        return -1;
    }

    json_object_object_add(status_object, "Status", json_object_new_string(status == STATUS_OK ? "Ok" : "Error"));

    if (msg != NULL) {
        json_object_object_add(status_object, "Message", json_object_new_string(msg));
    }

    const char *status_str = json_object_to_json_string(status_object);
    return s_write_all(peer_fd, status_str, strlen(status_str) + 1);
}

int s_send_data_key(int peer_fd, int status, char * enc_data, char * enc_key) {
    struct json_object *status_object = json_object_new_object();
    if (status_object == NULL) {
        return -1;
    }

    json_object_object_add(status_object, "Status", json_object_new_string(status == STATUS_OK ? "Ok" : "Error"));


    if (enc_data != NULL) {
        json_object_object_add(status_object, "EncData", json_object_new_string(enc_data));
    }

    if (enc_key != NULL) {
        json_object_object_add(status_object, "KeyPackage", json_object_new_string(enc_key));
    }

    const char *status_str = json_object_to_json_string(status_object);
    return s_write_all(peer_fd, status_str, strlen(status_str) + 1);
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

struct aws_byte_buf b64_decode(const struct app_ctx *app_ctx, const char * encoded) {
    size_t ciphertext_len;
    struct aws_byte_buf ciphertext;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str(encoded);
    aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
    aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
    aws_base64_decode(&ciphertext_b64, &ciphertext);
    return ciphertext;
}

struct aws_byte_buf b64_encode(const struct app_ctx *app_ctx, const unsigned char * buf, const int len){
    size_t encoded_data_len;
    struct aws_byte_buf encoded_data; // base 64 encrypted data
    struct aws_byte_cursor decoded_cursor = aws_byte_cursor_from_array(buf, len);
    aws_base64_compute_encoded_len(len, &encoded_data_len);
    aws_byte_buf_init(&encoded_data, app_ctx->allocator, encoded_data_len);
    aws_base64_encode(&decoded_cursor, &encoded_data);
    return encoded_data;
}

    
static void handle_connection(struct app_ctx *app_ctx, int peer_fd) {
    char buf[BUF_SIZE] = {0};
    size_t buf_idx = 0;
    ssize_t rc = 0;
    struct json_object *object = NULL;
    char *err_msg = NULL;

    struct aws_credentials *credentials = NULL;
    struct aws_string *region = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = "3", .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator,
        .endpoint = &endpoint,
        .domain = AWS_SOCKET_VSOCK,
    };
    /*
    char cwd [PATH_MAX];
     if (getcwd(cwd, sizeof(cwd))!=NULL){
        const char * tmp = "test";
        fprintf(stderr, tmp);
        fprintf(stderr, cwd);
        //rc = s_send_status(peer_fd, STATUS_OK, cwd);
    }else{
        const char * tmp = "cwd failed";
        fprintf(stderr, tmp);
        //rc = s_send_status(peer_fd, STATUS_OK, tmp);
    }
    */
    while (true) {
        char *sep = memchr(buf, '\0', buf_idx);
        if (buf_idx == 0 || sep == NULL) {
            /* Buffer full, but no message available. */
            if (buf_idx >= sizeof(buf)) {
                rc = s_send_status(peer_fd, STATUS_ERR, "Message size too large.");
                fprintf(stderr, "Message size too large.\n");
                break;
            }

            // Read data from socket if no complete message is available
            ssize_t bytes = read(peer_fd, buf + buf_idx, sizeof(buf) - buf_idx);
            if (bytes == -1) {
                if (errno == EAGAIN || errno == EINTR) {
                    /* Retry operation. */
                    continue;
                }
                perror("Socket read error: ");
                break;
            } else if (bytes == 0) {
                /* Peer closed socket. */
                break;
            } else {
                /* Update counter and then check for object. */
                buf_idx += bytes;
                continue;
            }
        }

        /* Safe, because we know the buffer has a 0 before the end. */
        fprintf(stderr, "Object = %s\n", buf);
        object = json_tokener_parse(buf);

        /* Remove message from buffer */
        buf_idx -= (sep + 1 - buf);
        memmove(buf, sep + 1, buf_idx);

        fail_on(object == NULL, loop_next_err, "Error reading JSON object");
        fail_on(!json_object_is_type(object, json_type_object), loop_next_err, "JSON is wrong type");

        struct json_object *operation = json_object_object_get(object, "Operation");
        fail_on(operation == NULL, loop_next_err, "JSON structure incomplete");
        fail_on(!json_object_is_type(operation, json_type_string), loop_next_err, "Operation is wrong type");

        

        if (strcmp(json_object_get_string(operation), "SetClient") == 0) {
            /* SetClient operation sets the AWS credentials and optionally a region and
             * creates a matching KMS client. This needs to be called before Decrypt. */
            struct aws_credentials *new_credentials = s_read_credentials(app_ctx->allocator, object);
            fail_on(new_credentials == NULL, loop_next_err, "Could not read credentials");

            /* If credentials or client already exists, replace them. */
            if (credentials != NULL) {
                aws_nitro_enclaves_kms_client_destroy(client);
                aws_credentials_release(credentials);
            }

            if (aws_string_is_valid(region)) {
                aws_string_destroy(region);
                region = NULL;
            }
            region = s_read_region(app_ctx, object);
            fail_on(region == NULL, loop_next_err, "Could not set region correctly, check configuration.");

            credentials = new_credentials;
            configuration.credentials = new_credentials;
            configuration.region = region;
            client = aws_nitro_enclaves_kms_client_new(&configuration);

            fail_on(client == NULL, loop_next_err, "Could not create new client");

            rc = s_send_status(peer_fd, STATUS_OK, NULL);
            fail_on(rc <= 0, exit_clean_json, "Could not send status");




        } else if (strcmp(json_object_get_string(operation), "Decrypt") == 0) {
            /* Decrypt uses KMS to decrypt the data passed to it in the Ciphertext
             * field and sends it back to the called*
             * TODO: This should instead send a hash of the data instead.
             */

            fail_on(client == NULL, loop_next_err, "Client not initialized");

            /*
             1. Decrypt data key
                If no key, assert no data.  If neither, create new data.
             2. Decrypt data
             3. Decrypt command
             4. Run command
             5. Return val (either result or updated data)
             */

            struct json_object *ciphertext_obj = json_object_object_get(object, "Ciphertext");
            struct json_object *datakey_obj = json_object_object_get(object, "data_key");
            
            fail_on(datakey_obj == NULL && ciphertext_obj != NULL, loop_next_err, "Ciphertext needs data key");

            struct json_object *data_json = NULL;

            if (ciphertext_obj == NULL){
                /**
                * If no dataset, initialized empty JSON
                */
                data_json = json_tokener_parse("{}");
            }else{

                /**
                * Start by KMS Decrypting the AES-GCM data key package
                */

                fprintf(stderr, json_object_get_string(datakey_obj));
                
                struct aws_byte_buf cipherkey = b64_decode(app_ctx, json_object_get_string(datakey_obj));

                struct aws_byte_buf datakey_package_decrypted;
                rc = aws_kms_decrypt_blocking(client, &cipherkey, &datakey_package_decrypted);

                // key package holds info for encryption - 256B key, 128B iv, 16B tag, length of ciphertext as 32 bit int
                unsigned char * datakey_package = datakey_package_decrypted.buffer;
                unsigned char datakey [256];
                unsigned char iv [128];
                unsigned char tag [16];
                int cipherlen = 0;

                cipherlen += datakey_package[256 + 128 + 16] << 24;
                cipherlen += datakey_package[256 + 128 + 16 + 1] << 16;
                cipherlen += datakey_package[256 + 128 + 16 + 2] << 8;
                cipherlen += datakey_package[256 + 128 + 16 + 3];

                memcpy(datakey, (char *) datakey_package_decrypted.buffer, 256);
                memcpy(iv, ((char*) datakey_package_decrypted.buffer) + 256, 128);
                memcpy(tag, ((char*) datakey_package_decrypted.buffer) + 256 + 128, 16);

                fprintf(stderr, "KMS Decrypted data key: %s\n", (char *) datakey);
                fprintf(stderr, "KMS Decrypted data iv: %s\n", (char *) iv);
                fprintf(stderr, "KMS Decrypted data length: %d\n", cipherlen);

                /**
                * Use data key to decrypt test result data
                */
                
                const char * b64_cipher_const = json_object_get_string(ciphertext_obj);
                char b64_ciphertext [strlen(b64_cipher_const)];
                memset(b64_ciphertext, 0, sizeof(b64_ciphertext));
                strcpy(b64_ciphertext, b64_cipher_const);

                fprintf(stderr, "\nb64 cipher: %s\n", b64_ciphertext);

                struct aws_byte_buf ciphertext_buf = b64_decode(app_ctx, b64_ciphertext);

                unsigned char * ciphertext = ciphertext_buf.buffer;

                EVP_CIPHER_CTX *ctx;
                int outlen, rv;
                unsigned char plaintext[BUF_SIZE];
                fprintf(stderr, "AES GCM Decrypt:\n");
                fprintf(stderr, "Ciphertext:\n");
                fprintf(stderr, "%s\n", ciphertext);
                ctx = EVP_CIPHER_CTX_new();
                /* Select cipher */
                EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
                /* Set IV length, omit for 96 bits */
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(iv), NULL);
                /* Specify key and IV */
                EVP_DecryptInit_ex(ctx, NULL, NULL, datakey, iv);
                /* Decrypt plaintext */
                fprintf(stderr, "%d\n", cipherlen);
                EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
                /* Output decrypted block */
                printf("Plaintext:\n");
                fprintf(stderr, "%s\n", plaintext);
                /* Set expected tag value. */
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(tag),
                                    (void *)tag);
                /* Finalise: note get no output for GCM */
                rv = EVP_DecryptFinal_ex(ctx, plaintext, &outlen);
                /*
                * Print out return value. If this is not successful authentication
                * failed and plaintext is not trustworthy.
                */
                fail_on(rv <= 0, loop_next_err, "Tag wrong");
                EVP_CIPHER_CTX_free(ctx);

                data_json = json_tokener_parse((char *) plaintext);

            }

            /**
             * KMS Decrypt the encrypted command
             */

            struct json_object *command_obj = json_object_object_get(object, "command");

            
            struct aws_byte_buf command = b64_decode(app_ctx, json_object_get_string(command_obj));

            /* Decrypt the data with KMS. */
            struct aws_byte_buf command_decrypted;
            rc = aws_kms_decrypt_blocking(client, &command, &command_decrypted);
            aws_byte_buf_clean_up(&command);
            fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not decrypt ciphertext");

            
            if (data_json == NULL){
                rc = s_send_status(peer_fd, STATUS_OK, (char *)buf);
            }
            if (strstr((char *) command_decrypted.buffer, " ")!= NULL){
                // Data update command (distinguished by two arguments)

                /**
                 * Update JSON with new user test result
                 */
                char * command_string = (char *) command_decrypted.buffer;
                char * uuid = strtok(command_string, " ");
                char * test = strtok(NULL, " ");
                
                

                struct json_object *current_data = json_object_object_get(data_json, uuid);
                char cat_buff[BUF_SIZE];
                if (current_data == NULL){
                    strcpy(cat_buff, test);
                }else{
                    const char * test_hist = json_object_get_string(current_data);
                    strcpy(cat_buff, test_hist);
                    strncat(cat_buff, test, 1);
                }
                json_object_object_add(data_json, uuid, json_object_new_string(cat_buff));


                // Generate random data key

                unsigned char rand_key[256 + 128];
                unsigned char key[256];
                RAND_bytes(rand_key, 256 + 128);
                for ( int i = 0 ; i < 256 ; i++ ){
                    key[i] = rand_key[i]%90 + 33;
                }

                unsigned char iv[128];
                for ( int i = 0 ; i < 128 ; i++ ){
                    iv[i] = iv[256 + i]%90 + 33;
                }


                
                fprintf(stderr, "\n new key: %s\n", (char *) key);
                fprintf(stderr, "\n new iv: %s\n", (char *) iv);

                /**
                 * Encrypt updated data by AES-GCM with newly generated key
                 */
                const char * ret_plaintext = json_object_get_string(data_json);
                unsigned char reencrypted_data [BUF_SIZE];
                int cipherlen;
                int outlen;
                int tag_size = 16;
                unsigned char tag [tag_size];
                EVP_CIPHER_CTX *ctx;
                fprintf(stderr, "AES GCM Encrypt:\n");
                fprintf(stderr, "Plaintext:\n");
                fprintf(stderr, "%s\n", ret_plaintext);
                ctx = EVP_CIPHER_CTX_new();
                /* Set cipher type and mode */
                EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
                /* Set IV length if default 96 bits is not appropriate */
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(iv), NULL);
                /* Initialise key and IV */
                EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
                /* Encrypt plaintext */
                EVP_EncryptUpdate(ctx, reencrypted_data, &outlen, (unsigned char *) ret_plaintext, strlen(ret_plaintext));
                /* Output encrypted block */
                fprintf(stderr, "Ciphertext:\n");
                cipherlen = outlen;
                fprintf(stderr, "%s\n", reencrypted_data);
                
                /* Finalise: note get no output for GCM */
                EVP_EncryptFinal_ex(ctx, reencrypted_data, &outlen);
                
                /* Get tag */
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag);
                /* Output tag */
                fprintf(stderr, "Tag:\n");
                fprintf(stderr, "%s\n", tag);
                EVP_CIPHER_CTX_free(ctx);

                fprintf(stderr, "%s\n", (char *) reencrypted_data);

                struct aws_byte_buf encoded_reencrypted_data = b64_encode(app_ctx, reencrypted_data, cipherlen); // base 64 encrypted data

                fprintf(stderr, "encoded reencrypted %s\n", (char *) encoded_reencrypted_data.buffer);


                /**
                 * Construct new key package
                 * key package holds info for encryption - 256B key, 128B iv, 16B tag, length of ciphertext as 32 bit int
                 */
                unsigned char keypackage [256 + 128 + 16 + 4];
                memset(keypackage, 0, sizeof(keypackage));
                memcpy(keypackage, key, 256);
                memcpy(keypackage + 256, iv, 128);
                memcpy(keypackage + 256 + 128, tag, 16);

                // Storing length of ciphertext in key package as 32-bit int.  Necessary for decryption.
                keypackage[256 + 128 + 16] = (cipherlen >> 24) & 0xFF;
                keypackage[256 + 128 + 16 + 1] = (cipherlen >> 16) & 0xFF;
                keypackage[256 + 128 + 16 + 2] = (cipherlen >> 8) & 0xFF;
                keypackage[256 + 128 + 16 + 3] = (cipherlen) & 0xFF;

                fprintf(stderr, "%s\n", (char *) keypackage);

                /**
                 * KMS Encrypt key package
                 */
                struct aws_byte_buf dec_key = aws_byte_buf_from_array((void *) keypackage, 256 + 128 + 16 + 4);
                struct aws_byte_buf enc_key;

                enc_key = aws_byte_buf_from_c_str(aws_kms_encrypt_get_cipher(client, &dec_key, &enc_key));  // base 64 encrypted key

                fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not encrypt data key");

                // Return 1. AES-GCM encrypted, updated data and 2. KMS encypted AES-GCM data key package to the host instance
                rc = s_send_data_key(peer_fd, STATUS_OK, (char *) encoded_reencrypted_data.buffer, (char *) enc_key.buffer);

                break_on(rc <= 0);

            }else{
                /**
                 * Status query command
                 */
                struct json_object *command_obj = json_object_object_get(data_json, (char *) command_decrypted.buffer);
                const char * test_hist = json_object_get_string(command_obj);

                // Currently, we return a binary risk assessment - 0 if two negative tests, otherwise 1
                // This can be expanded - return a continuous value by complex analysis a user's test history or additional data added to the dataset.
                if (strlen(test_hist) < 2 || strcmp((const char *)test_hist + strlen(test_hist) - 2, "00")==1){
                    rc = s_send_status(peer_fd, STATUS_OK, "1");
                }
                else{
                    rc = s_send_status(peer_fd, STATUS_OK, "0");
                }
                rc = s_send_status(peer_fd, STATUS_OK, (const char *)"query failed?");
            }
            break_on(rc <= 0);
        } else {
            rc = s_send_status(peer_fd, STATUS_ERR, "Operation not recognized");
            break_on(rc <= 0);
        }


        json_object_put(object);
        object = NULL;
        continue;
    loop_next_err:
        json_object_put(object);
        object = NULL;
        rc = s_send_status(peer_fd, STATUS_ERR, err_msg);
        err_msg = NULL;
        break_on(rc <= 0);
    }

    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return;
exit_clean_json:
    json_object_put(object);
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return;
}

int main(int argc, char **argv) {
    int rc = 0;
    struct app_ctx app_ctx;

    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();
    s_parse_options(argc, argv, &app_ctx);

    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };
    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);

    /* Set up a really simple vsock server. We are purposefully using vsock directly
     * in this example, as an example for using it in other projects.
     * High level communication libraries might be better suited for production
     * usage.
     * The server will work as follow:
     * 1. Set up a vsock socket and bind it to port given as a parameter.
     * 2. Listen for new connections on the socket.
     * 3. On a new connection, go into a loop that reads strings split by '\0'.
     *    Each string should be parsed into JSON object containing a command
     *    and its parameters.
     * 4. Process the command.
     * 5. When the connection is closed, listen for a new connection. */
    int vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (vsock_fd < 0) {
        perror("Could not create vsock port");
        exit(1);
    }

    struct sockaddr_vm svm = {
        .svm_family = AF_VSOCK,
        .svm_cid = VMADDR_CID_ANY,
        .svm_port = app_ctx.port,
        .svm_reserved1 = 0, /* needs to be set to 0 */
    };

    rc = bind(vsock_fd, (struct sockaddr *)&svm, sizeof(svm));
    if (rc < 0) {
        perror("Could not bind socket to port");
        close(vsock_fd);
        exit(1);
    }

    rc = listen(vsock_fd, 1);
    if (rc < 0) {
        perror("Could not listen on socket");
        close(vsock_fd);
        exit(1);
    }

    while (true) {
        /* Wait for a new connection. */
        fprintf(stderr, "Awaiting connection...\n");
        int peer_fd = accept(vsock_fd, NULL, NULL);
        fprintf(stderr, "Connected peer\n");
        if (peer_fd < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                /* Try to get a new connection again */
                continue;
            }
            perror("Could not accept new connection");
            close(vsock_fd);
            aws_nitro_enclaves_library_clean_up();
            exit(1);
        }
        handle_connection(&app_ctx, peer_fd);
        fprintf(stderr, "Sesssion ended\n");
        close(peer_fd);
    }

    aws_nitro_enclaves_library_clean_up();
    aws_global_thread_creator_shutdown_wait_for(10);
    return 0;
}
