/*

RokWall Virtual Status Card Enclave Code

Nicholas Chen, Mohammad Behnia, Aneesh Lodhavia, Ruihao Yao, Vikram Sharma Mailthody 2021

Template from https://github.com/aws/aws-nitro-enclaves-sdk-c
*/

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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>
#include <dirent.h> 
#define SERVICE_PORT 3000
#define PROXY_PORT 8000
#define BUF_SIZE 2000000
AWS_STATIC_STRING_FROM_LITERAL(default_region, "us-west-2");

// Dummy inputHash Values to test verification without going through CCF
char *buffer = "A07CD577627D23165C8C92AD91E0AF0D403889E4004992D7425D3BF24FBB5126";
char *buffer_ct = "A07CD577627D23165C8C92AD91E0AF0D403889E4004992D7425D3BF24FBB51260";

// Dummy signature on inputHash+counter to test verification
char *dsignature = "Uv2Mj+OwFTypR60vmpk8xjmqcBLaSssrK0UI4Hg4uH+s9ZNY49EnZI5kFNnRQmGKJ+VzK8eRZq1uMTRnNqaTvFuye0UNqP0yKo1KSy1/Hn/udsBxU5Fp1dkuSaPR+gBccrFoQOGu057YT/w40bBwIE0SJbri4hJTiRpVF+H99cMjJxrlBAG+ovUIxyocYegLATL9lKxVYke68QT/A6QdOtTaUDPFwJ/kRByDpOIWZjbzsEScZtyX5WAHPri28XZ/4KWE5mmEpUEE4sMbzUeTCqSuevMnY6hLp1WZGgIhOGSMknuBVEke1NYZVnrRznA1yKd/0ypBbyl3s5D/SZX90w=="; 


// CCF Public Key - hardcoded in enclave image
char *pem_key_buffer = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA03fJxmXltog3ILBrUsbI\niRvSDWm8VB/Q3rnjhC9FJAzy3869iYFFWgQgTVhv2kwUNCsrvuwUXSMCISsRjR65\nqpsswc0Z8rH+6eR1sFNQtbXDOIIKadNkrCUlqHEAXCGOdZsiJHLzcBTlGRozLwDK\nWZJi4WZt1HYRFYXBt2c8/6A4tCbI29D/rypbH1qVcfY4OMghLyFZikBHGEPp5xxT\n2hTdgFixBFa90vkGhQxtPfBkUQlnp3ylhDMlqn2kWOTYRRPp/E7ZnqBoRFKRXaLb\nLVC6oLwG8vTWVbj7YY9R8p46MoTMoE1IR3otumxoG8BPCGZgxtM6yE8qZBI0JDgo\nIwIDAQAB\n-----END PUBLIC KEY-----\n";   

// Given size of an raw input buffer (N = inlen bytes) compute size of cooresponding base64 encoded buffer -> ceil(4(N/3), 4 bytes)
size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}

// Given a null-terminated/'='padded base64 encoded buffer compute the size of the decoded raw buffer in bytes
size_t b64_decoded_size(const char *in)
{
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
}

// Useful arrays for computing base64 encode and decode
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

// Determine if a char is a valid base64 encoded char
int b64_isvalidchar(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}

// Decode a base64 encoded input buffer, pre-compute expected outlen and writes to array given by "out", returns 1 on success and 0 on error conditions
int c_b64_decode(const char *in, unsigned char *out, size_t outlen)
{
	size_t len;
	size_t i;
	size_t j;
	int    v;

	if (in == NULL || out == NULL)
		return 0;

	len = strlen(in);
	if (outlen < b64_decoded_size(in) || len % 4 != 0)
		return 0;

	for (i=0; i<len; i++) {
		if (!b64_isvalidchar(in[i])) {
			return 0;
		}
	}

	for (i=0, j=0; i<len; i+=4, j+=3) {
		v = b64invs[in[i]-43];
		v = (v << 6) | b64invs[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

		out[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=')
			out[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=')
			out[j+2] = v & 0xFF;
	}

	return 1;
}

// Encode into base64 a raw input string "in" of size "len" bytes, return char array of encoded result. CAUTION: freeing of malloced output buffer is on the caller
char *c_b64_encode(const unsigned char *in, size_t len)
{
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}


unsigned char * HARD_DATAKEY = (unsigned char *) "Deeplearningisnotoriouslyreferredtoasablackboxtechnique,andwithreasonablecause.WhiletraditionalstatisticallearningmethodslikeregressionandBayesianmodelinghelpresearchersdrawdirectconnectionsbetweenfeaturesandpredictions,deepneuralnetworksrequirecomplexcomp";
unsigned char * HARD_IV = (unsigned char *) "ositionsofmanytomanyfunctions.Layeredarchitecturesenableuniversalapproximationbutmakeitdifficulttorecognizeandreacttocostlymista";


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

int s_send_data_key_query(int peer_fd, int status, char * enc_data, char * enc_key, char * result) {
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

    json_object_object_add(status_object, "Message", json_object_new_string(result));

    const char *status_str = json_object_to_json_string(status_object);
    return s_write_all(peer_fd, status_str, strlen(status_str) + 1);
}

int s_send_hash(int peer_fd, int status, char * hash) {
    struct json_object *status_object = json_object_new_object();
    if (status_object == NULL) {
        return -1;
    }

    json_object_object_add(status_object, "Status", json_object_new_string(status == STATUS_OK ? "Ok" : "Error"));

    if (hash != NULL) {
        json_object_object_add(status_object, "Hash", json_object_new_string(hash));
        fprintf(stderr, "GOT HASH\n");
    }
    else {
        fprintf(stderr, "NO HASH\n");
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

struct aws_byte_buf b64_decode(const struct app_ctx *app_ctx, const unsigned char * encoded, const int len) {
    size_t ciphertext_len;
    struct aws_byte_buf ciphertext;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_array(encoded, len);
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
            
			// Verify the signature and content from CCF
			// 1) Is this a valid signature based on public key? if not send STATUS "[CCF] Invalid Signature"
			// 2) Is this a signed signature of the inputHash = hash(encrypted_dataset, encrypted_cmd, 1)? if not send STATUS "[CCF] Invalid InputHash"
			// 3) Is the CCF counter == total_counter? if not send STATUS "[CCF] Mismatch Counter" 
			// else if all checks pass send STATUS "[CCF] Signature Verified!"
            /*struct json_object *sig_jobj = json_object_object_get(object, "signature");
            if (sig_jobj != NULL) {
				
               	fprintf(stderr, "Start Verification of Signature");       
				
				struct json_object *ciphertext_obj = json_object_object_get(object, "Ciphertext");
				struct json_object *datakey_obj = json_object_object_get(object, "data_key");
				
				fail_on(datakey_obj == NULL || ciphertext_obj == NULL, loop_next_err, "Ciphertext needs data key");
				
                // TODO: buffer_ct is hardcoded, compute buffer_ct = hash(dataset + cmds) || current_counter
                unsigned char digest[SHA256_DIGEST_LENGTH];
                SHA256_CTX ctx;
                SHA256_Init(&ctx);
                SHA256_Update(&ctx, buffer_ct, 65);
                SHA256_Final(digest, &ctx);

                BIO *bufio;
                bufio = BIO_new_mem_buf((char*)pem_key_buffer, strlen(pem_key_buffer));
                RSA* rsa_pubkey =  PEM_read_bio_RSA_PUBKEY(bufio, NULL, NULL, NULL);
                
                const char* signa = json_object_get_string(sig);
                char *out;
                size_t out_len;  
                out_len = b64_decoded_size(signature)+1;
                out = malloc(out_len);
                if (!c_b64_decode(signa, (unsigned char *)out, out_len)) {
                    fprintf(stderr, signa); 
                    rc = s_send_status(peer_fd, STATUS_ERR, signa); 
                }
                out[out_len] = '\0';

                int result = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, (const unsigned char *) out, 256, rsa_pubkey);

                RSA_free(rsa_pubkey);  
                BIO_free(bufio);

                if(result == 1)
                {
                    rc = s_send_status(peer_fd, STATUS_OK, "Signature Valid");  
                }
                else
                {
                    rc = s_send_status(peer_fd, STATUS_ERR, "Signature NOT Valid");   
                }

            }
            else {
                rc = s_send_status(peer_fd, STATUS_OK, "NO Signature");
            }*/
            
            /*
             1. Decrypt data key
                If no key, assert no data.  If neither, create new data.
             2. Decrypt data
             3. Decrypt command
             4. Run command
             5. Return val (either result or updated data)
             */


            fprintf(stderr, "\nNEW ENCLAVE COMMAND\n");
            struct json_object *ciphertext_obj = json_object_object_get(object, "Ciphertext");
            struct json_object *datakey_obj = json_object_object_get(object, "data_key");
            
            fail_on(datakey_obj == NULL && (ciphertext_obj != NULL && (strcmp(json_object_get_string(ciphertext_obj), "None") != 0)), loop_next_err, "Ciphertext needs data key");

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

                const char * encoded_cipherkey = json_object_get_string(datakey_obj);

                fprintf(stderr, "Cipher: %s\n", encoded_cipherkey);
                
                struct aws_byte_buf cipherkey = b64_decode(app_ctx, (unsigned char *) encoded_cipherkey, strlen(encoded_cipherkey));
                fprintf(stderr, "Cipher Decoded: %s\n", (char *) cipherkey.buffer);
                struct aws_byte_buf datakey_package_decrypted;
                rc = aws_kms_decrypt_blocking(client, &cipherkey, &datakey_package_decrypted);
                fprintf(stderr, "KMS Decrypted: %s\n", (char *) datakey_package_decrypted.buffer);
                struct aws_byte_buf cipherkey_decoded = b64_decode(app_ctx, datakey_package_decrypted.buffer, datakey_package_decrypted.len);
                fprintf(stderr, "Decrypt Decoded: %s\n", (char *) cipherkey_decoded.buffer);
                // key package holds info for encryption - 256B key, 128B iv, 16B tag, length of ciphertext as 32 bit int
                unsigned char * datakey_package = cipherkey_decoded.buffer;
                unsigned char datakey [257];
                unsigned char iv [129];
                unsigned char tag [17];
                int cipherlen = 0;

                cipherlen += datakey_package[256 + 128 + 16] << 24;
                cipherlen += datakey_package[256 + 128 + 16 + 1] << 16;
                cipherlen += datakey_package[256 + 128 + 16 + 2] << 8;
                cipherlen += datakey_package[256 + 128 + 16 + 3];

                memcpy(datakey, (char *) cipherkey_decoded.buffer, 256);
                memcpy(iv, ((char*) cipherkey_decoded.buffer) + 256, 128);
                memcpy(tag, ((char*) cipherkey_decoded.buffer) + 256 + 128, 16);
                datakey[256] = '\0';
                iv[128] = '\0';
                tag[16] = '\0';

                fprintf(stderr, "KMS Decrypted data key: %s\n", (char *) datakey);
                fprintf(stderr, "KMS Decrypted data iv: %s\n", (char *) iv);
                fprintf(stderr, "KMS Decrypted data tag: %s\n", (char *) tag);
                fprintf(stderr, "KMS Decrypted data length: %d\n", cipherlen);

                /**
                * Use data key to decrypt test result data
                */
                
                const char * b64_cipher_const = json_object_get_string(ciphertext_obj);
                char b64_ciphertext [strlen(b64_cipher_const) + 1];
                memset(b64_ciphertext, 0, sizeof(b64_ciphertext));
                strcpy(b64_ciphertext, b64_cipher_const);

                fprintf(stderr, "\nb64 cipher: %s\n", b64_ciphertext);

                struct aws_byte_buf ciphertext_buf = b64_decode(app_ctx, (unsigned char *) b64_ciphertext, strlen(b64_cipher_const));

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
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 128, NULL);
                /* Specify key and IV */
                EVP_DecryptInit_ex(ctx, NULL, NULL, datakey, iv);
                /* Decrypt plaintext */
                fprintf(stderr, "%d\n", cipherlen);
                EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
                /* Output decrypted block */
                printf("Plaintext:\n");
                fprintf(stderr, "%s\n", plaintext);
                /* Set expected tag value. */
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
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
            const char * commands_string_const = json_object_get_string(command_obj);
            char commands_string [strlen(commands_string_const) + 1];
            memset(commands_string, 0, sizeof(commands_string));
            strcpy(commands_string, commands_string_const);

            int num_commands = 1;
            char *pch = strchr(commands_string,';');

            while (pch!=NULL) {
                num_commands++;
                pch = strchr(pch+1,';');
            }

            struct aws_byte_buf command_list[num_commands];

            int command_ind = 0;
            char * command_str = strtok(commands_string, ";");
            while (command_str!=NULL) {
                struct aws_byte_buf command_encrypted = b64_decode(app_ctx, (unsigned char *) command_str, strlen(command_str));
                rc = aws_kms_decrypt_blocking(client, &command_encrypted, &command_list[command_ind]);
                aws_byte_buf_clean_up(&command_encrypted);
                fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not decrypt ciphertext");
                command_ind++;
                command_str = strtok(NULL, ";");
            }

            fprintf(stderr, "Num commands: %d\n", num_commands);

            for ( int i = 0 ; i < num_commands ; i++ ){
                fprintf(stderr, "Command #%d: %s\n", i, (char *)command_list[i].buffer);
            }
            
            
            
            /*
            fprintf(stderr, "encoded encrypted: %s\n", json_object_get_string(command_obj));
            struct aws_byte_buf command = b64_decode(app_ctx, (unsigned char *) json_object_get_string(command_obj), strlen(json_object_get_string(command_obj)));

            struct aws_byte_buf command_decrypted;
            
            rc = aws_kms_decrypt_blocking(client, &command, &command_decrypted);
            aws_byte_buf_clean_up(&command);
            fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not decrypt ciphertext");
            */
			
			/* Verification of the signature and content from CCF */
			// 1) Is this a valid signature based on public key? if not send STATUS "[CCF] Invalid Signature"
			// 2) Is this a signed signature of the inputHash = hash(encrypted_dataset, encrypted_cmd, 1)? if not send STATUS "[CCF] Invalid InputHash"
			// 3) Is the CCF counter == total_counter? if not send STATUS "[CCF] Mismatch Counter" 
			// else if all checks pass send STATUS "[CCF] Signature Verified!"
			const char *enc_data = json_object_get_string(ciphertext_obj);
			const char *enc_cmd = json_object_get_string(command_obj);
			
			char preimage_buf[BUF_SIZE];
			
			strcpy(preimage_buf, "");
			if(enc_data != NULL) {
				strncat(preimage_buf, enc_data, strlen(enc_data));
				fprintf(stderr, "HASH data: %s\n", preimage_buf);
			}
			if(enc_cmd != NULL) {
				strncat(preimage_buf, enc_cmd, strlen(enc_cmd));
				fprintf(stderr, "HASH cmd: %s\n", preimage_buf);
			}
			strncat(preimage_buf, "1", 1);
			fprintf(stderr, "HASH pre: %s\n", preimage_buf);
			
			unsigned char inputHash[SHA256_DIGEST_LENGTH];
			SHA256_CTX hctx;
			SHA256_Init(&hctx);
			SHA256_Update(&hctx, preimage_buf, strlen(preimage_buf));
			SHA256_Final(inputHash, &hctx);
			int i;
			char hexstring[256];
			char *strptr = hexstring;
			for (i = 0; i < 32; i++)
			{
				sprintf(strptr, "%02x", inputHash[i]);
				strptr += 2;
			}
							
            
            int64_t total_counter = 0;
			int mismatch_counter_flag = 0;
			int mismatch_counter_delta = 0;	
			int global_counter = 0;
			
			struct json_object *sig_jobj = json_object_object_get(object, "signature");
            struct json_object *cnt_jobj = json_object_object_get(object, "counter");
			if(cnt_jobj == NULL || sig_jobj == NULL) {
                	fprintf(stderr, "NO SIGNATURE OR COUNTER\n"); 
            }
			else {
				const char* signature = json_object_get_string(sig_jobj);
				const char* counter = json_object_get_string(cnt_jobj);
				global_counter = atoi(counter);
				struct json_object *totcount_jobj = json_object_object_get(data_json, "total_counter");
				if (totcount_jobj != NULL) {
					total_counter = json_object_get_int64(totcount_jobj);
				}
				else {
					total_counter = 0;
				}	
				if (total_counter+1 != global_counter) {
					mismatch_counter_flag = 1;
					mismatch_counter_delta = global_counter - total_counter - 1;
				}

				sprintf(strptr, "%d", global_counter);

				unsigned char digest[SHA256_DIGEST_LENGTH];
				SHA256_CTX sctx;
				SHA256_Init(&sctx);
				SHA256_Update(&sctx, hexstring, strlen(hexstring));
				SHA256_Final(digest, &sctx);

				BIO *bufio;
				bufio = BIO_new_mem_buf((char*)pem_key_buffer, strlen(pem_key_buffer));
				RSA* rsa_pubkey =  PEM_read_bio_RSA_PUBKEY(bufio, NULL, NULL, NULL);


				char *out;
				size_t out_len;  
				out_len = b64_decoded_size(signature)+1;
				out = malloc(out_len);
				if (!c_b64_decode(signature, (unsigned char *)out, out_len)) {
					fprintf(stderr, signature); 
					rc = s_send_status(peer_fd, STATUS_ERR, signature); 
				}
				out[out_len] = '\0';

				int result = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, (const unsigned char *) out, 256, rsa_pubkey);

				RSA_free(rsa_pubkey);  
				BIO_free(bufio);

				if(result == 1 && (mismatch_counter_flag == 0)){
					fprintf(stderr, "SIGNATURE VALID[%d]: %s\n", global_counter, preimage_buf); 
				}
				else if(result == 1 && (mismatch_counter_flag == 1)){
					fprintf(stderr, "SIGNATURE INVALID COUNTER MISMATCH [%d] vs [%ld] %s: %s\n", global_counter, total_counter+1, hexstring, preimage_buf); 
				}
				else {
					fprintf(stderr, "SIGNATURE INVALID[%d]: %s, HASH: %s\n", global_counter, signature, preimage_buf);  
				}

			}
			
			char batch_result [BUF_SIZE];
            memset(batch_result, 0, sizeof(batch_result));
            int batch_result_written = 0;

            /* Data Update */
            if (data_json == NULL){
                rc = s_send_status(peer_fd, STATUS_OK, (char *)buf);
            }

            for( int cmd_ind = 0 ; cmd_ind < num_commands ; cmd_ind++ ){
                struct aws_byte_buf command_decrypted = command_list[cmd_ind];

                if (strstr((char *) command_decrypted.buffer, " ") != NULL){
                    // Data update command (distinguished by two arguments)

                    /**
                        * Update JSON with new user test result
                        */
                    char * command_string = (char *) command_decrypted.buffer;
                    char * uuid = strtok(command_string, " ");
                    char * test = strtok(NULL, " ");
                    
                    fprintf(stderr, "[DATASET] BEFORE UPDATE: %s\n", json_object_to_json_string(data_json));
                    char temp_buff[BUF_SIZE];
                    
                    // Get "userdata" field
                    struct json_object *userdata_jobj = json_object_object_get(data_json, "user_data");
                    
                    // If userdata_jobj is NULL dataset is empty and we need to initialize it
                    if (userdata_jobj == NULL){
                        
                        struct json_object *uuid_jobj = json_object_new_object();
                        json_object_object_add(uuid_jobj, "test_history", json_object_new_string(test));
                        json_object_object_add(uuid_jobj, "query_counter", json_object_new_int64((int64_t)1));
                        
                        userdata_jobj = json_object_new_object();
                        json_object_object_add(userdata_jobj, uuid, uuid_jobj);
                        
                        json_object_object_add(data_json, "user_data", userdata_jobj);
                        json_object_object_add(data_json, "total_counter", json_object_new_int64((int64_t)1));
                        
                    }
                    else {
                        
                        struct json_object *uuid_jobj = json_object_object_get(userdata_jobj, uuid);
                        
                        // If uuid_jobj is NULL, first time user has queried add user 
                        if (uuid_jobj == NULL){

                            struct json_object *uuid_jobj = json_object_new_object();
                            json_object_object_add(uuid_jobj, "test_history", json_object_new_string(test));
                            json_object_object_add(uuid_jobj, "query_counter", json_object_new_int64((int64_t)1));
                            json_object_object_add(userdata_jobj, uuid, uuid_jobj);

                            int64_t total_counter = json_object_get_int64(json_object_object_get(data_json, "total_counter"));
                            json_object_object_add(data_json, "total_counter", json_object_new_int64(total_counter+1));	
                            
                        }
                        else {

                            const char *test_history = json_object_get_string(json_object_object_get(uuid_jobj, "test_history"));
                            strcpy(temp_buff, test_history);
                            strncat(temp_buff, test, 1);
                            json_object_object_add(uuid_jobj, "test_history", json_object_new_string(temp_buff));
                            int64_t query_counter = json_object_get_int64(json_object_object_get(uuid_jobj, "query_counter"));
                            json_object_object_add(uuid_jobj, "query_counter", json_object_new_int64(query_counter+1));
                            
                            int64_t total_counter = json_object_get_int64(json_object_object_get(data_json, "total_counter"));
                            json_object_object_add(data_json, "total_counter", json_object_new_int64(total_counter+1));	
                            
                        }
                    }
                    
                    // Update result string with delimiter (empty value for update)
                    batch_result[batch_result_written] = ';';
                    batch_result_written++;
                    
                    // Handle delta in global_counter vs total_counter
                    if (mismatch_counter_flag){
                        struct json_object *counter_mismatch_jobj = json_object_object_get(data_json, "counter_mismatch");
                        if(counter_mismatch_jobj == NULL) {
                            counter_mismatch_jobj = json_object_new_object();
                            json_object_object_add(counter_mismatch_jobj, hexstring, json_object_new_int64((int64_t)mismatch_counter_delta));
                            json_object_object_add(data_json, "counter_mismatch", counter_mismatch_jobj);
                        }
                        else {
                            json_object_object_add(counter_mismatch_jobj, hexstring, json_object_new_int64((int64_t)mismatch_counter_delta));
                        }
                        int total_count = 0;
                        struct json_object *totcount_jobj = json_object_object_get(data_json, "total_counter");
                        if (totcount_jobj != NULL) {
                            total_count = json_object_get_int64(totcount_jobj);
                        }				
                        json_object_object_add(data_json, "total_counter", json_object_new_int64((int64_t)total_count+mismatch_counter_delta));
                    }
                    
                    fprintf(stderr, "[DATASET] AFTER UPDATE: %s\n", json_object_to_json_string(data_json));		
                    

                }else{
                    // status query
                    // returns 0 or 1 for low and high risk respectively
                    //rc = s_send_status(peer_fd, STATUS_OK, (const char *)"query");
                    fprintf(stderr, "[DATASET] BEFORE QUERY: %s\n", json_object_to_json_string(data_json));
                    struct json_object *userdata_jobj = json_object_object_get(data_json, "user_data");
                    if(userdata_jobj == NULL) {
                        rc = s_send_status(peer_fd, STATUS_ERR, (const char *)"Dataset uninitialized: User does not exist");
                    }
                    else {
                        struct json_object *uuid_jobj = json_object_object_get(userdata_jobj, (char *) command_decrypted.buffer);
                        if(uuid_jobj == NULL) {
                            rc = s_send_status(peer_fd, STATUS_ERR, (const char *)"Dataset initialized: User does not exist");
                        }
                        else {
                            
                            int64_t query_counter = json_object_get_int64(json_object_object_get(uuid_jobj, "query_counter"));
                            json_object_object_add(uuid_jobj, "query_counter", json_object_new_int64(query_counter+1));
                            
                            int64_t total_counter = json_object_get_int64(json_object_object_get(data_json, "total_counter"));
                            json_object_object_add(data_json, "total_counter", json_object_new_int64(total_counter+1));	
                            
                            struct json_object *testhist_jobj = json_object_object_get(uuid_jobj, "test_history");
                            const char * test_hist = json_object_get_string(testhist_jobj);
                            if (strlen(test_hist) < 2 || strcmp((const char *)test_hist + strlen(test_hist) - 2, "00")==1){
                                // Update result string with delimiter (status value for query)
                                batch_result[batch_result_written] = '1';
                                batch_result[batch_result_written+1] = ';';
                                batch_result_written += 2;
                            }
                            else{
                                // Update result string with delimiter (status value for query)
                                batch_result[batch_result_written] = '0';
                                batch_result[batch_result_written+1] = ';';
                                batch_result_written += 2;
                            }
                        }
                    }

                    
                    
                    // Handle delta in global_counter vs total_counter
                    if (mismatch_counter_flag){
                        struct json_object *counter_mismatch_jobj = json_object_object_get(data_json, "counter_mismatch");
                        if(counter_mismatch_jobj == NULL) {
                            counter_mismatch_jobj = json_object_new_object();
                            json_object_object_add(counter_mismatch_jobj, hexstring, json_object_new_int64((int64_t)mismatch_counter_delta));
                            json_object_object_add(data_json, "counter_mismatch", counter_mismatch_jobj);
                        }
                        else {
                            json_object_object_add(counter_mismatch_jobj, hexstring, json_object_new_int64((int64_t)mismatch_counter_delta));
                        }
                        int total_count = 0;
                        struct json_object *totcount_jobj = json_object_object_get(data_json, "total_counter");
                        if (totcount_jobj != NULL) {
                            total_count = json_object_get_int64(totcount_jobj);
                        }				
                        json_object_object_add(data_json, "total_counter", json_object_new_int64((int64_t)total_count+mismatch_counter_delta));
                    }
                    
                    fprintf(stderr, "[DATASET] AFTER QUERY: %s\n", json_object_to_json_string(data_json));
                            
                    fprintf(stderr, "[KEYGEN] AFTER QUERY\n");
                }
            }

            // Generate random data key

            unsigned char rand_key[256 + 128];
            unsigned char key[257];
            RAND_bytes(rand_key, 256 + 128);
            for ( int i = 0 ; i < 256 ; i++ ){
                key[i] = rand_key[i]%90 + 33;
            }
            unsigned char iv[129];
            for ( int i = 0 ; i < 128 ; i++ ){
                iv[i] = rand_key[256 + i]%90 + 33;
            }

            key[256] = '\0';
            iv[128] ='\0';

            fprintf(stderr, "\n new key: %s\n", (char *) key);
            fprintf(stderr, "\n new iv: %s\n", (char *) iv);

            /**
                * Encrypt updated data by AES-GCM with newly generated key
                */
            const char * ret_plaintext = json_object_get_string(data_json);
            fprintf(stderr, "1146 ret plaintext %s\n", ret_plaintext);
            unsigned char reencrypted_data [BUF_SIZE];
            int cipherlen;
            int outlen;
            int tag_size = 17;
            unsigned char tag [tag_size];
            tag[16] = '\0';
            EVP_CIPHER_CTX *ctx;
            fprintf(stderr, "AES GCM Encrypt:\n");
            fprintf(stderr, "Plaintext:\n");
            fprintf(stderr, "%s\n", ret_plaintext);
            ctx = EVP_CIPHER_CTX_new();
            /* Set cipher type and mode */
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            /* Set IV length if default 96 bits is not appropriate */
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 128, NULL);
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
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
            /* Output tag */
            fprintf(stderr, "Tag:\n");
            fprintf(stderr, "%s\n", tag);
            EVP_CIPHER_CTX_free(ctx);

            fprintf(stderr, "%s\n", (char *) reencrypted_data);

            struct aws_byte_buf encoded_reencrypted_data = b64_encode(app_ctx, reencrypted_data, cipherlen); // base 64 encrypted data

            fprintf(stderr, "encoded reencrypted %s\n", (char *) encoded_reencrypted_data.buffer);

            struct aws_byte_buf decoded_reencrypted_data = b64_decode(app_ctx, encoded_reencrypted_data.buffer, encoded_reencrypted_data.len);

            fprintf(stderr, "decoded reencrypted %s\n", (char *) decoded_reencrypted_data.buffer);

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

            fprintf(stderr, "New Generated data key: %s\n", (char *) key);
            fprintf(stderr, "New Generated data iv: %s\n", (char *) iv);
            fprintf(stderr, "New Generated data tag: %s\n", (char *) tag);
            fprintf(stderr, "New Generated data length: %d\n", cipherlen);

            struct aws_byte_buf keypackage_encoded = b64_encode(app_ctx, keypackage, 256 + 128 + 16 + 4); // base 64 encrypted data
            fprintf(stderr, "New Encoded Keypackage: %s\n", (char *) keypackage_encoded.buffer);
            /**
            * KMS Encrypt key package
            */
            //struct aws_byte_buf dec_key = aws_byte_buf_from_array((void *) keypackage, 256 + 128 + 16 + 4);
            struct aws_byte_buf enc_key;

            //aws_kms_encrypt_blocking(client, &keypackage_encoded, &enc_key);

            enc_key = aws_byte_buf_from_c_str(aws_kms_encrypt_get_cipher(client, &keypackage_encoded, &enc_key));  // base 64 encrypted key

            //fail_on(rc != AWS_OP_SUCCESS, loop_next_err, "Could not encrypt data key");

            // Return 1. AES-GCM encrypted, updated data and 2. KMS encypted AES-GCM data key package to the host instance

            rc = s_send_data_key_query(peer_fd, STATUS_OK, (char *) encoded_reencrypted_data.buffer, (char *) enc_key.buffer, batch_result);

            /*
            if (query_result == -1){
                rc = s_send_data_key(peer_fd, STATUS_OK, (char *) encoded_reencrypted_data.buffer, (char *) enc_key.buffer);
            }
            else{
                rc = s_send_data_key_query(peer_fd, STATUS_OK, (char *) encoded_reencrypted_data.buffer, (char *) enc_key.buffer, query_result + '0');
            }
            */

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
