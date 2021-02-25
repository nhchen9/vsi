/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_key[] = "key";

static const unsigned char gcm_iv[] = "iv";

static const unsigned char gcm_pt[] =  "Deeplearningisnotoriouslyreferredtoasablackboxtechnique,andwithreasonablecause.WhiletraditionalstatisticallearningmethodslikeregressionandBayesianmodelinghelpresearchersdrawdirectconnectionsbetweenfeaturesandpredictions,deepneuralnetworksrequirecomplexcompDeeplearningisnotoriouslyDeeplearningisnotoriouslyreferredtoasablackboxtechnique,andwithreasonablecause.WhiletraditionalstatisticallearningmethodslikeregressionandBayesianmodelinghelpresearchersdrawdirectconnectionsbetweenfeaturesandpredictions,deepneuralnetworksrequirecomplexcompDeeplearningisnotoriously";

int tag_size = 16;

static unsigned char tag[16];

static unsigned char ciphertext[1024];
static int cipherlen;
void aes_gcm_encrypt(void)
{
    int outlen;
    EVP_CIPHER_CTX *ctx;
    printf("AES GCM Encrypt:\n");
    printf("Plaintext:\n");
    fprintf(stdout, "%s\n", gcm_pt);
    //BIO_dump_fp(stdout, gcm_pt, sizeof(gcm_pt));
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, gcm_pt, sizeof(gcm_pt));
    /* Output encrypted block */
    printf("Ciphertext:\n");
    cipherlen = outlen;
    fprintf(stdout, "%s\n", ciphertext);
    fprintf(stdout, "%d\n", cipherlen); 
    
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, ciphertext, &outlen);
    
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag);
    /* Output tag */
    printf("Tag:\n");
    fprintf(stdout, "%s\n", tag);
    EVP_CIPHER_CTX_free(ctx);
}

void aes_gcm_decrypt(void)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
    unsigned char outbuf[1024];
    printf("AES GCM Decrypt:\n");
    printf("Ciphertext:\n");
    fprintf(stdout, "%s\n", ciphertext);
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Decrypt plaintext */
    fprintf(stdout, "%d\n", cipherlen);
    EVP_DecryptUpdate(ctx, outbuf, &outlen, ciphertext, cipherlen);
    /* Output decrypted block */
    printf("Plaintext:\n");
    fprintf(stdout, "%s\n", outbuf);
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(tag),
                        (void *)tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    EVP_CIPHER_CTX_free(ctx);
}

int main(void)
{
    aes_gcm_encrypt();
    aes_gcm_decrypt();
}