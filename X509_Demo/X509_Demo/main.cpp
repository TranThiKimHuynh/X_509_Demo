#define _CRT_SECURE_NO_WARNINGS
#define OPENSSL_API_COMPAT 0x10101000L
#pragma comment (lib, "User32.lib")

#include <cstdio>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

RSA* generate_key()
{
    /* Allocate memory for the RSA structure. */
    RSA* rsa = RSA_new();
    if (!rsa)
    {
        std::cerr << "Unable to create RSA structure." << std::endl;
        return NULL;
    }

    /* Generate the RSA key. */
    BIGNUM* bne = BN_new();
    if (!bne || !BN_set_word(bne, RSA_F4) || !RSA_generate_key_ex(rsa, 2048, bne, NULL))
    {
        std::cerr << "Unable to generate 2048-bit RSA key." << std::endl;
        if (bne) BN_free(bne);
        RSA_free(rsa);
        return NULL;
    }

    BN_free(bne);


    return rsa;
}


/* Generates a self-signed x509 certificate. */
X509* generate_x509(RSA* pRSA)
{
    /* Allocate memory for the X509 structure. */
    X509* x509 = X509_new();
    if (!x509)
    {
        std::cerr << "Unable to create X509 structure." << std::endl;
        return NULL;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Create a new EVP_PKEY structure and set it with the RSA key */
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey)
    {
        std::cerr << "Unable to create EVP_PKEY structure." << std::endl;
        X509_free(x509);
        return NULL;
    }
    if (!EVP_PKEY_assign_RSA(pkey, pRSA))
    {
        std::cerr << "Unable to assign RSA key to EVP_PKEY." << std::endl;
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NULL;
    }

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME* name = X509_get_subject_name(x509);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"VN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"HCMUS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Team_3", -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);

    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509, pkey, EVP_sha1()))
    {
        std::cerr << "Error signing certificate." << std::endl;
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NULL;
    }

    EVP_PKEY_free(pkey);

    return x509;
}


bool write_to_disk(RSA* pRSA, X509* x509)
{
    /* Open the PEM file for writing the key to disk. */
    BIO* pOut = BIO_new_file("key.pem", "w");
    if (!pOut)
    {
        std::cerr << "Unable to open \"key.pem\" for writing." << std::endl;
        return false;
    }

    /* Write the key to disk. */
    if (!PEM_write_bio_RSAPrivateKey(pOut, pRSA, NULL, NULL, 0, NULL, NULL))
    {
        std::cerr << "Unable to write private key to disk." << std::endl;
        return false;
    }
    BIO_free_all(pOut);
    /* Open the PEM file for writing the certificate to disk. */
    BIO* x509file = BIO_new_file("cer.pem", "w");
    if (!x509file)
    {
        std::cerr << "Unable to open \"cert.pem\" for writing." << std::endl;
        return false;
    }
    if (!PEM_write_bio_X509(x509file, x509))
    {
        std::cerr << "Unable to write certificate to disk." << std::endl;
        return false;
    }
    BIO_free_all(x509file);

    return true;
}


int main(int argc, char** argv)
{
    /* Generate the key. */
    std::cout << "Generating RSA key..." << std::endl;

    RSA* pkey = generate_key();
    if (!pkey)
        return 1;

    /* Generate the certificate. */
    std::cout << "Generating x509 certificate..." << std::endl;

    X509* x509 = generate_x509(pkey);
    if (!x509)
    {
        RSA_free(pkey);
        return 1;
    }

    /* Write the private key and certificate out to disk. */
    std::cout << "Writing key and certificate to disk..." << std::endl;

    bool ret = write_to_disk(pkey, x509);

    if (ret)
    {
        std::cout << "Success!" << std::endl;

        X509_free(x509);
        return 0;
    }

    else {

        X509_free(x509);
        return 1;

    }


}