
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include "ScopedLocalCertificateChainFiles.h"
#include "Certificate.h"

#define FILL_WITH_OCTET_STRING(Ivalue, Ibuf, Isize, oRet)       \
    do {                                                        \
        OCTET_STRING_t ostr;                                    \
        memset(&ostr, 0, sizeof(OCTET_STRING_t));               \
        oRet = OCTET_STRING_fromBuf(&ostr, Ibuf, Isize);        \
        Ivalue = ostr;                                          \
    } while (0)
        
#define ERRO_FD  stderr
#define INFO_FD  stdout

#define _ECHO(type, format, ...)              \
    do {                                      \
        fprintf(type, format, ##__VA_ARGS__); \
    } while (0)

#define ECHO(type, format, ...)                                            \
    do {                                                                   \
        _ECHO(type ## _FD, "%s %3d " format "\n",                       \
                "[" #type "] ", __LINE__, ##__VA_ARGS__);        \
    } while (0)

#define ScmsFileVersion             1
#define GccfVersion                 0
#define LccfVersion                 0

#define COER_NAME  ("own.ScopedLocalCertificateChainFiles.coer")

static const char ucs[] = {
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                        'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O',
                        'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A',
                        'z', 'y', 'x', 'w', 'v', 'u', 't', 's', 'r', 'q', 'p', 'o',
                        'n', 'm', 'l', 'k', 'j', 'i', 'h', 'g', 'f', 'e', 'd', 'c', 'b', 'a',
                        '9', '8', '7', '6', '5', '4', '3', '2', '1', '0'
                        };

inline int oer_encode_write_callback(const void *buffer, size_t size, void *userp)
{
    std::string * str = dynamic_cast<std::string *>((std::string *)userp);
    str->append((char *)buffer, size);
    return (int)size;
}

int decodeCertificate(Certificate_t **cert)
{
    asn_dec_rval_t rval;
    
    std::ifstream ifs("../Certificate.coer", std::ifstream::in | std::ifstream::binary);
    if (! ifs.is_open()) {
        ECHO(ERRO, "open file for reading failed");
        return -1;
    }
    
    std::ostringstream oss;

    oss << ifs.rdbuf();
    ifs.close();
    
    std::string strStream(oss.str());
        
    rval = oer_decode(0,
                      &asn_DEF_Certificate,
                      (void**)cert,
                      strStream.c_str(),
                      strStream.size());
    if (rval.code != RC_OK) {
        return -1;
    }

    return 0;
}

int encodeScopedLocalCertificateChainFile()
{
    int ret = -1, i = 0, icode = -1;
    asn_enc_rval_t ecrval;
    std::string encodedStream;
    
    ScopedLocalCertificateChainFiles_t* pstScopedLocalCertificateChainFiles = nullptr;
    
    pstScopedLocalCertificateChainFiles = (ScopedLocalCertificateChainFiles_t*)
                                    calloc(1, sizeof(ScopedLocalCertificateChainFiles_t));
    if (pstScopedLocalCertificateChainFiles == nullptr) {
        ECHO(ERRO, "calloc failed");
        goto cleanup;
    }
    /** CompositeVersion - version field */
    pstScopedLocalCertificateChainFiles->version = ScmsFileVersion;
    pstScopedLocalCertificateChainFiles->content.present = ScmsFile__content_PR_cert_chain;
    pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                .localCertificateChainFile.version.gccfVersion = GccfVersion;
    pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                .localCertificateChainFile.version.lccfVersion = LccfVersion;
    pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                .localCertificateChainFile.version.lccfVersion = LccfVersion;
    FILL_WITH_OCTET_STRING(
    pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                .localCertificateChainFile.version.raHostname, ucs, 10, ret);
    if (ret != 0) {
        ECHO(ERRO, "OCTET_STRING_fromBuf failed");
        goto cleanup;
    }

    /** CertificateStore - requiredCertStore */
    {
        /** rootCACertificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.rootCACertificate = pstCertificate;
    }
    {
        /** icaCertificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.icaCertificate = pstCertificate;
    }
    {
        /** cracaCertificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.cracaCertificate = pstCertificate;
    }
    {
        /** pgCertificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.pgCertificate = pstCertificate;
    }
    {
        /** ecaCertificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.ecaCertificate = pstCertificate;
    }
    {
        /** pcaCertificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.pcaCertificate = pstCertificate;
    }
    {
        /** maCertificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.maCertificate = pstCertificate;
    }
    // {
        // /** raCppCertificate */
        // Certificate_t* pstCertificate = nullptr;
        // ret = decodeCertificate(&pstCertificate);
        // if (ret != 0) {
            // ECHO(ERRO, "decodeCertificate failed");
            // goto cleanup;
        // }
        
        // pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    // .localCertificateChainFile
                                        // .requiredCertStore.raCppCertificate = pstCertificate;
    // }
    // {
        // /** la1Certificate */
        // Certificate_t* pstCertificate = nullptr;
        // ret = decodeCertificate(&pstCertificate);
        // if (ret != 0) {
            // ECHO(ERRO, "decodeCertificate failed");
            // goto cleanup;
        // }
        
        // pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    // .localCertificateChainFile
                                        // .requiredCertStore.la1Certificate = pstCertificate;
    // }
    {
        /** la2Certificate */
        Certificate_t* pstCertificate = nullptr;
        ret = decodeCertificate(&pstCertificate);
        if (ret != 0) {
            ECHO(ERRO, "decodeCertificate failed");
            goto cleanup;
        }
        
        pstScopedLocalCertificateChainFiles->content.choice.cert_chain
                                    .localCertificateChainFile
                                        .requiredCertStore.la2Certificate = pstCertificate;
    }
    
    
    ecrval = oer_encode(&asn_DEF_ScopedLocalCertificateChainFiles,
                        pstScopedLocalCertificateChainFiles,
                        oer_encode_write_callback,
                        (void*)&encodedStream);
    if (-1 == ecrval.encoded) {
        ECHO(ERRO, "oer_encoded failed");
        goto cleanup;
    }
    
    {
        std::ofstream ofs(COER_NAME, std::ofstream::out | std::ofstream::binary);
        ofs << encodedStream;
        ofs.close();
    }
    
    xer_fprint(stdout, &asn_DEF_ScopedLocalCertificateChainFiles, pstScopedLocalCertificateChainFiles);
    
    icode = 0;
cleanup:
    if (pstScopedLocalCertificateChainFiles) {
        ASN_STRUCT_FREE(asn_DEF_ScopedLocalCertificateChainFiles, pstScopedLocalCertificateChainFiles);
    }
    
    return icode;
}

int main()
{
    int ret, i;
    
    ret = encodeScopedLocalCertificateChainFile();
    if (ret != 0) {
        return -1;
    }
    
    asn_dec_rval_t rval;
    
    std::ifstream ifs(COER_NAME, std::ifstream::in | std::ifstream::binary);
    if (! ifs.is_open()) {
        ECHO(ERRO, "open %s failed", COER_NAME);
        return -1;
    }
    
    std::ostringstream oss;
    
    oss << ifs.rdbuf();
    
    std::string strStream(oss.str());
    ifs.close();
    
    int counter = 0, total = 1000;
    
    for (i = 0; i < total; i++) {
        ScopedLocalCertificateChainFiles_t* pstScopedLocalCertificateChainFiles = nullptr;
        
        rval = oer_decode(0, &asn_DEF_ScopedLocalCertificateChainFiles,
                          (void**)&pstScopedLocalCertificateChainFiles,
                          strStream.c_str(),
                          strStream.size());
        if (rval.code != RC_OK) {
            ECHO(ERRO, "oer_decode failed");
            continue;
        }

        if (pstScopedLocalCertificateChainFiles) {
            ASN_STRUCT_FREE(asn_DEF_ScopedLocalCertificateChainFiles, pstScopedLocalCertificateChainFiles);
        }
        counter++;
    }
    
    ECHO(INFO, "===== test result(total=%d, counter=%d) =====", total, counter);
    
    return 0;
}