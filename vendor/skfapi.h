#ifndef UCISDK_VENDOR_SKFAPI_H
#define UCISDK_VENDOR_SKFAPI_H

#ifdef __cplusplus
extern "C" {
#endif

typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef UINT8 BYTE;
typedef char CHAR;
typedef UINT16 WORD;
typedef unsigned long DWORD;
typedef unsigned int ULONG;
typedef char *LPSTR;
typedef void *HANDLE;
typedef int BOOL;
typedef HANDLE DEVHANDLE;
typedef HANDLE HAPPLICATION;
typedef HANDLE HCONTAINER;

#define SAR_OK 0x00000000U
#define USER_TYPE 0x00000001U
#define ADMIN_TYPE 0x00000000U

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define SGD_SM3 0x00000001U
#define SGD_SHA256 0x00000004U
#define SGD_SM2_1 0x00020100U
#define SGD_SM2_3 0x00020400U
#define SGD_RSA 0x00010000U
#define SGD_RSA_SIGN 0x00010100U
#define SGD_RSA_ENC 0x00010200U
#define SGD_SM4_ECB 0x00000401U
#define SGD_SM4_CBC 0x00000402U
#define SGD_SMS4_ECB 0x00002001U
#define SGD_SMS4_CBC 0x00002002U

#define MAX_IV_LEN 32
#define MAX_RSA_MODULUS_LEN 256
#define MAX_RSA_EXPONENT_LEN 4
#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN 512
#define ECC_MAX_MODULUS_BITS_LEN 512
#define ECC_MAX_CIPHER_LEN 256

typedef struct Struct_Version {
    BYTE major;
    BYTE minor;
} VERSION;

typedef struct Struct_DEVINFO {
    VERSION Version;
    CHAR Manufacturer[64];
    CHAR Issuer[64];
    CHAR Label[32];
    CHAR SerialNumber[32];
    VERSION HWVersion;
    VERSION FirmwareVersion;
    ULONG AlgSymCap;
    ULONG AlgAsymCap;
    ULONG AlgHashCap;
    ULONG DevAuthAlgId;
    ULONG TotalSpace;
    ULONG FreeSpace;
    ULONG MaxECCBufferSize;
    ULONG MaxBufferSize;
    BYTE Reserved[64];
} DEVINFO, *PDEVINFO;

typedef struct Struct_RSAPUBLICKEYBLOB {
    ULONG AlgID;
    ULONG BitLen;
    BYTE Modulus[MAX_RSA_MODULUS_LEN];
    BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

typedef struct Struct_RSAPRIVATEKEYBLOB {
    ULONG AlgID;
    ULONG BitLen;
    BYTE Modulus[MAX_RSA_MODULUS_LEN];
    BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
    BYTE PrivateExponent[MAX_RSA_MODULUS_LEN];
    BYTE Prime1[MAX_RSA_MODULUS_LEN / 2];
    BYTE Prime2[MAX_RSA_MODULUS_LEN / 2];
    BYTE Prime1Exponent[MAX_RSA_MODULUS_LEN / 2];
    BYTE Prime2Exponent[MAX_RSA_MODULUS_LEN / 2];
    BYTE Coefficient[MAX_RSA_MODULUS_LEN / 2];
} RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

typedef struct Struct_ECCPUBLICKEYBLOB {
    ULONG BitLen;
    BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct Struct_ECCPRIVATEKEYBLOB {
    ULONG BitLen;
    BYTE PrivateKey[ECC_MAX_MODULUS_BITS_LEN / 8];
} ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

typedef struct Struct_ECCSIGNATUREBLOB {
    BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE s[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

typedef struct Struct_ECCCIPHERBLOB {
    BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
    BYTE HASH[32];
    ULONG CipherLen;
    BYTE Cipher[ECC_MAX_CIPHER_LEN];
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

typedef struct Struct_BLOCKCIPHERPARAM {
    BYTE IV[MAX_IV_LEN];
    ULONG IVLen;
    ULONG PaddingType;
    ULONG FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

typedef struct Struct_FILEATTRIBUTE {
    CHAR FileName[32];
    ULONG FileSize;
    ULONG ReadRights;
    ULONG WriteRights;
} FILEATTRIBUTE, *PFILEATTRIBUTE;

#define KYBER_PUB_MAX 2048U
#define KYBER_PRI_MAX 4096U
#define DILITHIUM_PUB_MAX 3072U
#define DILITHIUM_PRI_MAX 5120U

typedef struct KyberPublicKey_st { ULONG pk_len; BYTE pk[KYBER_PUB_MAX]; } KyberPublicKey;
typedef struct KyberPrivateKey_st { ULONG sk_len; BYTE sk[KYBER_PRI_MAX]; } KyberPrivateKey;
typedef struct DilithiumPublicKey_st { ULONG pk_len; BYTE pk[DILITHIUM_PUB_MAX]; } DilithiumPublicKey;
typedef struct DilithiumPrivateKey_st { ULONG sk_len; BYTE sk[DILITHIUM_PRI_MAX]; } DilithiumPrivateKey;

#ifdef __cplusplus
}
#endif

#endif
