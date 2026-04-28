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
#define SGD_SM4_ECB 0x00000401U
#define SGD_SM4_CBC 0x00000402U

#define MAX_IV_LEN 32
#define MAX_RSA_MODULUS_LEN 256
#define MAX_RSA_EXPONENT_LEN 4
#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN 512

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

typedef struct Struct_ECCPUBLICKEYBLOB {
    ULONG BitLen;
    BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct Struct_ECCSIGNATUREBLOB {
    BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE s[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

typedef struct Struct_BLOCKCIPHERPARAM {
    BYTE IV[MAX_IV_LEN];
    ULONG IVLen;
    ULONG PaddingType;
    ULONG FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

typedef ULONG (*SKF_EnumDev_Fn)(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
typedef ULONG (*SKF_ConnectDev_Fn)(LPSTR szName, DEVHANDLE *phDev);
typedef ULONG (*SKF_DisConnectDev_Fn)(DEVHANDLE hDev);
typedef ULONG (*SKF_GetDevInfo_Fn)(DEVHANDLE hDev, DEVINFO *pDevInfo);
typedef ULONG (*SKF_GenRandom_Fn)(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen);
typedef ULONG (*SKF_DigestInit_Fn)(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey, BYTE *pucID, ULONG ulIDLen, HANDLE *phHash);
typedef ULONG (*SKF_Digest_Fn)(HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
typedef ULONG (*SKF_CloseHandle_Fn)(HANDLE hHandle);

#ifdef __cplusplus
}
#endif

#endif
