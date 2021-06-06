#ifndef __AVLSDK_INTERFACE_H__
#define __AVLSDK_INTERFACE_H__

#ifdef __cplusplus
extern "C"{
#endif

// Macros about continue or abort
#define OD_CONTINUE                         (1)
#define OD_ABORT                            (2)

#define CUR_ENGINE_VER                      (0x01000001)
#define CUR_ENGINE_VER_STR                  ("1.0.0.1")

// Data type

// Data environment type
#define ET_NETWORK                          (1)
#define ET_DESKTOP                          (2)

// Sub module names
#define SMN_FILE_FMT                        ("AIFilFmt")
#define SMN_SHELL_RECOGNIZE                 ("AIPack")
#define SMN_SFX_DETECT                      ("AISfxArc")
#define SMN_INFECTED                        ("ASVirus")
#define SMN_BOL_DETECT                      ("ASBOL")
#define SMN_COMMON_DETECT                   ("ASCommon")
#define SMN_MALWS_DETECT                    ("ASMalwS")
#define SMN_MALWE_DETECT                    ("ASMalwE")
#define SMN_MALWFH_DETECT                   ("ASMalwFH")
#define SMN_MALWHS_DETECT                   ("ASMalwHS")
#define SMN_KEXPLOIT_DETECT                 ("ASKExplt")
#define SMN_EXPLOIT_DETECT                  ("ASExplot")
#define SMN_SCRIPT_DETECT                   ("ASScript")
#define SMN_MALWB_DETECT                    ("ASMalwB")
#define SMN_VCS2_STATIC                     ("ASVCS2S")
#define SMN_SPLIT_SCRIPT                    ("APSScrpt")
#define SMN_UNIT_EOP                        ("APUnitEP")
#define SMN_SPLIT_PE                        ("APSPE")
#define SMN_ARCHIVE                         ("APUnArc")
#define SMN_UNPACK_STATIC                   ("APUnPack")
#define SMN_SPLIT_EML                       ("APSMail")
#define SMN_SUF                             ("AWSuf")
#define SMN_SUF_DETECT                      ("ASSuf")
#define SMN_CLOUD_DETECT                    ("ASCloud")
#define SMN_MSCRIPT_DETECT                  ("ASMScrip")
#define SMN_ELF_DETECT                      ("ASELF")
#define SMN_YARA_DETECT                     ("ASYR")
#define SMN_MACRO_DETECT                    ("ASMacro")
#define SMN_ANDROID_DETECT                  ("ASDroid")
#define SMN_GEN_HASH_DETECT                 ("ASMalwGH")
#define SMN_VCS3_STATIC                     ("ASVCS3S")
#define SMN_MALWNS_DETECT                   ("ASMalwNS")
#define SMN_SWF_DETECT                      ("ASSwf")
#define SMN_SPLIT_SWF                       ("APUnSwf")
#define SMN_MALWHM_DETECT                   ("ASMalwHM")
#define SMN_REG_DETECT                      ("ASMalwRG")
#define SMN_MALWSC_DETECT                   ("ASMalwSC")
#define SMN_HEML_DETECT                     ("ASEMLH")
#define SMN_HSCPT_DETECT                    ("ASScptH")
#define SMN_ELF_SFX_DETECT                  ("AIESfxAc")
#define SMN_DOH_DETECT                      ("ASDOH")
#define SMN_DCERT_COLLECT                   ("AIDCert")
#define SMN_TEXT_INFECTED                   ("ASTVirus")
#define SMN_UNIT_TEXT                       ("APUnitT")

typedef void    *(*P_AVL_MALLOC)(unsigned long size);
typedef void    (*P_AVL_FREE)(void *p_handle);
typedef void    *(*P_AVL_EXEC_MALLOC)(int size);
typedef void    (*P_AVL_EXEC_FREE)(void *buf, int size);

typedef void    *(*P_AVL_FOPEN)(const char *path, const char *mode);
typedef long    (*P_AVL_FREAD)(void *buf, long size, long count, void *handle);
typedef long    (*P_AVL_FWRITE)(void *buf, long size, long count, void *handle);
typedef long    (*P_AVL_FTELL)(void *handle);
typedef int     (*P_AVL_FFLUSH)(void *handle);
typedef int     (*P_AVL_FCLOSE)(void *handle);
typedef int     (*P_AVL_FSEEK)(void *handle, long offset, int whence);

typedef struct _sys_fn_set
{
    P_AVL_MALLOC      sys_malloc;
    P_AVL_FREE        sys_free;
    P_AVL_EXEC_MALLOC sys_exec_malloc;
    P_AVL_EXEC_FREE   sys_exec_free;
    P_AVL_FOPEN       sys_fopen;
    P_AVL_FREAD       sys_fread;
    P_AVL_FWRITE      sys_fwrite;
    P_AVL_FTELL       sys_ftell;
    P_AVL_FFLUSH      sys_fflush;
    P_AVL_FCLOSE      sys_fclose;
    P_AVL_FSEEK       sys_fseek;
} SYS_FN_SET, *P_SYS_FN_SET;

typedef struct
{
    unsigned long   obj_ver;       // version of this structure
    unsigned long   obj_type;      // data type
    unsigned long   evro_type;     // environment type
    unsigned char   *buf;          // pointer of data buffer
    unsigned long   size;          // size of valid data
    unsigned char   obj_des[4096]; // data description
} OBJ_PROVIDER, *P_OBJ_PROVIDER;

/*************************************************************************************************\
 * Function : Engine will call this callback function when it finishes scanning a object
 * Param    : p_op              the object provider pointer
 *          : p_rpt_handle      the handle of result report
 *            p_param           transfered to engine by OBJ_DISPOSER::p_rpt_param
 *
 * Return   : Undefined
 * Note     : This callback function will be called only if engine reports the scanning result
\*************************************************************************************************/
typedef long    (*P_OBJ_DISPOSER_CALLBACK)(P_OBJ_PROVIDER p_op, void *p_rpt_handle, void *p_param);

/*************************************************************************************************\
 * Function : Engine will call this callback function when it needs to know continue or not
 * Param    : p_param           transfered to engine by OBJ_DISPOSER::p_rpt_param
 *
 * Return   : OD_CONTINUE or OD_ABORT
\*************************************************************************************************/
typedef long    (*P_QUERY_CONTINUE_CALLBACK)(void *p_param);

typedef struct
{
    P_OBJ_DISPOSER_CALLBACK   rpt_callback;
    void                      *p_rpt_param;
    P_QUERY_CONTINUE_CALLBACK query_continue_callback;
    void                      *p_qc_param;
} OBJ_DISPOSER, *P_OBJ_DISPOSER;

typedef struct
{
    unsigned long   total_db_item_count;
    char            db_time_stamp[32];
} DB_INFO, *P_DB_INFO;

/*************************************************************************************************\
 * Function : Create a new instance of engine
 * Param    : ppEngine          the engine handle returned
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_CreateInstance(void **ppEngine);

/*************************************************************************************************\
 * Function : Release handle of engine instance
 * Param    : pEngine           the engine handle
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_Release(void *pEngine);

/*************************************************************************************************\
 * Function : Set the functions of system(malloc etc.)
 * Param    : sys_fn            the pointer of SYS_FN_SET
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_SetSysFn(P_SYS_FN_SET sys_fn);

/*************************************************************************************************\
 * Function : Load a template file of configuration
 * Param    : pEngine           the engine handle
 *            szFilename        the full path of configuration file
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_LoadConfigFile(void *pEngine, char *szFilename);

/*************************************************************************************************\
 * Function : Set an int value to engine
 * Param    : pEngine           the engine handle
 *            pCfgIdx           index of configuration
 *            lValue            the value to be set
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_SetConfigInt(void *pEngine, long CfgIdx, long lValue);

/*************************************************************************************************\
 * Function : Set an string value to engine
 * Param    : pEngine           the engine handle
 *            pCfgIdx           index of configuration
 *            pValue            the value to be set
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_SetConfigString(void *pEngine, long CfgIdx, const char *pValue);

/*************************************************************************************************\
 * Function : Get an int value from engine
 * Param    : pEngine           the engine handle
 *            pCfgIdx           index of configuration
 *            pValue            the buffer to store the value
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_GetConfigInt(void *pEngine, long CfgIdx, long *pValue);

/*************************************************************************************************\
 * Function : Get an string value from engine
 * Param    : pEngine           the engine handle
 *            pCfgIdx           index of configuration
 *            Buf               the buffer to store the value
 *            BufLen            the length of the buffer
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_GetConfigString(void *pEngine, long CfgIdx, char *Buf, long BufLen);

/*************************************************************************************************\
 * Function : Initialize the engine handle based on the configuration
 * Param    : pEngine           the engine handle
 *            pVerificationCode verification code
 *
 * Return   : Error code
 * Note     : If initialization failes, engine will release this instance automatically
\*************************************************************************************************/
long    AVL_SDK_InitInstance(void *pEngine, const void* pVerificationCode);

/*************************************************************************************************\
 * Function : Scan data
 * Param    : pEngine           the engine handle
 *            pObj              the pointer of OBJ_PROVIDER structure
 *            pObjDisposer      the pointer of OBJ_DISPOSER structure
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_Scan(void *pEngine, P_OBJ_PROVIDER pObj, P_OBJ_DISPOSER pObjDisposer);

/*************************************************************************************************\
 * Function : Query the result report
 * Param    : pEngine           the engine handle
 *            pRptHandle        the handle of report
 *            key               the index of report
 *            value             the buffer to get report
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_QueryReportInt(void *pEngine, void *pRptHandle, unsigned long key, long *value);

/*************************************************************************************************\
 * Function : Query the result report
 * Param    : pEngine           the engine handle
 *            pRptHandle        the handle of report
 *            key               the index of report
 *            value             the pointer to string report
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_QueryReportStr(void *pEngine, void *pRptHandle, unsigned long key, unsigned char **value);

/*************************************************************************************************\
 * Function : Query the library info
 * Param    : pEngine           the engine handle
 *            pDBInfo           the pointer of DB_INFO structure
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_QueryDBInfo(void *pEngine, P_DB_INFO pDBInfo);

/*************************************************************************************************\
 * Function : Reload the library
 * Param    : pEngine           the engine handle
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_ReloadDB(void *pEngine);

/*************************************************************************************************\
 * Function : Get engine version
 * Param    : buf               the buffer to store the version string
 *            len               the buffer length
 *
 * Return   : Error code
\*************************************************************************************************/
long    AVL_SDK_GetCurVersion(unsigned char *buf, unsigned long len);

/*************************************************************************************************\
 * Function : Get license expiration date
 * Param    : pEngine           the engine handle
 *          : buf               the buffer to store the date string
 *            len               the buffer length
 *
 * Return   : Error code
\*************************************************************************************************/
long	AVL_SDK_GetLicenseExpDate(void *pEngine, unsigned char *buf, unsigned long len);
#ifdef __cplusplus
}
#endif

#endif // __AVLSDK_INTERFACE_H__


