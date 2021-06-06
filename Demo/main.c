#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../interface/engine.h"
#include "../interface/error_code.h"
#include "../interface/AVLSDK_rpt_idx.h"
#include "../interface/AVLSDK_conf_idx.h"
#include "./getopt/getopt.h"
#include "./Load_lib.h"
#include "./UsedFuns.h"

#define	DEFAULT_SDK_PATH		("./AVLSDK.so")
#define DEFAULT_MODULE_PATH     ("./Module")
#define DEFAULT_LICENSE_PATH    ("./License/License.alf")



typedef long	(*P_AVL_SDK_CreateInstance)(void**pEngine);
typedef long	(*P_AVL_SDK_Release)(void *pEngine);
typedef long	(*P_AVL_SDK_LoadConfigFile)(void *pEngine, char *szFilename);
typedef	long	(*P_AVL_SDK_SetConfigString)(void *pEngine, long CfgIdx, const char *pValue);
typedef	long	(*P_AVL_SDK_SetConfigInt)(void *pEngine, long CfgIdx, long lValue);
typedef	long	(*P_AVL_SDK_GetConfigInt)(void *pEngine, long CfgIdx, long *pValue);
typedef	long	(*P_AVL_SDK_GetConfigString)(void *pEngine, long CfgIdx, char *Buf, long BufLen);
typedef long	(*P_AVL_SDK_InitInstance)(void *pEngine, const void* pVerificationCode);
typedef long	(*P_AVL_SDK_Scan)(void *pEngine, P_OBJ_PROVIDER pObj, P_OBJ_DISPOSER pObjDisposer);
typedef long	(*P_AVL_SDK_QueryReportInt)(void *pEngine, void *pRptHandle, unsigned long key, long *value);
typedef long	(*P_AVL_SDK_QueryReportStr)(void *pEngine, void *pRptHandle, unsigned long key, unsigned char **value);
typedef long	(*P_AVL_SDK_GetCurVersion)(unsigned char* buf, unsigned long len);
typedef long	(*P_AVL_SDK_GetLicenseExpDate)(void* pEngine, unsigned char* buf, unsigned long len);



typedef struct	_engine_param
{
	void							*p_engine;
	P_AVL_SDK_QueryReportInt		p_query_rpt_int;
	P_AVL_SDK_QueryReportStr		p_query_rpt_str;
	P_AVL_SDK_Scan					p_scan;
	long                            process_object_num; //扫描对象数
	long                            detect_object_num;//检出对象数(原始文件+拆分出的子文件)
} ENGINE_PARAM, *P_ENGINE_PARAM;



long func_long_query_continue_callback(void *p_param)
{

	// This is the code sample, so it returns unconditionally. Users can modify according to the condition.
	return	OD_CONTINUE;
}

long func_long_get_rslt_callback(P_OBJ_PROVIDER p_op, void *p_rpt_handle, void *p_param)
{
	long			long_ret = 0, long_malware_id = 0, long_qry_ret = 0;
	P_ENGINE_PARAM	p_ep = (P_ENGINE_PARAM)p_param;
	unsigned char	*puchar_desc = NULL, *puchar_analyser = NULL, *puchar_malware_name = NULL;

	if (p_rpt_handle == NULL || p_param == NULL)
	{
		long_ret = -1;
		goto	finish;
	}

	p_ep->process_object_num++;

    // Query current description about the object
    long_qry_ret = p_ep->p_query_rpt_str(p_ep->p_engine, p_rpt_handle, RPT_IDX_OBJ_DESCRIPTION, &puchar_desc);
    if (long_qry_ret != ERR_SUCCESS)
    {
        printf("Query Description failed...\n");
        goto	finish;
    }

	// Query the Malware ID
	long_qry_ret = p_ep->p_query_rpt_int(p_ep->p_engine, p_rpt_handle, RPT_IDX_MALWARE_ID, &long_malware_id);
    if (long_qry_ret < 0)
	{
		printf("Query Malware_ID failed...\n");
		goto	finish;
	}

	if (long_qry_ret != ERR_RPT_NOT_EXIST)
	{
        // Query the analyser who detected this malware, users will use it when they need to get the malware name
        long_qry_ret = p_ep->p_query_rpt_str(p_ep->p_engine, p_rpt_handle, RPT_IDX_ANALYSER, &puchar_analyser);
        if (long_qry_ret != ERR_SUCCESS)
        {
            printf("Query Analyser failed...\n");
            goto	finish;
        }

        // Query the VName
		if (p_ep->p_query_rpt_str(p_ep->p_engine, p_rpt_handle, RPT_IDX_CLOUD_MALWARENAME_ID, &puchar_malware_name) < 0)
		{
			printf("Query MalwareName failed...\n");
			goto	finish;
		}

        p_ep->detect_object_num++;
        printf("Found malware: %x\t\t%s\t\t%s\t\t%s\n", (unsigned int)long_malware_id, (char *)puchar_malware_name, (char *)puchar_analyser, (char *)puchar_desc);
	}
	else
    {
        printf("Not Found \t%s\n", puchar_desc);
    }

finish:
	return	long_ret;
}

static const struct option options[] =
{
	{"file",	   required_argument,	NULL,	'f'},
	{"conf",	   required_argument,	NULL,	'c'},
	{"help",	   no_argument,		    NULL,	'h'},
	{NULL,		   0,					NULL,	 0 }
};

void func_void_show_usage(void)
{
	printf("\t\t--file      -f : scan the path of file.\n");
	printf("\t\t--conf      -c : config file.\n");
	printf("\t\t--help      -h : show this message.\n");
}

long func_long_scan_file(const char *pch_file_path, void *p_param)
{
    long long_ret       = 0;
    char *pch_buf       = NULL;
    long long_buf_size  = 0;

    OBJ_PROVIDER	op = {0};
    OBJ_DISPOSER	od = {0};
    P_ENGINE_PARAM	ep_handle = (P_ENGINE_PARAM)p_param;

    if( pch_file_path == NULL || ep_handle == NULL )
    {
        long_ret = -1;
        goto finish;
    }

    //get file buf and size
    if(func_long_get_file_buf_and_size(pch_file_path, &pch_buf, (unsigned long *)&long_buf_size) != 0)
    {
        long_ret =  -2;
        goto finish;
    }

    // Initialize the OBJ_PROVIDER structure
   // op.obj_ver = CUR_ENGINE_VER;
    op.buf = (unsigned char	*)pch_buf;
    op.size = long_buf_size;
    strncpy((char *)op.obj_des, pch_file_path, sizeof(op.obj_des)-1);

    // Initialize the OBJ_DISPOSERR structure
    od.rpt_callback = func_long_get_rslt_callback;
    od.p_rpt_param = ep_handle;
    od.query_continue_callback = func_long_query_continue_callback;
    od.p_qc_param = NULL;
    if(ep_handle->p_scan(ep_handle->p_engine, &op, &od) < 0)
    {
        printf("Scan failed...\n");
    }

finish:
    if( pch_buf != NULL )
    {
        free(pch_buf);
        pch_buf = NULL;
    }
    return long_ret;
}

int main(int argc, char **argv)
{
    long long_ret = 0;
	void							*p_sdk_handle = NULL, *p_name_handle = NULL;
	void							*p_engine_handle = NULL;
	P_AVL_SDK_CreateInstance        p_create        = NULL;
	P_AVL_SDK_Release				p_release       = NULL;
    P_AVL_SDK_LoadConfigFile		p_load_config   = NULL;
	P_AVL_SDK_SetConfigInt			p_set_cfg_int   = NULL;
	P_AVL_SDK_SetConfigString		p_set_cfg_str   = NULL;
    P_AVL_SDK_GetConfigInt			p_get_cfg_int   = NULL;
	P_AVL_SDK_GetConfigString		p_get_cfg_str   = NULL;
	P_AVL_SDK_InitInstance          p_init          = NULL;
	P_AVL_SDK_Scan					p_scan          = NULL;
	P_AVL_SDK_QueryReportInt		p_query_rpt_int = NULL;
	P_AVL_SDK_QueryReportStr		p_query_rpt_str = NULL;
	P_AVL_SDK_GetCurVersion         p_get_version = NULL;
	P_AVL_SDK_GetLicenseExpDate     p_get_license_expdate = NULL;
	ENGINE_PARAM    ep = {0};
    char  *pchar_scan_file = NULL, *pchar_config_file = NULL;
    int  int_c;


	
    while ((int_c = getopt_long(argc, argv, "f:c:h", options, NULL)) != -1)
	{
		switch (int_c)
		{
		case 'f':
			pchar_scan_file = optarg;
			break;
		case 'c':
			pchar_config_file = optarg;
			break;
		case 'h':
			func_void_show_usage();
			return 0;
		}
	}

	if (pchar_config_file == NULL)
	{
		goto finish;
	}

	// Load the SDK so
	if( func_long_loadLibrary(DEFAULT_SDK_PATH, &p_sdk_handle) != 0 )
	{
		printf("Load SDK failed...\n");
		goto	finish;
	}

	// Get APIs
	func_long_getProcAddress(p_sdk_handle, "AVL_SDK_CreateInstance",		  (void**)&p_create);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_LoadConfigFile",          (void**)&p_load_config);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_SetConfigInt",            (void**)&p_set_cfg_int);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_SetConfigString",         (void**)&p_set_cfg_str);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_GetConfigInt",            (void**)&p_get_cfg_int);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_GetConfigString",         (void**)&p_get_cfg_str);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_InitInstance",            (void**)&p_init);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_Scan",                    (void**)&p_scan);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_QueryReportInt",          (void**)&p_query_rpt_int);
    func_long_getProcAddress(p_sdk_handle, "AVL_SDK_QueryReportStr",          (void**)&p_query_rpt_str);
	func_long_getProcAddress(p_sdk_handle, "AVL_SDK_Release",				  (void**)&p_release);
	func_long_getProcAddress(p_sdk_handle, "AVL_SDK_GetCurVersion",				(void**)&p_get_version);
	func_long_getProcAddress(p_sdk_handle, "AVL_SDK_GetLicenseExpDate", (void**)&p_get_license_expdate);
	if (p_create==NULL || p_release==NULL || p_load_config==NULL || p_set_cfg_int==NULL || p_set_cfg_str==NULL || p_get_cfg_int==NULL || p_get_cfg_str==NULL || p_init==NULL || p_scan==NULL || p_query_rpt_int == NULL || p_query_rpt_str == NULL || p_get_version == NULL || p_get_license_expdate == NULL)
	{
		printf("Get procs failed from AVLSDK.so\n");
		goto	finish;
	}

	// Create a new instance of AVLSDK
	long_ret = p_create(&p_engine_handle);
	if (long_ret != ERR_SUCCESS)
	{
		printf("Create failed : %d\n", (int)long_ret);
		goto finish;
	}
	// Load the configuration template
	long_ret = p_load_config(p_engine_handle, pchar_config_file);
	if (long_ret != ERR_SUCCESS)
	{
		printf("LoadConfig failed : %d\n", (int)long_ret);
		goto	finish;
	}
	/*
	//设置最大解压层数
	long_ret = p_set_cfg_int(p_engine_handle, CFG_INT_APACK_RECURE_LAYER, 5);
	if (long_ret != ERR_SUCCESS)
	{
		printf("Set unapck recure layer failed : %d\n", (int)long_ret);
		goto	finish;
	}
	*/
	//设置license路径
	long_ret = p_set_cfg_str(p_engine_handle, CFG_STR_LICENSE_PATH, DEFAULT_LICENSE_PATH);
	if (long_ret != ERR_SUCCESS)
	{
		printf("Set sdk3.0 license path failed : %d\n", (int)long_ret);
		goto	finish;
	}

	//设置模块路径
	long_ret = p_set_cfg_str(p_engine_handle, CFG_STR_MODULE_PATH, DEFAULT_MODULE_PATH);
	if (long_ret != ERR_SUCCESS)
	{
		printf("Set Module path failed : %d\n", (int)long_ret);
		goto	finish;
	}

	//Initialize the instance
	long_ret = p_init(p_engine_handle, NULL);
	if (long_ret != ERR_SUCCESS)
	{
		printf("Init failed : %d\n", (int)long_ret);
		p_engine_handle = NULL;
		goto	finish;
	}

    ep.p_engine         = p_engine_handle;   
    ep.p_query_rpt_int  = p_query_rpt_int;
    ep.p_query_rpt_str  = p_query_rpt_str;
    ep.p_scan           = p_scan;


	//query engine version
	char version[64] = { 0 };
	long_ret = p_get_version((unsigned char*)version, sizeof(version));
	if (long_ret != 0)
	{
		printf("get version failed : %d\n", (int)long_ret);
		goto	finish;
	}
	printf("Engine version : %s\n", version);
    //scan

	if(pchar_scan_file != NULL)
	{
		func_long_scan_file(pchar_scan_file, &ep);
	}


	unsigned char lic_date[64] = { 0 };
	long_ret = p_get_license_expdate(p_engine_handle, lic_date, sizeof(lic_date));

	if (long_ret != 0)
	{
		printf("get license date failed : %d\n", (int)long_ret);
		goto	finish;
	}

    printf("==========================================================\n");
    printf("Total Processed objects:  %ld\n", ep.process_object_num);
    printf("Total detected objects:  %ld\n", ep.detect_object_num);
	printf("License Time:  %s\n", lic_date);
    printf("==========================================================\n");
finish:
	if (p_engine_handle != NULL)
	{
		p_release(p_engine_handle);
		p_engine_handle = NULL;
	}
    if (p_sdk_handle != NULL)
	{
		func_void_freeLibrary(p_sdk_handle);
	}
	if (p_name_handle != NULL)
	{
		func_void_freeLibrary(p_name_handle);
	}

    return 0;
}
