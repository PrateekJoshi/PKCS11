/*
 * main.c
 *
 *  Created on: Jul 19, 2018
 *      Author: prateek
 */

#include <stdio.h>
#include <stdlib.h>
#include "pkcs11.h"
#include <dlfcn.h>

/* Global variables */
char cryptoki_lib_dest[4096] = {0};
CK_VOID_PTR lib_handle = NULL_PTR;
CK_FUNCTION_LIST_PTR p11_functions = NULL_PTR;



void logger(int err, char *msg, int line, const char* file, const char *func)
{
	printf("\n%d : %s : %s : %s : %d \n",err,msg,func,file,line);
}

/*
 * Function : get_library()
 * Description : Get the cryptoki vendor library from path specified by env variable
 * CRYPTOKI_LIB_PATH and CRYPTOKI_LIB_NAME
 */
CK_RV get_library()
{
	CK_RV err = CKR_OK;
	char *lib_path = NULL;
	char *lib_name = NULL;

	lib_path = getenv("CRYPTOKI_LIB_PATH");
	if( lib_path == NULL )
	{
		printf("Failed to get CRYPTOKI_LIB_PATH");
		err = CKR_GENERAL_ERROR;
		goto exit;
	}

	lib_name = getenv("CRYPTOKI_LIB_NAME");
	if (lib_name == NULL)
	{
		err = CKR_GENERAL_ERROR;
		logger(err,"Failed to get CRYPTOKI_LIB_NAME",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	snprintf(cryptoki_lib_dest,sizeof(cryptoki_lib_dest)-1,"%s/%s",lib_path,lib_name);

	printf("\n Cryptoki will load the library: %s \n",cryptoki_lib_dest);

	exit:
		return err;
}


/*
 * Function : load_pkcs11_functions()
 * Description : Load the PKCS 11 functions from the library got from get_library()
 */
CK_RV load_pkcs11_functions()
{
	CK_RV err = CKR_OK;
	CK_C_GetFunctionList function_symbol_list = NULL;

	/* Get the PKCS 11 library name */
	err = get_library();
	if ( err != CKR_OK )
	{
		logger(err,"get_library() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	/* Get handle to the library */
	lib_handle = dlopen(cryptoki_lib_dest,RTLD_NOW);
	if ( lib_handle == NULL )
	{
		err = CKR_GENERAL_ERROR;
		logger(err,"dlopen() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	/* Obtain address of a symbols in a shared library */
	function_symbol_list = (CK_C_GetFunctionList) dlsym(lib_handle,"C_GetFunctionList");

	/* Get pkcs11 function list pointer */
	if(function_symbol_list)
	{
		err = function_symbol_list(&p11_functions);
		if ( err != CKR_OK )
		{
			logger(err,"function_symbol_list() failed",__LINE__,__FILE__,__FUNCTION__);
			goto exit;
		}
	}

	/* Initialize PKCS 11 function library */
	if(p11_functions)
	{
		err = p11_functions->C_Initialize(NULL_PTR);
		if( err != CKR_OK )
		{
			logger(err,"C_Initialize() failed",__LINE__,__FILE__,__FUNCTION__);
			goto exit;
		}
	}

	exit:
		return err;
}



int main()
{
	load_pkcs11_functions();
	return 0;
}
