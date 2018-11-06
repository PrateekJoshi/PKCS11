/*
 * main.c
 *
 *  Created on: Jul 19, 2018
 *      Author: prateek
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include "pkcs11.h"
#include <dlfcn.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "main.h"

/* Macros */
#define MAX_SESSION_COUNT  10
#define MAX_PWD_LEN  200
#define MAX_LABEL_LEN  200
#define APP_NAME "eTokenUtility"
#define APP_ERR -1


/* Global variables */
char cryptoki_lib_dest[4096] = {0};
CK_VOID_PTR lib_handle = NULL_PTR;
CK_FUNCTION_LIST_PTR p11_functions = NULL_PTR;
unsigned int session_count = 0;


// session list typedef
typedef struct
{
   CK_SESSION_HANDLE session_handle;
   CK_SLOT_ID        slot_id;
}session_list;

session_list session_arr[MAX_SESSION_COUNT];



void logger(int err, char *msg, int line, const char* file, const char *func)
{
	printf("\n0x%x : %s : %s : %s : %d \n",err,msg,func,file,line);
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

/*
 * Function : get_count_available_slots(CK_ULONG *slot_count)
 * Description : Get the number of available slot in slot_count
 */
CK_RV get_count_available_slots(CK_ULONG *slot_count)
{
	CK_RV err = CKR_OK;
	CK_BBOOL token_present = TRUE;

	/* Get number of available slots in slot_count */
	err = p11_functions->C_GetSlotList(token_present,NULL,slot_count);
	if( err != CKR_OK )
	{
		logger(err,"C_GetSlotList() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	exit:
		return err;
}

/*
 * Function : get_slot_list(CK_ULONG *max_slot_count,CK_SLOT_ID **slot_list)
 * Description : Allocate slot ids to slot_list buffer and max_slot_count to maximum expected slot id
 */
CK_RV get_slot_list(CK_ULONG *max_slot_count,CK_SLOT_ID **slot_list)
{
	CK_RV err = CKR_OK;
	CK_BBOOL token_present = TRUE;

	/*  Allocate slot ids to slot_list buffer and max no of slots */
	err = p11_functions->C_GetSlotList(token_present,*slot_list,max_slot_count);
	if( err != CKR_OK )
	{
		logger(err,"C_GetSlotList() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	exit:
		return err;
}

/*
 * Function : get_token_info(CK_SLOT_ID slot_id, CK_TOKEN_INFO **token_info)
 * Description : Get information of token in token_info in slot slot_id
 */
CK_RV get_token_info(CK_SLOT_ID slot_id, CK_TOKEN_INFO *token_info)
{
	CK_RV err = CKR_OK;

	/* Get info of token available at slot_id */
	err = p11_functions->C_GetTokenInfo(slot_id,token_info);
	if( err != CKR_OK)
	{
		logger(err,"C_GetTokenInfo() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	exit:
		return err;
}

/*
 * Function : initialize_token(CK_SLOT_ID slot_id_to_init)
 * Description : Init a token at given slot
 */
CK_RV initialize_token(CK_SLOT_ID slot_id_to_init)
{
	CK_RV err = CKR_OK;
	CK_SESSION_HANDLE session_handle;
	CK_BYTE so_password[MAX_PWD_LEN]={0};
	CK_BYTE token_label[MAX_LABEL_LEN]={0};
	unsigned int so_password_len = 0;

	printf("Enter new token label: ");
	scanf("%s",token_label);
	printf("Enter new SO password: ");

	getchar();
	read_pin(so_password,&so_password_len);

	err = p11_functions->C_InitToken(slot_id_to_init,so_password,so_password_len,token_label);
	if( err != CKR_OK )
	{
		/* If session exits on token */
		if( err == CKR_SESSION_EXISTS )
		{
			err = CKR_OK;
			printf("\nERROR: Sessions are opened on token, first close them and then init !!!\n");
			goto exit;
		}

		/* If PIN not in range */
		if( err == CKR_PIN_LEN_RANGE )
		{
			err = CKR_OK;
			printf("\nERROR: PIN length not in range !!!\n");
			goto exit;
		}

		logger(err,"C_InitToken() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	printf("\nToken initialized successfully \n");
	exit:
		return err;
}


/*
 * Function : open_session(CK_SLOT_ID slot_id)
 * Description : Open a session on given slot and store in session_arr
 */
CK_RV open_session(CK_SLOT_ID slot_id)
{
	CK_RV err = CKR_OK;
	CK_SESSION_HANDLE session_handle = CKR_SESSION_HANDLE_INVALID;
	CK_FLAGS session_flags;
	int option = 0;

	/* Verify that there is still memory available for another session */
	if( session_count > MAX_SESSION_COUNT )
	{
		printf("\n Maximum number of opened session already reached !!!\n ");
		goto exit;
	}

	/* Set session flags */
	printf("\nSecurity Officer [0] or Normal User [1]: ");
	scanf("%d",&option);

	if(option)
	{
		session_flags = session_flags | CKU_USER;
	}
	else
	{
		session_flags = session_flags | CKU_SO;
	}


	printf("\nRead only [0] or read/write session [1]: ");
	scanf("%d",&option);

	if(option)
	{
		session_flags = session_flags | CKF_RW_SESSION;
	}

	printf("\nParallel [0] or Serial session[1]: ");
	scanf("%d",&option);

	if(option)
	{
		session_flags = session_flags | CKF_SERIAL_SESSION ;
	}

	/* Open session and get handle in session_handle */
	err = p11_functions->C_OpenSession(slot_id, session_flags,(void*)APP_NAME,FALSE,&session_handle);
	if( err != CKR_OK )
	{
		/* If parallel session not supported on token */
		if( err == CKR_SESSION_PARALLEL_NOT_SUPPORTED )
		{
			err = CKR_OK;
			printf("Parallel session not supported !!!");
			goto exit;
		}

		/* Token not present on given slot */
		if( err == CKR_TOKEN_NOT_PRESENT )
		{
			err = CKR_OK;
			printf("No token present on this slot !!!");
			goto exit;
		}

		logger(err,"C_OpenSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}


	/* Session opened, store and increment the count */
	session_arr[session_count].session_handle = session_handle;				//it will be our current (last opened session)
	session_arr[session_count].slot_id = slot_id;
	session_count++;

	printf("\nSession opened succesfully \n");
	exit:
		return err;
}


/*
 * Function : close_session()
 * Description : Close all session or on a particular slot
 */
CK_RV close_session()
{
	CK_RV err = CKR_OK;
	CK_SLOT_ID slot_id = 0;
	int option = 0;

	/* Check if any session is opened on token */
	if (session_count == 0)
	{
		printf("\n No sessions are opened on token !!!\n");
		goto exit;
	}

	/* Display openend session */
	display_opened_session();

	printf("\nClose single session[0] or all session[1]: ");
	scanf("%d",&option);

	if(option)
	{
		/* Get slot id */
		printf("\nEnter the slot id of the session to close: ");
		scanf("%ld",&slot_id);

		/* Closes all sessions an application has with a token. slot_id specifies the token’s slot. */
		err = p11_functions->C_CloseAllSessions(slot_id);
		if( err )
		{
			/* If invalid slot id */
			if ( err == CKR_SLOT_ID_INVALID )
			{
				err = CKR_OK;
				printf("\nERROR: Invalid slot id entered!!!\n");
				goto exit;
			}
			logger(err,"C_CloseAllSessions() failed",__LINE__,__FILE__,__FUNCTION__);
			goto exit;
		}

		/* Remove all sessions from session array */
		for( int i = 0 ; i <= session_count; i++)
		{
			session_arr[i].session_handle = CKR_SESSION_HANDLE_INVALID;
			session_arr[i].slot_id=-1;
		}

		/* Make session count to 0 */
		session_count = 0;
	}
	else
	{
		printf("\nSelect session: ");
		scanf("%d",&option);

		err = p11_functions->C_CloseSession(session_arr[option-1].session_handle);
		if (err)
		{
			/* If invalid session handle selected */
			if( err == CKR_SESSION_HANDLE_INVALID )
			{
				err = CKR_OK;
				printf("\nInvalid session handle selected !!!\n");
				goto exit;
			}

			logger(err, "C_CloseSession() failed", __LINE__, __FILE__,__FUNCTION__);
			goto exit;
		}

		/* Clean stuff, and decrement session count */
		for( int i = option-1; i < session_count; i++)
		{
			session_arr[i].session_handle = session_arr[i+1].session_handle;
			session_arr[i].slot_id = session_arr[i+1].slot_id;
		}

		session_arr[session_count-1].session_handle = CKR_SESSION_CLOSED;
		session_arr[session_count-1].slot_id = 0;
		session_count--;
	}

	printf("Session closed successfully");
	exit:
		return err;
}

/*
 * Function : init_pin()
 * Description : Initialize a normal user pin on last session opened by SO
 */
CK_RV init_pin()
{
	CK_RV err = CKR_OK;
	CK_BYTE user_pin[MAX_PWD_LEN]={0};
	unsigned int user_pin_len = 0;
	CK_SESSION_HANDLE current_session = CKR_SESSION_HANDLE_INVALID;
	int option = 0;

	/* Check if any session is opened on token */
	if( session_count == 0)
	{
		printf("\n No sessions are opened on token !!!\n");
		goto exit;
	}

	/* Display openend session */
	display_opened_session();

	/* SO login is required to initialize a normal user */
	printf("\nSelect session on which SO is logged in : ");
	scanf("%d",&option);
	current_session = session_arr[option-1].session_handle;

	printf("\nEnter new user PIN: ");

	getchar();
	read_pin(user_pin,&user_pin_len);

	err = p11_functions->C_InitPIN(current_session,user_pin,user_pin_len);
	if( err )
	{
		/* Check if SO session is opened */
		if ( err == CKR_SESSION_HANDLE_INVALID )
		{
			err = CKR_OK;
			printf("\nNo SO session opened !!!\n");
			goto exit;
		}

		/* Check if SO is logged in */
		if ( err == CKR_USER_NOT_LOGGED_IN )
		{
			err = CKR_OK;
			printf("\nSO not logged in !!!\n");
			goto exit;
		}

		logger(err, "C_InitPIN() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	printf("\nNormal user PIN initialized \n");
	exit:
		return err;
}

/*
 * Function : change_pin()
 * Description : Modifies the PIN of the SO based on the session handle provided.
 * Known Bug: Unable to change normal user PIN
 */
CK_RV change_pin()
{
	CK_RV err = CKR_OK;
	CK_BYTE old_pin[MAX_PWD_LEN]={0};
	unsigned int old_pin_len = 0;
	CK_BYTE new_pin[MAX_PWD_LEN]={0};
	unsigned int new_pin_len = 0;
	CK_SESSION_HANDLE current_session = CKR_SESSION_HANDLE_INVALID;
	int option = 0;

	/* Check if any session is opened on token */
	if( session_count == 0)
	{
		printf("\n No sessions are opened on token !!!\n");
		goto exit;
	}

	/* Display opened session */
	display_opened_session();

	/* Select the session on which PIN is to be changed , can be of SO or user, but login is required */
	printf("\nSelect session : ");
	scanf("%d", &option);
	current_session = session_arr[option - 1].session_handle;

	getchar();
	printf("\nEnter old PIN: ");
	read_pin(old_pin, &old_pin_len);

	fflush(stdout);

	printf("\nEnter new PIN: ");
	read_pin(new_pin, &new_pin_len);

	err = p11_functions->C_SetPIN(current_session,old_pin,old_pin_len,new_pin,new_pin_len);
	if( err )
	{
		/* If PIN not in range */
		if( err == CKR_PIN_LEN_RANGE )
		{
			err = CKR_OK;
			printf("\nERROR: PIN length not in range !!!\n");
			goto exit;
		}

		/* If old PIN entered is incorrect */
		if( err == CKR_PIN_INCORRECT)
		{
			err = CKR_OK;
			printf("\nERROR: Old PIN entered is incorrect !!! \n");
			goto exit;
		}

		logger(err, "C_SetPIN() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	printf("\nPIN changed successfully\n");

	exit:
		return err;
}

/*
 * Function : login()
 * Description : Login to a SO or Normal user session
 */
CK_RV login()
{
	CK_RV err = CKR_OK;
	CK_BYTE pin[MAX_PWD_LEN]={0};
	int pin_len = 0;
	int option = 0;
	CK_USER_TYPE user_type = CKU_SO;		//default login SO
	CK_SESSION_HANDLE current_session = CKR_SESSION_HANDLE_INVALID;

	/* Check if any session is opened on token */
	if( session_count == 0)
	{
		printf("\n No sessions are opened on token !!!\n");
		goto exit;
	}

	/* Display session opened */
	display_opened_session();

	/* Get session handle to login on */
	printf("\nEnter the session into which you want to login: ");
	scanf("%d",&option);
	current_session = session_arr[option-1].session_handle;

	printf("\nSecurity Officer[0] or Normal User[1]: ");
	scanf("%d",&option);

	if( option )
	{
		user_type = CKU_USER;				//set login type to normal user
	}

	printf("\nEnter PIN: ");

	getchar();
	read_pin(pin,&pin_len);

	err = p11_functions->C_Login(current_session,(CK_USER_TYPE) user_type,pin,pin_len);
	if( err )
	{
		/* If invalid PIN */
		if( err == CKR_PIN_INCORRECT )
		{
			err = CKR_OK;
			printf("\nIncorrect PIN entered !!!\n");
			goto exit;
		}

		/* If the same user already logged in on this session */
		if( err == CKR_USER_ALREADY_LOGGED_IN )
		{
			err = CKR_OK;
			printf("\n Same user already loggen in !!!\n");
			goto exit;
		}

		/* If some other user is already logged in on this session*/
		if( err == CKR_USER_ANOTHER_ALREADY_LOGGED_IN  )
		{
			err = CKR_OK;
			printf("\n Another user already loggen in !!!\n");
			goto exit;
		}

		/* If session not opened */
		if( err == CKR_SESSION_HANDLE_INVALID )
		{
			err = CKR_OK;
			printf("\nSession not opened !!!\n");
			goto exit;
		}

		logger(err, "C_Login() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	printf("\nLogin successful\n");
	exit:
		return err;
}

/*
 * Function : logout()
 * Description : Logout from a SO or Normal user session
 */
CK_RV logout()
{
	CK_RV err = CKR_OK;
	CK_SESSION_HANDLE current_session = CKR_SESSION_HANDLE_INVALID;
	int option = 0;

	/* Check if any session is opened on token */
	if( session_count == 0)
	{
		printf("\n No sessions are opened on token !!!\n");
		goto exit;
	}

	display_opened_session();

	printf("\nEnter the session from which you want to logout: ");
	scanf("%d",&option);

	err = p11_functions->C_Logout(session_arr[option-1].session_handle);
	if( err )
	{
		/* If invalid session selected to logout from */
		if( err == CKR_SESSION_HANDLE_INVALID )
		{
			err = CKR_OK;
			printf("\nInvalid session selected or session not opened !!!\n");
			goto exit;
		}

		/* If user not logged in and you try to logout */
		if( err == CKR_USER_NOT_LOGGED_IN )
		{
			err = CKR_OK;
			printf("\nUser not logged in!!!\n");
			goto exit;
		}

		logger(err, "C_Logout() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	printf("\nLogout Successful\n");
	exit:
		return err;
}


/*
 * Function : read_pin(char *pin,int *pin_len)
 * Description : Read entered PIN (not echoing PIN) and stores PIN in pin and pin length in pin_len
 */
int read_pin(unsigned char *pin,unsigned int *pin_len)
{
	struct termios terminal_ds, prev_term_ds;
	int err = EXIT_SUCCESS;
	int ch;

	/* Retrieve current terminal settings */
	err = tcgetattr(STDIN_FILENO,&terminal_ds);
	if(err == -1)
	{
		logger(err, "tcgetattr() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	/* Save old settings, so that we can restore later */
	prev_term_ds = terminal_ds;

	/* Turn echo bit off and update terminal settings */
	terminal_ds.c_lflag &= ~ECHO;
	err = tcsetattr(STDIN_FILENO, TCSAFLUSH, &terminal_ds);
	if (err == -1)
	{
		logger(err, "tcgetattr() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	fflush(stdout);
	while( ((ch = getchar()) != '\n') )
	{
		pin[*pin_len] = ch;
		(*pin_len)++;
	}

	/* If newline at the end of the pin. You'll have to check that */
	if( pin[*pin_len-1] == '\n' )
	{
		pin[*pin_len-1] = '\0';
	}

	/* Restore original terminal settings */
	err = tcsetattr(STDIN_FILENO,TCSANOW,&prev_term_ds);
	if(err == -1)
	{
		logger(err, "tcgetattr() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	exit:
		return err;
}




/*
 * Function : display_opened_session()
 * Description : Display info of opened sessions on token
 */
void display_opened_session()
{
	/* If no session openend, exit */
	if( session_count == 0)
	{
		printf("\nNo session currently opened !!!\n");
		return;
	}

	printf("\n%10s %10s %10s", "Number", "Session Handle", "Slot ID \n");
	for (int i = 0; i < session_count; i++)
	{
		printf("\n%10d %10ld %10ld ", i + 1, session_arr[i].session_handle,session_arr[i].slot_id);
	}
}



char* get_mechanism_type(CK_MECHANISM_TYPE mechanism)
{
	switch( mechanism)
	{
	case 0x00000000:
		return "CKM_RSA_PKCS_KEY_PAIR_GEN";
		break;
	case 0x00000001:
		return "CKM_RSA_PKCS";
		break;
	case 0x00000002:
		return "CKM_RSA_9796";
		break;
	case 0x00000003:
		return "CKM_RCKM_RSA_X_509";
		break;
	case 0x00000004:
		return "CKM_MD2_RSA_PKCS";
		break;
	case 0x00000005:
		return "CKM_MD5_RSA_PKCS";
		break;
	case 0x00000006:
		return "CKM_SHA1_RSA_PKCS";
		break;
	case 0x00000007:
		return "CKM_RIPEMD128_RSA_PKCS";
		break;
	case 0x00000008:
		return "CKM_RIPEMD160_RSA_PKCS";
		break;
	case 0x00000009:
		return "CKM_RSA_PKCS_OAEP";
		break;
	case 0x0000000A:
		return "CKM_RSA_X9_31_KEY_PAIR_GEN";
		break;
	case 0x0000000B:
		return "CKM_RSA_X9_31";
		break;
	case 0x0000000C:
		return "CKM_SHA1_RSA_X9_31";
		break;
	case 0x0000000D:
		return "CKM_RSA_PKCS_PSS";
		break;
	case 0x0000000E:
		return "CKM_SHA1_RSA_PKCS_PSS";
		break;
	case 0x00000010:
		return "CKM_DSA_KEY_PAIR_GEN";
		break;
	case 0x00000011:
		return "CKM_DSA";
		break;
	case 0x00000012:
		return "CKM_DSA_SHA1";
		break;
	case 0x00000013:
		return "CKM_DSA_FIPS_G_GEN";
		break;
	case 0x00000014:
		return "CKM_DSA_SHA224";
		break;
	case 0x00000015:
		return "CKM_DSA_SHA256";
		break;
	case 0x00000016:
		return "CKM_DSA_SHA384";
		break;
	case 0x00000017:
		return "CKM_DSA_SHA512";
		break;
	case 0x00000020:
		return "CKM_DH_PKCS_KEY_PAIR_GEN";
		break;
	case 0x00000021:
		return "CKM_DH_PKCS_DERIVE";
		break;
	case 0x00000030:
		return "CKM_X9_42_DH_KEY_PAIR_GEN";
		break;
	case 0x00000031:
		return "CKM_X9_42_DH_DERIVE";
		break;
	case 0x00000032:
		return "CKM_X9_42_DH_HYBRID_DERIVE";
		break;
	case 0x00000033:
		return "CKM_X9_42_MQV_DERIVE";
		break;
	case 0x00000040:
		return "CKM_SHA256_RSA_PKCS";
		break;
	case 0x00000041:
		return "CKM_SHA384_RSA_PKCS";
		break;
	case 0x00000042:
		return "CKM_SHA512_RSA_PKCS";
		break;
	case 0x00000043:
		return "CKM_SHA256_RSA_PKCS_PSS";
		break;
	case 0x00000044:
		return "CKM_SHA384_RSA_PKCS_PSS";
		break;
	case 0x00000045:
		return "CKM_SHA512_RSA_PKCS_PSS";
		break;
	case 0x00000046:
		return "CKM_SHA224_RSA_PKCS";
		break;
	case 0x00000047:
		return "CKM_SHA224_RSA_PKCS_PSS";
		break;
	case 0x00000048:
		return "CKM_SHA512_224";
		break;
	case 0x00000049:
		return "CKM_SHA512_224_HMAC";
		break;
	case 0x0000004A:
		return "CKM_SHA512_224_HMAC_GENERAL";
		break;
	case 0x0000004B:
		return "CKM_SHA512_224_KEY_DERIVATION";
		break;
	case 0x0000004C:
		return "CKM_SHA512_256";
		break;
	case 0x0000004D:
		return "CKM_SHA512_256_HMAC";
		break;
	case 0x0000004E:
		return "CKM_SHA512_256_HMAC_GENERAL";
		break;
	case 0x0000004F:
		return "CKM_SHA512_256_KEY_DERIVATION";
		break;
	case 0x00000050:
		return "CKM_SHA512_T";
		break;
	case 0x00000051:
		return "CKM_SHA512_T_HMAC";
		break;
	case 0x00000052:
		return "CKM_SHA512_T_HMAC_GENERAL";
		break;
	case 0x00000053:
		return "CKM_SHA512_T_KEY_DERIVATION";
		break;
	case 0x00000100:
		return "CKM_RC2_KEY_GEN";
		break;
	case 0x00000101:
		return "CKM_RC2_ECB";
		break;
	case 0x00000102:
		return "CKM_RC2_CBC";
		break;
	case 0x00000103:
		return "CKM_RC2_MAC";
		break;
	case 0x00000104:
		return "CKM_RC2_MAC_GENERAL";
		break;
	case 0x00000105:
		return "CKM_RC2_CBC_PAD";
		break;
	case 0x00000110:
		return "CKM_RC4_KEY_GEN";
		break;
	case 0x00000111:
		return "CKM_RC4";
		break;
	case 0x00000120:
		return "CKM_DES_KEY_GEN";
		break;
	case 0x00000121:
		return "CKM_DES_ECB";
		break;
	case 0x00000122:
		return "CKM_DES_CBC";
		break;
	case 0x00000123:
		return "CKM_DES_MAC";
		break;
	case 0x00000124:
		return "CKM_DES_MAC_GENERAL";
		break;
	case 0x00000125:
		return "CKM_DES_CBC_PAD";
		break;
	case 0x00000130:
		return "CKM_DES2_KEY_GEN";
		break;
	}
	return "EMPTY";
}

/*
 *
 */

CK_RV mechanism_list()
{
	CK_RV err = CKR_OK;
	CK_SLOT_ID slot_id = 0UL;
	CK_ULONG no_of_mechanism = 0;
	CK_MECHANISM_TYPE_PTR mechanism_list = NULL ;
	CK_MECHANISM_INFO mechanism_info;

	printf("\nEnter the slot id of the token to get mechanisms from: ");
	scanf("%ld",&slot_id);

	/* First get number of mechanism supported by token */
	err = p11_functions->C_GetMechanismList(slot_id,NULL_PTR,&no_of_mechanism);
	if( err )
	{
		logger(err, "C_GetMechanismList() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	/* If success , then allocate memory to hold mechanism list supported by token */
	if( no_of_mechanism > 0 )
	{
		mechanism_list = (CK_MECHANISM_TYPE_PTR) malloc(no_of_mechanism * sizeof(CK_MECHANISM_TYPE));
		if( mechanism_list == NULL)
		{
			printf("\nERROR: Unable to allocate memory to mechanism list !!! \n");
			goto exit;
		}

		/* Get token mechanism supported */
		err = p11_functions->C_GetMechanismList(slot_id,mechanism_list,&no_of_mechanism);
		if( err )
		{
			logger(err, "C_GetMechanismList() failed", __LINE__, __FILE__,__FUNCTION__);
			goto exit;
		}
	}
	else
	{
		printf("\nERROR: No mechanism supported by token!!!\n");
		goto exit;
	}

	/* Print mechanism supported */
	for( CK_ULONG i = 0; i < no_of_mechanism; i++)
	{
		//err = get_mechanism_info(slot_id,mechanism_list[i],&mechanism_info);
		printf("\n%ld> %s \n",i+1,get_mechanism_type(mechanism_list[i]));
	}

	exit:
		return err;
}

void display_menu()
{
	printf("\n--------------------- PKCS11 eToken Utility --------------------\n");
	printf("\n1.Display number of available slots with token \n");
	printf("\n2.List number of available slots id with tokens\n");
	printf("\n3.Get token information in slot \n");
	printf("\n4.Initialize token in slot \n");
	printf("\n5.Open a session in given slot \n");
	printf("\n6.Close session\n");
	printf("\n7.Initialize a normal user\n");
	printf("\n8.Login into a session\n");
	printf("\n9.Display list of opened sessions\n");
	printf("\n10.Display menu\n");
	printf("\n11.Logout from a session \n");
	printf("\n12.Change SO/Normal User PIN \n");
	printf("\n13.List mechanism type supported by token \n");
	printf("\n-----------------------------------------------------------------\n");
}

int main()
{
	CK_RV err = CKR_OK;
	int option = 0;

	/* Load PKCS 11 functions from library */
	err = load_pkcs11_functions();
	if( err != CKR_OK)
	{
		logger(err,"load_pkcs11_functions() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	/* Display menu */
	display_menu();

	while(TRUE)
	{
		printf("\n Enter an option:");

		if( scanf("%d",&option) == 0)
		{
			printf("\n Invalid operation selected \n");
			goto exit;
		}

		switch(option)
		{
		case 1:
		{
			CK_ULONG slot_count = 0;
			/* Get number of available slots */
			err = get_count_available_slots(&slot_count);
			if (err != CKR_OK)
			{
				logger(err, "get_count_available_slots() failed", __LINE__,__FILE__, __FUNCTION__);
				goto exit;
			}
			printf("\n Number of available slots with tokens: %ld \n",slot_count);
			break;
		}
		case 2:
		{
			CK_ULONG slot_count = 0;
			CK_ULONG max_slot_count = 0;
			CK_SLOT_ID *slot_list = NULL;
			CK_ULONG slot_iterator = 0;

			/* List number of available slots id with tokens*/
			err = get_count_available_slots(&slot_count);
			if (err != CKR_OK) {
				logger(err, "get_count_available_slots() failed", __LINE__,__FILE__, __FUNCTION__);
				goto exit;
			}
			/* Assign memory to slot_id buffer to store list of slot list of slot ids */
			slot_list = (CK_SLOT_ID*) malloc(sizeof(CK_SLOT_ID) * slot_count);
			max_slot_count = slot_count;

			/* Get slot list */
			err = get_slot_list(&max_slot_count, &slot_list);
			if (err != CKR_OK)
			{
				logger(err, "get_slot_list() failed", __LINE__, __FILE__,__FUNCTION__);
				goto exit;
			}

			/* Verify new count to slot does not exceed slots previously detected */
			if (slot_count > max_slot_count)
			{
				printf("Second call to C_GetSlotList returned number of present slots(%ld) larger than previously detected(%ld)",max_slot_count, slot_count);
			}

			printf("\nList of available slot ids with tokens: \n");

			/* Get info of each slot */
			for (slot_iterator = 0; slot_iterator < max_slot_count; slot_iterator++)
			{
				printf("\nSlot #%ld\n", slot_list[slot_iterator]);
			}

			break;
		}
		case 3:
		{
			CK_TOKEN_INFO token_info ;
			CK_SLOT_ID slot_id = 0 ;
			char buffer[100] ={0};

			printf("\nEnter slot id: ");
			scanf("%ld",&slot_id);

			get_token_info(slot_id,&token_info);

			printf("Token information: \n");
			snprintf(buffer,sizeof(token_info.label),"%s",token_info.label);
			printf("->label: %s\n",buffer);

			memset(buffer,0,sizeof(buffer));
			snprintf(buffer,sizeof(token_info.manufacturerID),"%s",token_info.manufacturerID);
			printf("->Manufacturer: %s\n",buffer);


			memset(buffer,0,sizeof(buffer));
			snprintf(buffer,sizeof(token_info.model),"%s",token_info.model);
			printf("->Model: %s\n",buffer);

			memset(buffer,0,sizeof(buffer));
			snprintf(buffer,sizeof(token_info.serialNumber),"%s",token_info.serialNumber);
			printf("->Serial number: %s\n",buffer);

			memset(buffer,0,sizeof(buffer));
			snprintf(buffer,sizeof(token_info.ulTotalPublicMemory),"%ld",token_info.ulTotalPublicMemory);
			printf("->Total public memory: %s\n",buffer);

			memset(buffer,0,sizeof(buffer));
			snprintf(buffer,sizeof(token_info.ulFreePublicMemory),"%ld",token_info.ulFreePublicMemory);
			printf("->Total free public memory: %s\n",buffer);

			memset(buffer,0,sizeof(buffer));
			snprintf(buffer,sizeof(token_info.ulSessionCount),"%ld",token_info.ulSessionCount);
			printf("->Session count: %s\n",buffer);

			memset(buffer,0,sizeof(buffer));
			snprintf(buffer,sizeof(token_info.ulMaxSessionCount),"%ld",token_info.ulMaxSessionCount);
			printf("->Max Session count: %s\n",buffer);

			/* Check flags */
			if( token_info.flags & CKF_RNG)
			{
				printf("->Token has its own random number generator \n");
			}
			else
			{
				printf("->Token does not have its own random number generator \n");
			}

			if( token_info.flags & CKF_WRITE_PROTECTED)
			{
				printf("->Token is write protected\n");
			}
			else
			{
				printf("->Token is not write protected \n");
			}

			if( token_info.flags & CKF_TOKEN_INITIALIZED)
			{
				printf("->Token is initialized\n");
			}
			else
			{
				printf("->Token is not initialized \n");
			}

			break;
		}
		case 4:
		{
			CK_SLOT_ID slot_id = 0 ;

			printf("\nEnter slot id of the token to init: ");
			scanf("%ld", &slot_id);

			err = initialize_token(slot_id);
			if ( err != CKR_OK )
			{
				logger(err,"initialize_token() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}

			break;
		}
		case 5:
		{
			CK_SLOT_ID slot_id = 0 ;

			printf("\nEnter the slot on which you want to open session: ");
			scanf("%ld",&slot_id);

			err = open_session(slot_id);
			if( err )
			{
				logger(err,"open_session() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}

			break;
		}
		case 6:
		{
			err = close_session();
			if( err )
			{
				logger(err,"close_session() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}


			break;
		}
		case 7:
		{
			err = init_pin();
			if( err )
			{
				logger(err,"init_pin() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}

			break;
		}
		case 8:
		{
			err = login();
			if( err )
			{
				logger(err,"login() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}

			break;
		}
		case 9:
		{
			display_opened_session();
			break;
		}
		case 10:
		{
			display_menu();
			break;
		}
		case 11:
		{
			err = logout();
			if( err )
			{
				logger(err,"logout() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}
			break;
		}
		case 12:
		{
			err = change_pin();
			if( err )
			{
				logger(err,"change_pin() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}
			break;
		}
		case 13:
		{
			err = mechanism_list();
			if( err )
			{
				logger(err,"change_pin() failed",__LINE__,__FILE__,__FUNCTION__);
				goto exit;
			}
			break;
		}
		default:
		{
			printf("\nInvalid option entered\n");
			goto exit;
		}

		}
	}

	exit:
		return err;
}
