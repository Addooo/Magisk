#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <utils.hpp>
#include <logging.hpp>

//per le capabilities
#include <sys/capability.h>
//#include <libcap.h>
#include <libcap/libcap.h>
#include <libcap/include/sys/capability.h>
#include <sys/prctl.h>
#include <linux/prctl.h>

//altre
#include <linux/types.h>
#include <errno.h>
#include <math.h>
#define LEN_CAP 21

int get_magisk_uid()
{	
	FILE *file;
	char *name = NULL;
	char *p, *p2;
	char *app = "com.topjohnwu.magisk";
	size_t len = 0;
	int ris = 0;
	char *valString = NULL;
	if(file = fopen("/data/system/packages.list", "r")){
		//leggendo riga per riga cerco uid
		//una volta trovato prendo tutto ciò che ci sta prima in modo da beccarmi il nome
		while(getline(&name, &len, file) != -1){
			if((p = strstr(name, app)) != NULL && (p2 = strstr(name, " ")) != NULL){ //strstr locate a substring
				char *p3 = strstr(++p2," ");
				unsigned int dim_string = ++p3 - p2;
			//	LOGD("lunghezza stringa [%d]\n", dim_string);
				valString = (char *)calloc(sizeof(char), dim_string);
				memset((void*)valString, 0, dim_string);
				memcpy(valString, p2, dim_string - 1);
				memset((void*)name, 0, len);
				free(name);
				ris = atoi(valString);
				LOGD("UID Magisk trovato %d", ris);
				break;
			}
		}
		fclose(file);
	}
	else
		LOGD("File packages.xml non trovato\n");
	
	return ris; 													
}

int* getCapab(const char *capFile){
	
	int *ris = (int*)malloc(sizeof(int) * (CAP_LAST_CAP+1));
	memset((void*)ris, 0, sizeof(int) * (CAP_LAST_CAP + 1));
	const char *cap_name[CAP_LAST_CAP+1] = {
		"cap_chown",
		"cap_dac_override",
		"cap_dac_read_search",
		"cap_fowner",
		"cap_fsetid",
		"cap_kill",
		"cap_setgid",
		"cap_setuid",
		"cap_setpcap",
		"cap_linux_immutable",
		"cap_net_bind_service",
		"cap_net_broadcast",
		"cap_net_admin",
		"cap_net_raw",
		"cap_ipc_lock",
		"cap_ipc_owner",
		"cap_sys_module",
		"cap_sys_rawio",
		"cap_sys_chroot",
		"cap_sys_ptrace",
		"cap_sys_pacct",
		"cap_sys_admin",
		"cap_sys_boot",
		"cap_sys_nice",
		"cap_sys_resource",
		"cap_sys_time",
		"cap_sys_tty_config",
		"cap_mknod",
		"cap_lease",
		"cap_audit_write",
		"cap_audit_control",
		"cap_setfcap",
		"cap_mac_override",
		"cap_mac_admin",
		"cap_syslog",
		"cap_wake_alarm",
		"cap_block_suspend",
		"cap_audit_read"
	};

	//parsing
	
	FILE *file;
 	if (file = fopen(capFile, "r")) {

		char str[LEN_CAP];
		while(fgets(str, LEN_CAP, file)){
			//legge la capability e la cerca se la trova bene, altrimenti ciao
			str[strlen(str) - 1] = 0;
		//	LOGD("Capability letta [%s]\n", str);
			for(int i = 0; i < CAP_LAST_CAP + 1; i++){
				if(!strcmp(str, cap_name[i])){
		//			LOGD("	-capability trovata [%s]\n",cap_name[i]);
					ris[i] = 1;
					break;
				}
			}
			
			memset((void*)str, 0, LEN_CAP);
		}
		LOGD("File capabilities utilizzato\n");
 		fclose(file);
	 }
	else{
		LOGD("Errore nell'apertura del file\n");	
		return NULL;	
	}	
	return ris;
}

bool doesFileExist(const char *pathFile){

//	LOGD("Percorso file [%s]\n", pathFile);
	int fd = open(pathFile, O_RDONLY);
//	LOGD("fd: [%d]\n", fd);
	if (fd != -1){
		close(fd);
		LOGD("File [%s] trovato\n", pathFile);
		return true;
	}
	LOGD("File  [%s] non trovato\n", pathFile);	
	return false;
}


char* get_process_name_by_uid(const int uid)
{
	FILE *file;
	char *name = NULL;
	char *p;
	char *app = (char *)calloc(sizeof(char), 10);
	memset((void *)app, 0, 10);
	sprintf(app,"%d",uid);
	size_t len = 0;
	char *ris = NULL;
	if(file = fopen("/data/system/packages.list", "r")){
		//leggendo riga per riga cerco uid
		//una volta trovato prendo tutto ciò che ci sta prima in modo da beccarmi il nome
		while(getline(&name, &len, file) != -1){
			if((p = strstr(name, app)) != NULL){ //strstr locate a substring
				unsigned int dim_string = p - name;
//				LOGD("lunghezza stringa [%d]\n", dim_string);
				ris = (char *)calloc(sizeof(char), dim_string);
				memset((void*)ris, 0, dim_string);
				memcpy(ris, name, dim_string - 1);
				memset((void*)name, 0, len);
				memset((void*)app, 0, 10);
				free(app);
				free(name);
				LOGD("Nome applicazione trovato\n");
				break;
			}
		}
		fclose(file);
	}
	else
		LOGD("File packages.xml non trovato\n");


	return ris;

}

char* searchBin(char *searchPath, const char* comm){

	char *ret = NULL;
	unsigned int len = 0;
	unsigned int commlen = strlen(comm);
//	LOGD("Dim commlen: %d\n", commlen);
	char *token = strtok(searchPath, ":");
	bool fileExist = false;
//	LOGD("Primo Token: [%s]\n", token);
//	LOGD("Comando in input: [%s]\n", comm);
	while(token != NULL){
	//	LOGD("Path preso in esame [%s]\n", token);
		unsigned int pathlen = strlen(token);
//		LOGD("Pathlen: %d\n", pathlen);
		len = commlen + pathlen + 2; //NULL e "/"
		ret = (char *)malloc(sizeof(char) * len);
		memset(ret, 0, len);
		sprintf(ret, "%s/%s", token, comm);
	//	LOGD("Binario cercato: [%s]", ret);
		if(fileExist = doesFileExist(ret))
			break;
		token = strtok(NULL, ":");
		memset(ret, 0, len);
		free(ret);
	}
	if(!fileExist){
		memset(ret, 0, len);	
		free(ret);
		ret = (char *)malloc(sizeof(char) * (commlen + 1));
		strncpy(ret, comm, commlen);
		ret[commlen] = 0;
	//	LOGD("Binario cercato: [%s]", ret);
		if(fileExist = doesFileExist(ret))
			LOGD("Binario trovato in $PWD");
		else{
			LOGD("Binario non trovato");
			memset(ret, 0, len);
			free(ret);
			ret = NULL;
		}
	}

	LOGD("Bin trovato: [%s]\n", ret);
	return ret;
}

unsigned long long int getSCap(int* capArray){

	unsigned long long int ris = 0;
	
	for(int i = 0 ; i < CAP_LAST_CAP + 1; i++){
		if(capArray[i]){
			unsigned long long int app = pow(2, i);
			ris |= app;
		}
	}

	LOGD("Val: [%x]", ris);
	return ris;
}


