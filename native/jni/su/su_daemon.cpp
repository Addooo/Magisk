#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <stdio.h>

#include <logging.hpp>
#include <daemon.hpp>
#include <utils.hpp>
#include <selinux.hpp>

#include "su.hpp"
#include "pts.hpp"
#include "cap_util.hpp"

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

//#define LEN_CAP 21


using namespace std;

static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static shared_ptr<su_info> cached;
static cap_t *fileCapOld;
static char *binPath;
static unsigned int nReq = 0;
static const unsigned long long int CapDefault = 0x0000003fffffffff;
extern int rMag;


su_info::su_info(unsigned uid) :
		uid(uid), access(DEFAULT_SU_ACCESS), mgr_st({}),
		timestamp(0), _lock(PTHREAD_MUTEX_INITIALIZER) {}

su_info::~su_info() {
	pthread_mutex_destroy(&_lock);
}

mutex_guard su_info::lock() {
	return mutex_guard(_lock);
}

bool su_info::is_fresh() {
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	long current = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
	return current - timestamp < 3000;  /* 3 seconds */
}

void su_info::refresh() {
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void database_check(const shared_ptr<su_info> &info) {
	int uid = info->uid;
	get_db_settings(info->cfg);
	get_db_strings(info->str);
	// Check multiuser settings
	switch (info->cfg[SU_MULTIUSER_MODE]) {
		case MULTIUSER_MODE_OWNER_ONLY:
			if (info->uid / 100000) {
				uid = -1;
				info->access = NO_SU_ACCESS;
			}
			break;
		case MULTIUSER_MODE_OWNER_MANAGED:
			uid = info->uid % 100000;
			break;
		case MULTIUSER_MODE_USER:
		default:
			break;
	}

	if (uid > 0)
		get_uid_policy(info->access, uid);

	// We need to check our manager
	if (info->access.log || info->access.notify)
		validate_manager(info->str[SU_MANAGER], uid / 100000, &info->mgr_st);
}

//QUERY = 0,
//DENY = 1,
//ALLOW = 2,
			
static shared_ptr<su_info> get_su_info(unsigned uid, bool fileExist, char* filePath, int* & indici) {
	LOGD("su: request from uid=[%d]\n", uid);

	shared_ptr<su_info> info;
	{
		mutex_guard lock(cache_lock);
		if (!cached || cached->uid != uid || !cached->is_fresh())
			cached = make_shared<su_info>(uid);
		cached->refresh();
		info = cached;
	}

	auto g = info->lock();

	LOGD("ACCESS POLICY: %d", info->access.policy);

	if(fileExist){
		LOGD("File exist");
		indici = getCapab(filePath);
		info->capab = getSCap(indici); 
	}
	else{
//		unsigned long long int valCap = getCapfromDB(info->access, info->uid);
//		LOGD("ACCESS: [%d], Cap from DB: [%llu]", info->access, valCap);
		info->capab = CapDefault;
	}

	LOGD("Cap: %llu", info->capab);

	if (info->access.policy == QUERY) {
		// Not cached, get data from database
		database_check(info);

		// If it's root or the manager, allow it silently
		if (info->uid == UID_ROOT || (info->uid % 100000) == (info->mgr_st.st_uid % 100000)) {
			info->access = SILENT_SU_ACCESS;
			LOGD("SILENT_SU_ACCESS %d", uid);
			return info;
		}

		// Check su access settings
		switch (info->cfg[ROOT_ACCESS]) {
			case ROOT_ACCESS_DISABLED:
				LOGW("Root access is disabled!\n");
				LOGD("Switch 1");
				info->access = NO_SU_ACCESS;
				break;
			case ROOT_ACCESS_ADB_ONLY:
				if (info->uid != UID_SHELL) {
					LOGW("Root access limited to ADB only!\n");
					info->access = NO_SU_ACCESS;
				}
				LOGD("Switch 2");
				break;
			case ROOT_ACCESS_APPS_ONLY:
				if (info->uid == UID_SHELL) {
					LOGW("Root access is disabled for ADB!\n");
					info->access = NO_SU_ACCESS;
				}
				LOGD("Switch 3");
				break;
			case ROOT_ACCESS_APPS_AND_ADB:
				LOGD("Switch 4");
			default:
				break;
		}
	//	LOGD("1 %d", uid);
		LOGD("Access policy: %d, info->capab: %d", info->access.policy, info->capab);
		if (info->access.policy != QUERY){
			unsigned long long int controllo = getCapfromDB(info->access, info->uid);
			LOGD("Valore in db: [%llu]", controllo);
			if((fileExist && info->capab !=  controllo) || (!fileExist && controllo != CapDefault))
				info->access.policy = QUERY;		
			else
				return info;
		}
		
	//	LOGD("2 %d", uid);
		// If still not determined, check if manager exists
		if (info->str[SU_MANAGER][0] == '\0') {
			info->access = NO_SU_ACCESS;
			LOGD("3 %d", uid);
			return info;
		}
	} else {
		return info;
	}

	// If still not determined, ask manager
	struct sockaddr_un addr;
	int sockfd = create_rand_socket(&addr);

	// Connect manager
	app_socket(addr.sun_path + 1, info);
	int fd = socket_accept(sockfd, 60);
	if (fd < 0) {
		info->access.policy = DENY;
	} else {
		socket_send_request(fd, info);
		int ret = read_int_be(fd);
	//	LOGD("4 %d", uid); //la prima volta arriva qua
		info->access.policy = ret < 0 ? DENY : static_cast<policy_t>(ret);
	//	LOGD("Ritorno da richiest policy ecc: %d", ret);
		close(fd);
	}
	close(sockfd);
//	LOGD("5 %d", uid);
	return info;
}

static void set_identity(unsigned uid) {
	/*
	 * Set effective uid back to root, otherwise setres[ug]id will fail
	 * if uid isn't root.
	 */
	if (seteuid(0)) {
		PLOGE("seteuid (root)");
	}
	if (setresgid(uid, uid, uid)) {
		PLOGE("setresgid (%u)", uid);
	}
	if (setresuid(uid, uid, uid)) {
		PLOGE("setresuid (%u)", uid);
	}
}

void su_daemon_handler(int client, struct ucred *credential) {

//	fileCapOld = (cap_t *)mmap(NULL, sizeof(*fileCapOld), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0); 
	binPath = (char*)mmap(NULL, sizeof(char) * 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(binPath, 0, 1024);

	LOGD("=======================================================================");
	LOGD("Richiesta n° %d\n", nReq++);
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
	bool fileExist = false; // file sarà presente in /data/data/packageName
        char *filePath;
        int *indici;

	LOGD("su: request from pid=[%d], client=[%d]\n", credential->pid, client);

	//trovo il nome dell'applicazione dall'uid
	char *fName = get_process_name_by_uid((int)credential->uid);//ogni applicazione è un user in Android (ci sono alcune eccezioni da vedere però)
	
	//se file presente bene altrimenti lo si legge e si prendono le capabilities da mostrare a video ecc.. da chiedere(se è prima volta)
	//se file non presente si fa presente che sarà una su request normale (magari con qualche roba scritta rossa e così via)
	filePath = (char *)malloc(sizeof(char)  * 1024);
	memset((void*)filePath, 0,1024);
	sprintf(filePath, "/data/data/%s/capfile", fName);//assicurati che vale per tutte le applicazioni
//	LOGD("UID: %d\n", credential->uid);
//	LOGD("Percorso file: [%s], nReq: [%d]", filePath, nReq);
	fileExist = doesFileExist(filePath); 
	LOGD("nReq: %d, fileExist: %d ",nReq, fileExist);

	su_context ctx = {
		.info = get_su_info(credential->uid, fileExist, filePath, indici),//shared_ptr<su_info>(su_info è una classe)(get_su_info controlla se già presente in "cache"(?))
		.req = su_request(true),	     //su_request (con shell e command)
		.pid = credential->pid		     //pid
	};
	
	// Read su_request
	xxread(client, &ctx.req, sizeof(su_req_base));//read con fd, buf, e count
	ctx.req.shell = read_string(client);//puntatore a stringa zero terminated (la read si ricorda fin dove hai letto)
	ctx.req.command = read_string(client);//puntatore a stringa zero terminated
	LOGD("Shell: [%s], command: [%s], dim command: [%d]\n", ctx.req.shell, ctx.req.command, sizeof(ctx.req.command));

	//LOGD("SU REQUEST\n");
	//LOGD("command: %s\n", ctx.req.command);

	if (ctx.info->access.log)//controlla (vedi include/db.hpp)
		app_log(ctx);
	else if (ctx.info->access.notify)
		app_notify(ctx);

	// Fail fast
	if (ctx.info->access.policy == DENY) {//se policy è negativa niente chiudi tutto e ciao
		LOGW("su: request rejected (%u)", ctx.info->uid);
		ctx.info.reset();
		write_int(client, DENY);
		close(client);
		return;
	} else if (int child = xfork(); child) {//altrimenti forka (qua prosegue il padre perchè child non è nel suo caso)
		ctx.info.reset();// Replaces the managed object with an object pointed to by ptr (tecnicamente NULL)

		// Wait result
		LOGD("su: waiting child pid=[%d]\n", child);
		int status, code;

		if (waitpid(child, &status, 0) > 0)//aspetta il cambiamento di stato del figlio(se ok ritorna il pd [occhio a caso partic] se no -1)
			code = WEXITSTATUS(status);//esce con lo status
		else
			code = -1;
	

		//risetto le capabilities precedenti
	//	cap_set_file(binPath , *fileCapOld);
		//rimuovere le file cap
		if(fileExist){
			LOGD("File cap esiste, quindi ha senso deallocare\n");
//			cap_free(*fileCapOld);
		}
//		LOGD("Cap %x\n", *fileCapOld);	
//		memset(binPath, 0, 1024); // Occhio
		munmap(binPath, sizeof(char) * 1024);
//		munmap(fileCapOld, sizeof(*fileCapOld));

		LOGD("su: return code=[%d] errno=[%d]\n", code, errno);
		write(client, &code, sizeof(code));//scrive sul client ecc
		close(client);
//		LOGD("==============================================");
		return;
	}
	
	/* The child process will need to setsid, open a pseudo-terminal (setsid run a program in a new session)
	 * if needed, and will eventually run exec.
	 * The parent process will wait for the result and
	 * send the return code back to our client
	 */
	//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	LOGD("su: fork handler\n");

	// Abort upon any error occurred
	log_cb.ex = exit;

	// ack
	write_int(client, 0);

	// Become session leader
	xsetsid();

	// Get pts_slave
	char *pts_slave = read_string(client);

	// The FDs for each of the streams
	int infd  = recv_fd(client);
	int outfd = recv_fd(client);
	int errfd = recv_fd(client);

	if (pts_slave[0]) {
		LOGD("su: pts_slave=[%s]\n", pts_slave);
		// Check pts_slave file is owned by daemon_from_uid
		struct stat st;
		xstat(pts_slave, &st);

		// If caller is not root, ensure the owner of pts_slave is the caller
		if(st.st_uid != ctx.info->uid && ctx.info->uid != 0)
			LOGE("su: Wrong permission of pts_slave");

		// Opening the TTY has to occur after the
		// fork() and setsid() so that it becomes
		// our controlling TTY and not the daemon's
		int ptsfd = xopen(pts_slave, O_RDWR);

		if (infd < 0)
			infd = ptsfd;
		if (outfd < 0)
			outfd = ptsfd;
		if (errfd < 0)
			errfd = ptsfd;
	}

	free(pts_slave);

	// Swap out stdin, stdout, stderr
	xdup2(infd, STDIN_FILENO);
	xdup2(outfd, STDOUT_FILENO);
	xdup2(errfd, STDERR_FILENO);

	// Unleash all streams from SELinux hell
	setfilecon("/proc/self/fd/0", "u:object_r:" SEPOL_FILE_DOMAIN ":s0");
	setfilecon("/proc/self/fd/1", "u:object_r:" SEPOL_FILE_DOMAIN ":s0");
	setfilecon("/proc/self/fd/2", "u:object_r:" SEPOL_FILE_DOMAIN ":s0");

	close(infd);
	close(outfd);
	close(errfd);
	close(client);

	// Handle namespaces
	if (ctx.req.mount_master)
		ctx.info->cfg[SU_MNT_NS] = NAMESPACE_MODE_GLOBAL;
	switch (ctx.info->cfg[SU_MNT_NS]) {
		case NAMESPACE_MODE_GLOBAL:
			LOGD("su: use global namespace\n");
			break;
		case NAMESPACE_MODE_REQUESTER:
			LOGD("su: use namespace of pid=[%d]\n", ctx.pid);
			if (switch_mnt_ns(ctx.pid))
				LOGD("su: setns failed, fallback to global\n");
			break;
		case NAMESPACE_MODE_ISOLATE:
			LOGD("su: use new isolated namespace\n");
			xunshare(CLONE_NEWNS);
			xmount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);
			break;
	}

	const char *argv[] = { nullptr, nullptr, nullptr, nullptr };
		

	LOGD("ctx.req.login %d\n", ctx.req.login);
	argv[0] = ctx.req.login ? "-" : ctx.req.shell;

	if (ctx.req.command[0]) {
		argv[1] = "-c";
		argv[2] = ctx.req.command;
	}
//	LOGD("Vari args in input ad execvp\n");
	LOGD("argv[0]: %s\n",argv[0]);
	LOGD("argv[1]: %s\n",argv[1]);
	LOGD("argv[2]: %s\n",argv[2]);

	// Setup environment
	umask(022);
	char path[32];
	snprintf(path, sizeof(path), "/proc/%d/cwd", ctx.pid);
	chdir(path);
	snprintf(path, sizeof(path), "/proc/%d/environ", ctx.pid);
	char buf[4096] = { 0 };
	int fd = xopen(path, O_RDONLY);
	read(fd, buf, sizeof(buf));
	close(fd);
	clearenv();
	for (size_t pos = 0; buf[pos];) {
		putenv(buf + pos);
		pos += strlen(buf + pos) + 1;
	}
	if (!ctx.req.keepenv) {
		struct passwd *pw;
		pw = getpwuid(ctx.req.uid);
	if (pw) {
			setenv("HOME", pw->pw_dir, 1);
			setenv("USER", pw->pw_name, 1);
			setenv("LOGNAME", pw->pw_name, 1);
			setenv("SHELL", ctx.req.shell, 1);
		}
	}
	const char *ld_path = getenv("LD_LIBRARY_PATH");
	if (ld_path && strncmp(ld_path, ":/apex/com.android.runtime/lib", 30) == 0)
		unsetenv("LD_LIBRARY_PATH");

	// Unblock all signals
	sigset_t block_set;
	sigemptyset(&block_set);
	sigprocmask(SIG_SETMASK, &block_set, nullptr);
	set_identity(ctx.req.uid);
	//Se file capabilities è presente faccio il setuid e setto le capabilities che necessito
	//E poi vado ad eseguire il programma ponendo attenzione di poter far le cose in questione(aka come vengono ereditate le cap con execvp)
	LOGD("fileExist: %d, rMag: %d, credential->uid: %d", fileExist, rMag, credential->uid);
	if(fileExist && rMag != credential->uid){
		cap_value_t cap_list[CAP_LAST_CAP + 1];
		
		//change capabilities
		//change setuid
		LOGD("Operazioni su capabilities\n");
	
		// - Trovo il comando (aka il binario) 
		// - Prendo $PATH ed inizio a parsarla			
		char *searchPath = getenv("PATH");
		//nella funzione utilizzerò strok che modifica parte di $PATH e non è corretto (a quanto pare)
		unsigned int dim = strlen(searchPath);
		char *searchPath2 = (char *) malloc(sizeof(char) * (dim + 1)); //importante se no va a modificare $PATH vera e propria
		strncpy(searchPath2, searchPath, dim);
		searchPath2[dim] = 0;
		char *cmd;
		//La cosa sul comando ha senso ????
		struct stat isSetuid{}; // ricordati di inizializzarla in modo che abbia tutto a 0		
		
		if(argv[2] != NULL){
			int index = strlen(argv[2]) + 1;
		//	LOGD("Ciclo su ctx.req.command [%s]:\n", argv[2]);

			const char *space = strchr(ctx.req.command, 32);// ' ' = 32    3 2 1 0
		      	if(space != NULL)	
				index = space - argv[2];

			cmd = (char*)malloc(sizeof(char) * index);
			strncpy(cmd, argv[2], index);
			cmd[index] = 0;
		//	LOGD("\nQuesto è il comando senza parametri: [%s]\n", cmd);
		//	LOGD("Comando da eseguire [%s]\n",argv[2]);// argv[2] = ctx.req.command (da prima??)
			//ok però qua poi cambia le cose
			char *app = searchBin(searchPath2, cmd);// searchBin(searchPath2, ctx.req.command); prima del controllo su spazio	
			LOGD("Dopo aver eseguito searchBin [%s]\n", app);
			int pathLen = strlen(app);
			if(pathLen > 1023){
				LOGD("Dim percorso eccessiva\n");
				exit(EXIT_FAILURE);
			}
			//salvo binPath e fileCapOld in sharedbin
//			LOGD("binPath before strncat: [%s]\n", binPath);
			strncat(binPath, app, pathLen);
//			LOGD("binPath after strncat: [%s]\n", binPath);
			if(stat(binPath, &isSetuid) == -1){
                        	LOGD("Errore nel richiamare la funzione stat, errno: [%d]\n", errno);
				exit(EXIT_FAILURE);	
                        }

			//	- Quando trovo il binario in questione mi fermo ed uso le operazioni con le capabilities
		}
		LOGD("Dim searchPath2: %d", strlen(searchPath2));
		memset(searchPath2, 0, strlen(searchPath2));
		free(searchPath2);	

		LOGD("Binario trovato %s\n", binPath);

		//S_ISUID
	//	LOGD("st_mode: [%d]\n", isSetuid.st_mode); // setto quindi il setuid a quello che esegue il determinato binario (?)
		//perchè la sturttura dati isSetuid è NULL se non vi è un comando
		if(isSetuid.st_mode & S_ISUID && isSetuid.st_uid == 0) //PENSACI SU UN ATTIMO MEGLIO PERÒ SU STA COSA
			LOGD("il setuid Bit è settato\n");
		else{
	
//			LOGD("Qua iniziano le operazioni con le capabilities\n");


		//procedo con quanto sta sotto

		//	LOGD("Rimozione capabilities dal bounding set\n");
		//
			for(int i = 0; i < CAP_LAST_CAP + 1; i++){
				int ris = 0;
		//		if(prctl(PR_CAPBSET_READ, i, 0, 0, 0))
		//				LOGD("La capability: %s è nel bounding set", cap_name[i]);
				if(!indici[i]){
					if(ris = prctl(PR_CAPBSET_DROP, i,0,0,0))
			 	  		LOGD("Errore nel rimuovere dal bounding cap: %s, ris: %d, errno: %d\n", cap_name[i] ,ris, errno);
				}

			}
			
			//per mantenere le caps prima del setuid (PR_SET_KEEPCAPS) (SOLO LE PERMITTED PERÒ VERIFICA)
			if(prctl(PR_SET_KEEPCAPS, 1L)){//perchè ritorna 0 se l'operazione ha successo
				LOGD("IMPOSSIBILE MANTENERE LE CAPS\n");
				exit(EXIT_FAILURE);
			}
			
                
//TEST
    		/*	pid_t pidfTEST = getpid();
			cap_t capTEST = cap_get_pid(pidfTEST);
			for(int i = 0; i < CAP_LAST_CAP + 1; i++){
                        	cap_from_name(cap_name[i], &cap_list[i]);
                                LOGD("%-20s %d ", cap_name[i], cap_list[i]);
                              	for(int j = 0; j<3; j++){
                              		cap_get_flag(capTEST, cap_list[i], flags[j].flag, &cap_flags_value);
                              		LOGD("TEST: %s %-4s ", flags[j].str, (cap_flags_value == CAP_SET) ? "OK" : "NOK");
                              	}

				int ris_a = 0;
                        	if(ris_a = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0))
                        		LOGD("TEST AMBIENT %s è settata, ris: %d\n", cap_name[i], ris_a);
                        	else
                        		LOGD("TEST AMBIENT %s non è settata, ris: %d\n", cap_name[i], ris_a);

				int ris_b = 0;
				if(ris_b = prctl(PR_CAPBSET_READ, i, 0,0 ,0))
					LOGD("TEST BOUNDING %s è settata, ris %d\n", cap_name[i], ris_b);
				else
					LOGD("TEST BOUNDING %s non è settata, ris %d\n", cap_name[i], ris_b);

			}*/

//ENDTEST

			setgid(credential->gid);	
			setuid(credential->uid);
//			LOGD("SETUID FATTO");
			//nella variabile inidici ho tutte le capabilities che devo avere (quindi PERMITTED ed EFFECTIVE)
			//quindi settarle ora nessun problema (anche alla luce di PR_SET_KEEPCAPS)
			//risolvere problema execvp
			
			pid_t pidf = getpid();
			cap_t cap = cap_get_pid(pidf);

			//var per mettere nei log quanto letto/modificato/ecc (insieme a cap_name sopra)
			cap_flag_t cap_flags;                   		
			cap_flag_value_t cap_flags_value;       		
			struct {                                		
				const char *str;                		
				cap_flag_t flag;                		
			} flags[3] = {                          		
				{"EFFECTIVE", CAP_EFFECTIVE},   		
				{"PERMITTED", CAP_PERMITTED},   		
				{"INHERITABLE", CAP_INHERITABLE}		
			};                              		
        

			LOGD("Procedo con le modifche");    
			for(int i = 0; i < CAP_LAST_CAP + 1; i++){
				
				if(indici[i]){
					//solo INHERITABLE perchè PERMITTED preservate (keepcapfs)
		//			LOGD("Settando la capability numero: [%d]\n", i);
					cap_list[0] = i;
					if(cap_set_flag(cap, CAP_INHERITABLE, 1, cap_list, CAP_SET) == -1){
						LOGD("Errore nel settare la capability %d\n", i);
						exit(EXIT_FAILURE);
					}	
				}
				else{ //rimuovo da PERMITTED così son sicuro non saranno più ambient (val da Kernel > 4.3)
					cap_list[0] = i;
					if(cap_set_flag(cap, CAP_PERMITTED, 1, cap_list, CAP_CLEAR) == -1){
						LOGD("Errore nel rimuovere la permitted %d\n", i);
						exit(EXIT_FAILURE);
					}	
				}

			}
			
			int ris = cap_set_proc(cap);
			cap_free(cap);
			if(ris == -1)
				LOGD("Errore nel settare le capabilities\n");
			else
				LOGD("OPERAZIONI ANDATATE A BUON FINE\n");

			cap = cap_get_pid(pidf);
			LOGD("Post le modifiche\n");
 	     	    	for(int i = 0; i < CAP_LAST_CAP + 1; i++){
      	      			cap_from_name(cap_name[i], &cap_list[i]);
			      	LOGD("%-20s %d ", cap_name[i], cap_list[i]);
	      	          	for(int j = 0; j<3; j++){
	      	          		cap_get_flag(cap, cap_list[i], flags[j].flag, &cap_flags_value);
		          		LOGD("%s %-4s ", flags[j].str, (cap_flags_value == CAP_SET) ? "OK" : "NOK");
	      	          	}

		/*		int ris_b = 0;
				if(ris_b = prctl(PR_CAPBSET_READ, i, 0 ,0 ,0))
					LOGD("%s è nel bounding set",cap_name[i]);	
				else
					LOGD("%s non è nel bounding set", cap_name[i]);				
*/
				int ris_sa = 0;
				if(indici[i]){	
					if(ris_sa = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0 ,0))
						LOGD("Errore nel settare la capability [%s], ris_sa: [%d]", cap_name[i], ris_sa);
				}

				//PER TEST
		/*		int ris_a = 0;
				if(ris_a = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0))
					LOGD("AMBIENT %s è settata, ris: %d\n", cap_name[i], ris_a);
				else
					LOGD("AMBIENT %s non è settata, ris: %d\n", cap_name[i], ris_a);*/

      		          }

			cap_free(cap);
		}
//		LOGD("---------------------------------------------------------");
//		LOGD("UID: %d, indici: %x", credential->uid, indici);
//		LOGD("Dim tot indici: [%d]", sizeof(int) * (CAP_LAST_CAP + 1));
		memset((void*)indici, 0, sizeof(int) * (CAP_LAST_CAP + 1));
		free(indici);
	}
	memset((void*)filePath, 0,1024);
	free(filePath);
	char *app = fName;
	while(*app != 0)
		*app++ = 0;
	free(fName);
	LOGD("Ora eseguo il comando\n");
	execvp(ctx.req.shell, (char **) argv);
	fprintf(stderr, "Cannot execute %s: %s\n", ctx.req.shell, strerror(errno));
	PLOGE("exec");
	exit(EXIT_FAILURE);
}
