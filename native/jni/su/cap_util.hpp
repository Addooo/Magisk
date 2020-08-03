


int get_magisk_uid();
int* getCapab(const char *capFile);
bool doesFileExist(const char *pathFile);
char* get_process_name_by_uid(const int uid);
char* searchBin(char *searchPath, const char* comm);
unsigned long long int getSCap(int* capArray);
