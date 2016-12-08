#include "/gpfs/main/home/efriesne/include/curl/curl.h"
#include <stdio.h>

int main(int argc, char **argv) {
	CURL *curl;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	return 0;
}