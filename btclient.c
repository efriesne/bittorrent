#define FILE_IO

#include <stdio.h>
#include <string.h>
#ifdef FILE_IO
#include <sys/stat.h>
#include <stdlib.h>
#endif
#include "bencoding/bencode.h"
#include <curl/curl.h>

char *read_file(const char *file, long long *len) {
	struct stat st;
	char *ret = NULL;
	FILE *fp;

	if (stat(file, &st))
		return ret;
	*len = st.st_size;

	fp = fopen(file, "r");
	if (!fp)
		return ret;

	ret = malloc(*len);
	if (!ret)
		return NULL;

	fread(ret, 1, *len, fp);

	fclose(fp);

	return ret;
}

size_t tracker_response_func(void *ptr, size_t size, size_t nmemb, void *stream) {
	size_t len;
	char *response_str = NULL;
	be_node *n;

	len = size * nmemb;
	response_str = (char *)malloc(len);
	if (!response_str)
		return -1;

	fread(response_str, 1, len, (FILE *)stream);
	fclose(stream);

	n = be_decoden(response_str, len);
	if (n) {
		be_dump(n);
		be_free(n);
	} else {
		printf("\tparsing tracker response failed!\n");
	}
	free(response_str);
}

add_url_param(char *url, char *key, char* val, int end) {
	strcat(url, key);
	strcat(url, "=");
	strcat(url, val);
	if (!end) {
		strcat(url, "&");
	}
}

tracker_request_func(torrent_ctrl_t *tc, char *event) {
	CURL *curl;
	CURLcode res;
	char *url;
	FILE *tracker_response_file;
	char url_buf[MAX_URL_SIZE];
	memset(url_buf, 0, MAX_URL_SIZE);

	curl_global_init(CURL_GLOBAL_DEFAULT); 
	curl = curl_easy_init();
	if (curl) {
		strcat(url_buf, tc.tracker_url);
		strcat(url_buf, "?");
		add_url_param(url_buf, "info_hash", tc.info_hash, 0);
		add_url_param(url_buf, "peer_id", client_id, 0);
		add_url_param(url_buf, "port", port, 0);
		add_url_param(url_buf, "uploaded", tc.uploaded, 0);
		add_url_param(url_buf, "downloaded", tc.downloaded, 0);
		add_url_param(url_buf, "left", tc.torrend_len - downloaded, 0);
		add_url_param(url_buf, "compact", 1, 0);
		add_url_param(url_buf, "event", event, 1);
		
		curl_easy_setopt(curl, CURLOPT_URL, url_buf);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tracker_response_func);
		res = curl_easy_perform(curl); 
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
		    curl_easy_strerror(res));
		}

		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
}


int main(int argc, char *argv[])
{
	int i;

	setbuf(stdout, NULL);

	char *buf;
	long long len;
	be_node *n;

	buf = read_file(argv[1], &len);
	if (!buf) {
		buf = argv[1];
		len = strlen(argv[1]);
	}

	printf("DECODING: %s\n", argv[1]);
	n = be_decoden(buf, len);
	if (n) {
		be_dump(n);
		be_free(n);
	} else {
		printf("\tparsing failed!\n");
	}
	if (buf != argv[1]) {
		free(buf);
	}

	return 0;
}