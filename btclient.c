#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "bencoding/bencode.h"
#include <curl/curl.h>
#include "btclient.h"

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

int main(int argc, char *argv[])
{
	int i;
	char *buf;
	long long len;
	be_node *n;

	if (argc != 4) {
		printf("error: usage is <torrentfile> <dest directory> <port number>\n");
		return -1;
	}
	torrent_ctrl.dest_dir = argv[2];
	port = atoi(argv[3]);

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


//prints the given bitmap
void print_bitmap(char *bitmap, int numbits) {
	int i;
	for (i = 0; i < numbits; i++) {
		printf("%d", get_bit(bitmap, i));
	}
	printf("\n");
}