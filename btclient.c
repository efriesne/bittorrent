#define FILE_IO

#include <stdio.h>
#include <string.h>
#ifdef FILE_IO
#include <sys/stat.h>
#include <stdlib.h>
#endif
#include "bencoding/bencode.h"

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
