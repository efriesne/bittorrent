#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "bencoding/bencode.h"
#include <curl/curl.h>
#include "btclient.h"
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include "error.h"
#include <sys/socket.h>
#include <netdb.h>


void dump_string(const char *str, long long len)
{
	long long i;
	const unsigned char *s = (const unsigned char *)str;

	/* Assume non-ASCII data is binary. */
	for (i = 0; i < len; ++i)
		if (s[i] >= 0x20 && s[i] <= 0x7e)
			printf("%c", s[i]);
		else
			printf("\\x%02x", s[i]);  
}

int create_tcp_socket(char *host, char *port, int *sock){
        struct addrinfo hints;
        struct addrinfo *results;
        struct addrinfo *rp;
        int err;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = AI_PASSIVE;
        hints.ai_socktype = SOCK_STREAM;
       printf("creating socket with ip %s and port %s\n", host, port);
        if ((err = getaddrinfo(host, port, &hints, &results)) != 0){
                perror("getaddrinfo: error occured");
                return -SYS_ERR;
        }
        for (rp = results; rp != NULL; rp = rp->ai_next) {
                if ((*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0){
                        printf("here\n");
                        continue;
                }
                if (connect(*sock, rp->ai_addr, rp->ai_addrlen) >= 0){
                        printf("connected to socket\n");
                        break;
                }
                if (close(*sock) == -1){
                        perror("close: error occured closing socket");
                        freeaddrinfo(results);
                        return -SYS_ERR;
                }
        }

        if (rp == NULL){
                fprintf(stderr, "error: could not connect to host %s at port number %s\n", host, port);
                freeaddrinfo(results);
                return -CONN_ERR;
        }
        freeaddrinfo(results);
        close(*sock);
        return 0;
}

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

void download_from_peer() {

}

void setup_peers(char *peers_str, int peer_count) {
	int i;
	struct sockaddr_in sa;
	tc.peers = (peer_t *)malloc(sizeof(peer_t)*peer_count);
	for (i = 0; i < peer_count; i++) {
		//parse ip address
		uint32_t addr;
		struct in_addr ip;
		ip.s_addr = *((uint32_t *) peers_str);
		inet_ntop(AF_INET,&ip, tc.peers[i].ip, INET_ADDRSTRLEN);
		printf("ip %s\n", tc.peers[i].ip);
		peers_str += 4;
		
		//parse port
		uint16_t port;
		memcpy(&port, peers_str, 2);
		tc.peers[i].port = ntohs(port);
		peers_str += 2;

		//create TCP socket
		char port_str[PORT_SIZE];
		sprintf(port_str, "%u", tc.peers[i].port);
		if (create_tcp_socket(tc.peers[i].ip, port_str, &tc.peers[i].sock) < 0) {
			printf("problem making tcp socket\n");
		}

		//start downloading from peer
/*
		if ((err = pthread_create(&tc.peers[i].thread, NULL, (void *)&download_from_peer, NULL)) < 0) {
                
        }*/
	}
}

void tracker_response_func() {
	int i, j;
	char *buf;
	long long len;
	be_node *n;
	char *peers_str;
	int peer_count = 0;

	buf = read_file(RESPONSE_FILENAME, &len);
	
	n = be_decoden(buf, len, NULL, NULL);
	if (n) {
		be_dump(n);

		for (i = 0; n->val.d[i].val; ++i) {
			if (!strcmp(n->val.d[i].key, "complete")) {
				peer_count += n->val.d[i].val->val.i;
			} else if (!strcmp(n->val.d[i].key, "incomplete")) {
				peer_count += n->val.d[i].val->val.i;
			} else if (!strcmp(n->val.d[i].key, "peers")) {
				peers_str = (char * )malloc(peer_count*6);
				memcpy(peers_str,  n->val.d[i].val->val.s, peer_count*6);
			}
		}

		setup_peers(peers_str, peer_count);
		free(peers_str);
		be_free(n);
	} else {
		printf("\tparsing response failed!\n");
	}
	
}

void add_url_param(char *url, char *key, char* val, int end) {
	strcat(url, key);
	strcat(url, "=");
	strcat(url, val);
	if (!end) {
		strcat(url, "&");
	}
}

void tracker_request_func(char *event) {
	CURL *curl;
	CURLcode res;
	char *url;
	FILE *tracker_response_file;
	char url_buf[MAX_URL_SIZE];
	memset(url_buf, 0, MAX_URL_SIZE);
	char *encoded_info_hash;
	char *encoded_peer_id;

	curl_global_init(CURL_GLOBAL_DEFAULT); 
	tracker_response_file = fopen(RESPONSE_FILENAME, "w+");
	curl = curl_easy_init();
	if (curl) {
		encoded_info_hash = curl_easy_escape(curl, tc.info_hash, SHA_SIZE);
		printf("hash %s \n encoded hash %s\n", tc.info_hash, encoded_info_hash);
		encoded_peer_id = curl_easy_escape(curl, client_id, strlen(client_id));
		strcat(url_buf, tc.tracker_url);
		strcat(url_buf, "?");

		char uploaded[STRING_SIZE];
		sprintf(uploaded, "%d", tc.uploaded);
		char downloaded[STRING_SIZE];
		sprintf(downloaded, "%d", tc.downloaded);
		char left[STRING_SIZE];
		sprintf(left, "%d", tc.torrent_len - tc.downloaded);
		char compact[STRING_SIZE];
		sprintf(compact, "%d", 1);


		add_url_param(url_buf, "info_hash", encoded_info_hash, 0);
		//add_url_param(url_buf, "peer_id", encoded_peer_id, 0);
		add_url_param(url_buf, "port", port, 0);
		add_url_param(url_buf, "uploaded", uploaded, 0);
		add_url_param(url_buf, "downloaded", downloaded, 0);
		add_url_param(url_buf, "left", left, 0);
		add_url_param(url_buf, "compact", compact, 0);
		add_url_param(url_buf, "event", event, 1);
		printf("\nSENDING HTTP GET REQUEST: %s\n", url_buf);
		printf("RESPONSE:\n");
		curl_easy_setopt(curl, CURLOPT_URL, url_buf);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, tracker_response_file);
		res = curl_easy_perform(curl); 
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
		    curl_easy_strerror(res));
		}
		curl_free(encoded_info_hash);
		curl_free(encoded_peer_id);
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	fclose(tracker_response_file);
	tracker_response_func();
}

void setup_files(be_node *files) {
	int i, j;
	int num_files = 0;
	tc.torrent_len = 0;
	for (i = 0; files->val.l[i]; ++i) {
		be_node *file = files->val.l[i];
		for (j = 0; file->val.d[j].val; ++j) {
			be_dict file_item = file->val.d[j];
			if (!strcmp(file_item.key, "length")) {
				tc.torrent_len += file_item.val->val.i;
			}
		}
		num_files++;
	}
	printf("torrent len %d\n", tc.torrent_len);
	/*
	tc.files = (btfile_t *)malloc(sizeof(btfile_t) * num_files);
	for (i = 0; files->val.l[i]; ++i) {
			printf("here\n");

		be_node *file = files->val.l[i];
		for (j = 0; file->val.d[j].val; ++j) {
			be_dict file_item = file->val.d[j];
			if (!strcmp(file_item.key, "length")) {
				tc.files[i].len = file_item.val->val.i;
			} else if (!strcmp(file_item.key, "sha1")) {
				memcpy(tc.files[i].sha1, file_item.val->val.s, strlen(file_item.val->val.s));
			} else if (!strcmp(file_item.key, "path")) {
				memcpy(tc.files[i].filename, file_item.val->val.l[0]->val.s, strlen(file_item.val->val.l[0]->val.s));
				int filename_len = strlen(tc.dest_dir) + strlen(tc.files[i].filename) + 1;
				char buf[filename_len];
				strcat(buf, tc.dest_dir);
				strcat(buf, "/");
				strcat(buf, tc.files[i].filename);
				FILE *fd = fopen(buf, "w+");
			}
		}
	} */
}





void setup_pieces(char *pieces) {
	int i;
	int offset = 0;
	int left = tc.torrent_len;
	tc.num_pieces = (int)ceil((double)tc.torrent_len / (double)tc.piece_length);
	tc.pieces = malloc(sizeof(piece_t) * tc.num_pieces);
	for (i = 0; i < tc.num_pieces; ++i) {
		memcpy(tc.pieces[i].sha1, pieces, SHA_SIZE);
		pieces += SHA_SIZE;
		tc.pieces[i].offset = offset;
		offset += tc.piece_length;
		if (left < tc.piece_length) {
			tc.pieces[i].len = left;
		} else {
			tc.pieces[i].len = tc.piece_length;
		}
		printf("piece %d length %d offset %d\n", i, tc.pieces[i].len, tc.pieces[i].offset);
		left -= tc.piece_length;

		//status
		//inialize block bitmap
	} 
}


int main(int argc, char *argv[]) {
	int i, j;
	char *buf;
	long long len;
	be_node *n;

	if (argc != 4) {
		printf("error: usage is <torrentfile> <dest directory> <port number>\n");
		return -1;
	}
	tc.dest_dir = argv[2];
	tc.uploaded = 0;
	tc.downloaded = 0;
	port = argv[3];

	buf = read_file(argv[1], &len);
	if (!buf) {
		buf = argv[1];
		len = strlen(argv[1]);
	}
	char info_str[len];
	int info_str_len;
	printf("DECODING: %s\n", argv[1]);
	n = be_decoden(buf, len, info_str, &info_str_len);
	if (n) {
		//be_dump(n);

		//parse info from decoded torrent file
		for (i = 0; n->val.d[i].val; ++i) {
			if (!strcmp(n->val.d[i].key, "announce")) {
				be_node *announce_n = n->val.d[i].val;
				memcpy(tc.tracker_url, announce_n->val.s, strlen(announce_n->val.s));
			} else if (!strcmp(n->val.d[i].key, "info")) {
				be_node *info_n = n->val.d[i].val;
				for (j = 0; info_n->val.d[j].val; ++j) {
					if (!strcmp(info_n->val.d[j].key, "files")) {
						setup_files(info_n->val.d[j].val);
					} else if (!strcmp(info_n->val.d[j].key, "piece length")) {
						tc.piece_length = info_n->val.d[j].val->val.i;
					} else if (!strcmp(info_n->val.d[j].key, "pieces")) {
						setup_pieces(info_n->val.d[j].val->val.s);
					}
				}
			}
		}

		SHA1(info_str, info_str_len, tc.info_hash);
		sprintf(client_id, "emmanoah%d", getpid());
		tracker_request_func("started");
		be_free(n);
		

	} else {
		printf("\tparsing failed!\n");
	}
	if (buf != argv[1]) {
		free(buf);
	}
	return 0;
}

int get_next_piece() {
	int i;
	for (i = 0; i < tc.num_pieces; i++) {
		if (get_bit(tc.piece_bitmap, i) == 0) {
			return i;
		}
	}
}

int get_next_block(int pieceno) {
	char *block_bitmap = tc.pieces[pieceno].block_bitmap;
	int i;
	for (i = 0; i < ((int) tc.pieces[pieceno].len / BLOCKSIZE); i++) {
		if (get_bit(block_bitmap, i) == 0) {
			return i;
		}
	}
}

void get_block(peer_t *peer, int *offset, int *length) {
	if (peer->cur_piece == UNSET || get_bit(tc.piece_bitmap, peer->cur_piece) == 1) {
		peer->cur_piece = get_next_piece();
	}
	int blockno = get_next_block(peer->cur_piece);
	*offset = blockno*BLOCKSIZE;
	*length = MIN(BLOCKSIZE, tc.pieces[peer->cur_piece].len - *offset);
}

int write_block(char *block_ptr, int pieceno, int offset, int len) {
	int byte_num = pieceno*tc.piece_length + offset;
	int i;
	for (i = 0; i < tc.num_files; i++) {
		btfile_t file = tc.files[i];
		if (byte_num >= file.offset && byte_num < file.offset + file.len) {
			int to_write = MIN(len, file.len);
			int written = write(file.fd, block_ptr, to_write);
			if (written < 0) {
				//error occurred
				perror("error writing to one of the files");
				return -1;
			}
			if (written < len) {
				write_block(block_ptr + written, pieceno, offset + written, len - written);
			}
			return 1;
		}
	}
}


//prints the given bitmap
void print_bitmap(char *bitmap, int numbits) {
	int i;
	for (i = 0; i < numbits; i++) {
		printf("%d", get_bit(bitmap, i));
	}
	printf("\n");
}