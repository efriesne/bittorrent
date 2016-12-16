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
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include "error.h"
#include <sys/socket.h>
#include <netdb.h>


int mkpath(char* file_path, mode_t mode) {
  char* p;
  for (p=strchr(file_path+1, '/'); p; p=strchr(p+1, '/')) {
    *p='\0';
    if (mkdir(file_path, mode)==-1) {
      if (errno!=EEXIST) { *p='/'; return -1; }
    }
    *p='/';
  }
  return 0;
}

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
       	//printf("creating socket with ip %s and port %s\n", host, port);
        if ((err = getaddrinfo(host, port, &hints, &results)) != 0){
                perror("getaddrinfo: error occured");
                return -SYS_ERR;
        }
        for (rp = results; rp != NULL; rp = rp->ai_next) {
                if ((*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0){
                        continue;
                }
                //printf("found socket %d\n", sock);
                if (connect(*sock, rp->ai_addr, rp->ai_addrlen) >= 0){
                        //printf("connected to socket\n");
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
        //printf("done\n");
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

int do_handshake(peer_t *peer) {

		//send handshake to peer
		uint8_t pstrlen = 19;
		char *pstr = "BitTorrent protocol";
		char reserved[8];
		memset(reserved, 0, 8);
		//printf("pstr being sent %s tc hash %s and id %s with length %d\n", pstr, tc.info_hash, client_id, pstrlen);
        write(peer->sock, &pstrlen, sizeof(uint8_t));
        write(peer->sock, pstr, strlen(pstr));
        write(peer->sock, reserved, 8);
        write(peer->sock, tc.info_hash, SHA_SIZE); 
        write(peer->sock, client_id, PEER_ID_SIZE);

        //receive handshake from peer
        uint8_t reply_pstrlen;
        
        char reply_reserved[8];
        char reply_info_hash[SHA_SIZE];
        read(peer->sock, &reply_pstrlen, sizeof(uint8_t));
        char reply_pstr[reply_pstrlen + 1];
        read(peer->sock, reply_pstr, reply_pstrlen);
        reply_pstr[reply_pstrlen] = '\0';
        read(peer->sock, reply_reserved, 8);
        read(peer->sock, reply_info_hash, SHA_SIZE);
        read(peer->sock, peer->id, PEER_ID_SIZE);
        //printf("received pstr: %s with tc hash %s and id %s\n", reply_pstr, reply_info_hash, peer->id);
        if (strncmp(reply_info_hash, tc.info_hash, SHA_SIZE)) {
        	printf("sha1 from responding handshake incorrect\n");
        	return -1;
        }

        // printf("handshake succeeded with peer id %s\n", peer->id);
        return 0;
}

void send_bitmap(peer_t *peer) {
	int len_bitfield = (int)ceil((double)tc.num_pieces / (double) 8);
	//printf("length of bitfield being send %d, number of pieces %d\n", len_bitfield, tc.num_pieces);
	send_message(peer->sock, len_bitfield + 1, BITFIELD, tc.piece_bitmap);
}

void request_block(peer_t *peer) {
	int block;
	int offset;
	int length;
	if (peer->cur_piece != 0 && is_being_requested(0)) {
		return;
	}
	peer->cur_piece = 0;
	get_block(peer, &block, &offset, &length);
	//printf("requesting block %d of piece %d with offset %d and length %d (num_blocks in piece is %d size is %d)\n", block, peer->cur_piece, offset, length, tc.pieces[peer->cur_piece].num_blocks, tc.pieces[peer->cur_piece].len);
	char payload[REQUEST_LEN];
	if (peer->cur_piece == UNSET) {
		return;
	}
	block = htonl(block);
	offset = htonl(offset);
	length = htonl(length);
	int piece_num = htonl(peer->cur_piece);
	memcpy(payload, &piece_num, sizeof(uint32_t));
	memcpy(payload + 4, &offset, sizeof(uint32_t));
	memcpy(payload+8, &length, sizeof(uint32_t));
	send_message(peer->sock, REQUEST_LEN, REQUEST, payload);
	//set that we have requested the block
	set_bit(tc.pieces[peer->cur_piece].requested_blocks, ntohl(block));
	peer->num_requested++;
}

int handle_reply(peer_t *peer, uint8_t reply_id, int reply_len) {
	//printf("handling reply %d with length %d\n", reply_id, reply_len);
	if (reply_id == BITFIELD && peer->bitmap == NULL) {
		peer->bitmap = (char *) malloc(reply_len -1);
		read(peer->sock, peer->bitmap, reply_len -1);
		if (!is_full(peer->bitmap, tc.num_pieces)) {
			printf("peer bitmap is not full disconnecting\n");
			return -1;
		}
		peer->am_interested = 1;
		//printf("printing bitmap with len %d:", tc.num_pieces);
		//print_bitmap(peer->bitmap, (reply_len -1) * 8);
		send_bitmap(peer);
		send_message(peer->sock, 1, INTERESTED, NULL);
		//printf("done sending bitmap and interested message\n");
		// request_block(peer);
	} else if (reply_id == UNCHOKE) {
		//send a bunch of requests
		printf("received unchoke\n");
		if (peer->peer_choking == 1) {
			while (peer->num_requested < 20) {
				request_block(peer);
			}
			peer->peer_choking = 0;
		}
		
	} else if (reply_id == CHOKE) {
		peer->peer_choking = 1;
	} else if (reply_id == PIECE) {
		uint32_t index;
		uint32_t begin;
		char block[reply_len - 9];
		int bytes_read = 0;
		read(peer->sock, &index, sizeof(uint32_t));
		read(peer->sock, &begin, sizeof(uint32_t));
		while (bytes_read < reply_len - 9) {
			bytes_read += read(peer->sock, block+ bytes_read, reply_len - 9 - bytes_read);
		}
		//printf("read %d bytes from the socket\n", bytes_read);
		index = ntohl(index);
		begin = ntohl(begin);
		//printf("recieved piece reply with index %d and begin %d\n", index, begin);
		write_block(block, index, begin, reply_len - 9);
		peer->num_requested-= 1;
		tc.downloaded += reply_len -9;
		request_block(peer);
		//update block/piece map, check SHA-1
		//send another request if needed
	} else {
		printf("received improper reply id number exiting\n");
		return -1;
	}
	return 0;
}



void send_message(int sock, uint32_t len, uint8_t id, char *payload) {
	uint32_t net_len = htonl(len);
	int written = write(sock, &net_len, sizeof(uint32_t));
	written += write(sock, &id, sizeof(uint8_t));
	if (payload != NULL) {
		written += write(sock, payload, len-1);
	}
	//printf("%d bytes written to socket\n", written);
}


void connect_to_peer(void *args) {
	int peer_id = *((int *)args);
	peer_t *peer = &tc.peers[peer_id];
	//create TCP socket
	char port_str[PORT_SIZE];
	sprintf(port_str, "%u", peer->port);
	if (create_tcp_socket(peer->ip, port_str, &peer->sock) < 0) {
		return;
	}

	//printf("successfully created tcp socket %d for ip %s and port %s\n", peer->sock, peer->ip, port_str);

	// //handshake
	if (do_handshake(peer) < 0) {
		printf("error occured\n");
		return;
	}

	peer->status = HANDSHAKE_RECVD;
	tc.num_estab_peers += 1;
	// //send bitfield
	// send_message(peer->sock, tc.num_pieces+1, BITFIELD, tc.piece_bitmap);


	//212 with length 1699497422
	//handling reply 165 with length -1306272106
	while (1) {
		//printf("receiving reply\n");
		uint32_t reply_len;
		uint8_t reply_id;
		read(peer->sock, &reply_len, sizeof(reply_len));
		read(peer->sock, &reply_id, sizeof(reply_id));
		reply_len = ntohl(reply_len);
		if (handle_reply(peer, reply_id, reply_len) < 0) {
			return;
		}
	}
}

int setup_peers(char *peers_str, int peer_count) {
	int i;
	struct sockaddr_in sa;
	tc.peers = (peer_t *)malloc(sizeof(peer_t)*peer_count);
	tc.num_peers = peer_count;
	tc.num_estab_peers = 0;
	for (i = 0; i < peer_count; i++) {
		//parse ip address
		uint32_t addr;
		struct in_addr ip;
		ip.s_addr = *((uint32_t *) peers_str);
		inet_ntop(AF_INET,&ip, tc.peers[i].ip, INET_ADDRSTRLEN);
		peers_str += 4;
		
		//parse port
		uint16_t port;
		memcpy(&port, peers_str, 2);
		tc.peers[i].port = ntohs(port);
		peers_str += 2;

		//initalize connection states
		tc.peers[i].am_choking = 1;
		tc.peers[i].am_interested = 0;
		tc.peers[i].peer_choking = 1;
		tc.peers[i].peer_interested = 0;
		tc.peers[i].status = NO_CONNECTION;
		tc.peers[i].cur_piece = UNSET;
		tc.peers[i].num_requested = 0;
		tc.peers[i].bitmap = NULL;

		//start connecting with peer
		int *peer_id = malloc(sizeof(int));
		*peer_id = i;
		if (pthread_create(&tc.peers[i].thread, NULL, (void *)&connect_to_peer, (void *)peer_id) < 0) {
         	perror("problem creating peer thread");
         	return -1;       
        }
	}
	return 0;
	// TODO: thread for checking keep alive messages & sending keep alive messages
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
		//be_dump(n);

		for (i = 0; n->val.d[i].val; ++i) {
			if (!strcmp(n->val.d[i].key, "complete")) {
				peer_count += n->val.d[i].val->val.i;
			} else if (!strcmp(n->val.d[i].key, "incomplete")) {
				peer_count += n->val.d[i].val->val.i;
			} else if (!strcmp(n->val.d[i].key, "peers")) {
				peers_str = (char * )malloc(peer_count*6);
				memcpy(peers_str,  n->val.d[i].val->val.s, peer_count*6);
			} else if (!strcmp(n->val.d[i].key, "tracker_id")) {
				tc.tracker_id = (char *)malloc(strlen(n->val.d[i].val->val.s));
				memcpy(tc.tracker_id, n->val.d[i].val->val.s, strlen(n->val.d[i].val->val.s));
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
		//printf("\nSENDING HTTP GET REQUEST: %s\n", url_buf);
		//printf("RESPONSE:\n");
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
		num_files++;
	}
	tc.files = malloc(sizeof(btfile_t)*num_files);
	tc.num_files = num_files;
	for (i = 0; files->val.l[i]; ++i) {
		be_node *file = files->val.l[i];
		for (j = 0; file->val.d[j].val; ++j) {
			be_dict file_item = file->val.d[j];
			if (!strcmp(file_item.key, "length")) {
				tc.files[i].offset = tc.torrent_len;
				tc.files[i].len = file_item.val->val.i;
				tc.torrent_len += file_item.val->val.i;
			}
			if (!strcmp(file_item.key, "path")) {
				be_node *node = file_item.val->val.l[0];
				memcpy(tc.files[i].filename, node->val.s, strlen(node->val.s) );
				//printf("creating file with name %s\n", tc.files[i].filename);
				memcpy(tc.files[i].filepath, tc.dest_dir, strlen(tc.dest_dir));
				memcpy(tc.files[i].filepath + strlen(tc.dest_dir), tc.files[i].filename, strlen(tc.files[i].filename) + 1);
				//printf("full path for file is %s\n");
				tc.files[i].fd = open(tc.files[i].filepath, O_CREAT | O_RDWR, S_IRWXU);
			}
		}
	}

	//printf("torrent len %d\n", tc.torrent_len);
}





void setup_pieces(char *pieces) {
	int i;
	int offset = 0;
	int left = tc.torrent_len;
	tc.num_pieces = (int)ceil((double)tc.torrent_len / (double)tc.piece_length);
	//printf("number of pieces is %d\n", tc.num_pieces);
	tc.pieces = malloc(sizeof(piece_t) * tc.num_pieces);
	tc.piece_bitmap = malloc(((int)(tc.num_pieces / 8)) + 1);
	memset(tc.piece_bitmap, 0, ((int)(tc.num_pieces / 8)) + 1);
	//print_bitmap(tc.piece_bitmap, tc.num_pieces);
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
		tc.pieces[i].num_blocks = (int) ceil((double)tc.pieces[i].len / (double) BLOCKSIZE);
		tc.pieces[i].block_bitmap = malloc((int) (tc.pieces[i].num_blocks/8) + 1);
		tc.pieces[i].requested_blocks = malloc((int) (tc.pieces[i].num_blocks/8) + 1);
		memset(tc.pieces[i].block_bitmap, 0, (int) (tc.pieces[i].num_blocks/8) + 1);
		memset(tc.pieces[i].requested_blocks, 0, (int) (tc.pieces[i].num_blocks/8) + 1);
		// printf("piece %d length %d offset %d\n", i, tc.pieces[i].len, tc.pieces[i].offset);
		left -= tc.piece_length;

		//status
		//inialize block bitmap
	} 
}

void read_files(int start_byte, int length, char *buffer) {
	int i;
	for (i=0; i < tc.num_files; i++) {
		btfile_t file = tc.files[i];
		if (start_byte >= file.offset && start_byte < file.offset + file.len) {
			int to_read = MIN(file.len - (start_byte - file.offset), length);
			struct stat buf;
			fstat(file.fd, &buf);
			int size = buf.st_size;
			lseek(file.fd, start_byte - file.offset, SEEK_SET);
			int bytes_read = read(file.fd, buffer, to_read);
			//printf("read %d bytes from file %s (to read is %d file size is %d) \n", bytes_read, file.filename, to_read, size);
			if (bytes_read != to_read) {
				printf("read failed\n");
				return;
			}
			if (bytes_read < length) {
				read_files(start_byte + bytes_read, length - bytes_read, buffer + bytes_read);
			}
		}
	}
}

void bitmap_initialize() {
	int i;
	for (i = 0; i < tc.num_pieces; i++) {
		//printf("checking piece %d\n", i);
		piece_t piece = tc.pieces[i];
		char data[piece.len];
		char hash[SHA_SIZE];
		read_files(piece.offset, piece.len, data);
		SHA1(data, piece.len, hash);
		if (!strncmp(piece.sha1, hash, SHA_SIZE)) {
			printf("we have piece %d\n", i);
		}
	}
}

void help_cmd(const char *line){
  (void)line;

  printf("- help: Print this list of commands.\n"
  		 "- tracker: Print information about the tracker.\n"
         "- torrent: Print information the torrent file.\n"
         "- status: Print information the torrent status.\n"
         "- files: Print information the files.\n"
         "- pieces: Print information the pieces.\n"
         "- peers: Print information the peers.\n"
         "- q: exit the program.\n");

  return;
}

void cleanup_and_exit() {
  exit(0);
}

void tracker_cmd(const char *line) {
	pthread_mutex_lock(&tc.mtx);
	printf("  tracker id: %s\n", tc.tracker_id);
	pthread_mutex_unlock(&tc.mtx);
}

void torrent_cmd(const char *line) {
	pthread_mutex_lock(&tc.mtx);
	printf("  announce url:  %s\n",  tc.tracker_url);
	//printf("  creation date:  %d\n", tc.num_peers - tc.num_estab_peers);
	//printf("  comment:  ", tc.num_pieces);
	printf("  piece count: %d\n", tc.num_pieces);
	printf("  piece length: %d\n", tc.piece_length);
	printf("  file count: %d\n", tc.num_files);
	printf("  download directory: %s\n", tc.dest_dir);
	pthread_mutex_unlock(&tc.mtx);
}

void status_cmd(const char *line){
	pthread_mutex_lock(&tc.mtx);
	printf("  seeders:  %d\n", tc.num_estab_peers);
	printf("  leechers:  %d\n", tc.num_peers - tc.num_estab_peers);
	printf("  pieceBitmap (%d):  ", tc.num_pieces);
	if (tc.piece_bitmap != NULL) {
		print_bitmap(tc.piece_bitmap, tc.num_pieces);
	}
	printf("  downloaded: %d\n", tc.downloaded);
	printf("  uploaded: %d\n", tc.uploaded);
	printf("  totalsize: %d\n", tc.torrent_len);
	printf("  remaining: %d\n", tc.torrent_len - tc.downloaded);
	printf("  seeding: %d\n", tc.seeding);
	pthread_mutex_unlock(&tc.mtx);
}

void peers_cmd(const char *line){
	pthread_mutex_lock(&tc.mtx);
	int i;
	printf("Peers (%d)\n", tc.num_estab_peers); //when does peer get disconnected
	int count = 0;
	for (i = 0; i < tc.num_peers; i++) {
		if (tc.peers[i].status == HANDSHAKE_RECVD) {
			printf("    Peer %d:\n", count);
			printf("        addr: %s\n", tc.peers[i].ip);
			printf("        port: %u\n", tc.peers[i].port);
			//printf("%8srecvMsgs: %d\n", tc.peers[i].recv_msgs);
			//printf("%8ssentMsgs: %d\n", tc.peers[i].sent_msgs);
			printf("        requested: %d\n", tc.peers[i].num_requested);
			printf("        pieceBitmap: (%d)", tc.num_pieces);
			if (tc.peers[i].bitmap == NULL) {
				printf("NULL\n");
			} else {
				print_bitmap(tc.peers[i].bitmap, tc.num_pieces);
			}
			printf("        choked: %d\n", tc.peers[i].peer_choking);
			printf("        choking: %d\n", tc.peers[i].am_choking);
			printf("        interested: %d\n", tc.peers[i].peer_interested);
			printf("        interesting: %d\n", tc.peers[i].am_interested);
			count++;
		}
	}

  	

  	pthread_mutex_unlock(&tc.mtx);
}

void pieces_cmd(const char *line){
	pthread_mutex_lock(&tc.mtx);
	int i;
	printf("Pieces (%d)\n", tc.num_pieces); //when does peer get disconnected
	for (i = 0; i < tc.num_pieces; i++) {
		printf("    Piece (%d)\n", i);
		printf("        offset: %d\n", tc.pieces[i].offset);
		printf("        length: %d\n", tc.pieces[i].len);
		printf("        complete: %d\n", get_bit(tc.piece_bitmap, i));
		printf("        blockBitmap: (%d)  ", tc.pieces[i].num_blocks);
		if (tc.pieces[i].block_bitmap == NULL) {
			printf("NULL\n");
		} else {
			print_bitmap(tc.pieces[i].block_bitmap, tc.pieces[i].num_blocks);
		}
	}
  	pthread_mutex_unlock(&tc.mtx);
}

void files_cmd(const char *line){
	pthread_mutex_lock(&tc.mtx);
	int i;
	printf("Files (%d)\n", tc.num_files); //when does peer get disconnected
	for (i = 0; i < tc.num_files; i++) {
		printf("    File (%d)\n", i);
		printf("        name: %s\n", tc.files[i].filename);
		printf("        offset: %d\n", tc.files[i].offset);
		printf("        length: %d\n", tc.files[i].len);
		printf("        filePath: %s\n", tc.files[i].filepath);
	}
  	pthread_mutex_unlock(&tc.mtx);
}



void quit_cmd(const char *line){
  cleanup_and_exit();
}

struct {
  const char *command;
  void (*handler)(const char *);
} cmd_table[] = {
  {"help", help_cmd},
  {"peers", peers_cmd},
  {"files", files_cmd},
  {"pieces", pieces_cmd},
  {"status", status_cmd},
  {"tracker", tracker_cmd},
  {"torrent", torrent_cmd},
  {"q", quit_cmd}
};

void driver(){
  char line[LINE_MAX];
  char cmd[LINE_MAX];
  char *fgets_ret;
  int ret;
  unsigned i; 

  while (1){
    printf("> ");
    (void)fflush(stdout);

    fgets_ret = fgets(line, sizeof(line), stdin);
    if (fgets_ret == NULL){
      break;
    }

    ret = sscanf(line, "%s", cmd);
    if (ret != 1){
      fprintf(stderr, "syntax error (first argument must be a command)\n");
      continue;
    }

    for (i=0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); i++){
      if (!strcmp(cmd, cmd_table[i].command)){
        cmd_table[i].handler(line);
        break;
      }
    }

    if (i == sizeof(cmd_table) / sizeof(cmd_table[0])){
      fprintf(stderr, "error: no valid command specified\n");
      continue;
    }

  }
  return;
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
	pthread_mutex_init(&tc.mtx);
	mkpath(tc.dest_dir, 0755);
	tc.uploaded = 0;
	tc.downloaded = 0;
	tc.seeding = 0;
	port = argv[3];

	//parse metainfo
	buf = read_file(argv[1], &len);
	if (!buf) {
		buf = argv[1];
		len = strlen(argv[1]);
	}
	char info_str[len];
	int info_str_len;
	//printf("DECODING: %s\n", argv[1]);
	char name[MAX_FILENAME];
	memset(name, 0, MAX_FILENAME);
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
					if (!strcmp(info_n->val.d[j].key, "files")) { //multi file mode
						setup_files(info_n->val.d[j].val);
					} else if (!strcmp(info_n->val.d[j].key, "name")) {
						memcpy(name, info_n->val.d[j].val->val.s, strlen(info_n->val.d[j].val->val.s));
					} else if (!strcmp(info_n->val.d[j].key, "length")) { //single file mode
						tc.files = malloc(sizeof(btfile_t));
						tc.num_files = 1;
						tc.files[0].offset = 0;
						tc.files[0].len = info_n->val.d[j].val->val.i;
						tc.torrent_len = info_n->val.d[j].val->val.i;
						memcpy(tc.files[0].filename, name, strlen(name));
						memcpy(tc.files[0].filepath, tc.dest_dir, strlen(tc.dest_dir));
						memcpy(tc.files[0].filepath + strlen(tc.dest_dir), name, strlen(name));
						tc.files[i].fd = open(tc.files[i].filepath, O_CREAT | O_RDWR, S_IRWXU);
					} else if (!strcmp(info_n->val.d[j].key, "piece length")) {
						tc.piece_length = info_n->val.d[j].val->val.i;
					} else if (!strcmp(info_n->val.d[j].key, "pieces")) {
						setup_pieces(info_n->val.d[j].val->val.s);
					}
				}
			}
		}

		
		// bitmap_initialize();
		SHA1(info_str, info_str_len, tc.info_hash);
		strcpy(client_id, "-EN0001-123456789012");
		
		//TODO - check if some of file has been downloaded - run function for "have" message once before requesting tracker info

		tracker_request_func("started");
		be_free(n);


		driver();
		

	} else {
		printf("\tparsing failed!\n");
	}
	if (buf != argv[1]) {
		free(buf);
	}
	pthread_exit(0);
}

//returns whether or not all of a piece's blocks have been requested
int is_full(char *bitmap, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if (get_bit(bitmap, i) == 0) {
			return 0;
		}
	}
	return 1;
}

//returns whether or not a piece is being requested currently by another peer (should request entire piece from one peer)
int is_being_requested(int pieceno) {
	int i;
	for (i = 0; i < tc.num_peers; i++) {
		if (tc.peers[i].cur_piece == pieceno ) {
			return 1;
		}
	}
	return 0;
}

int get_next_piece() {
	int i;
	for (i = 0; i < tc.num_pieces; i++) {
		// printf("piece %d has value %d and fully requested %d and is being requested %d\n", i, get_bit(tc.piece_bitmap, i), is_fully_requested(i), is_being_requested(i));
		if (get_bit(tc.piece_bitmap, i) == 0 && !is_full(tc.pieces[i].requested_blocks, tc.pieces[i].num_blocks) && !is_being_requested(i)) {
			return i;
		}
	}
	return UNSET;
}

int get_next_block(int pieceno) {
	char *block_bitmap = tc.pieces[pieceno].requested_blocks;
	int i;
	for (i = 0; i < tc.pieces[pieceno].num_blocks; i++) {
		// printf("value of block %d is %d\n", i, get_bit(block_bitmap, i));
		if (get_bit(block_bitmap, i) == 0) {
			return i;
		}
	}
}

//if all blocks have been requested, this puts UNSET in block
void get_block(peer_t *peer, int *block, int *offset, int *length) {
	pthread_mutex_lock(&tc.mtx);
	if (peer->cur_piece == UNSET || is_full(tc.pieces[peer->cur_piece].requested_blocks, tc.pieces[peer->cur_piece].num_blocks) || get_bit(tc.piece_bitmap, peer->cur_piece) == 1) {
		peer->cur_piece = UNSET;
		peer->cur_piece = get_next_piece();
	}
	if (peer->cur_piece == UNSET) {
		*block = UNSET;
		pthread_mutex_unlock(&tc.mtx);
		return;
	}
	int blockno = get_next_block(peer->cur_piece);
	pthread_mutex_unlock(&tc.mtx);
	*block = blockno;
	*offset = blockno*BLOCKSIZE;
	*length = MIN(BLOCKSIZE, tc.pieces[peer->cur_piece].len - *offset);
}

int write_block(char *block_ptr, int pieceno, int offset, int len) {
	int byte_num = pieceno*tc.piece_length + offset;
	int i;
	for (i = 0; i < tc.num_files; i++) {
		btfile_t file = tc.files[i];
		if (byte_num >= file.offset && byte_num < file.offset + file.len) {
			int to_write = MIN(len, file.len - (byte_num - file.offset));
			pthread_mutex_lock(&tc.mtx);
			lseek(file.fd, byte_num - file.offset, SEEK_SET);
			int written = write(file.fd, block_ptr, to_write);
			pthread_mutex_unlock(&tc.mtx);
			//printf("wrote %d bytes to file %s at location %d of file starting at offset %d\n", written, file.filename, byte_num - file.offset, file.offset);
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
