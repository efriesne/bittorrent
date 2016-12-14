#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>


#define set_bit(A,k)     ( A[(k/8)] |= (1 << (k%8)) )
#define clear_bit(A,k)   ( A[(k/8)] &= ~(1 << (k%8)) )
#define get_bit(A,k)    ( (A[(k/8)] & (1 << (k%8))) >> (k%8))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define NOT_STARTED 0
#define STARTED 1
#define COMPLETED 2

#define MAX_FILENAME 1024
#define PEER_ID_SIZE 20
#define MAX_URL_SIZE 2048
#define PORT_SIZE 32
#define STRING_SIZE 128
#define SHA_SIZE 20
#define RESPONSE_FILENAME "tracker_response_file"
#define REQUEST_LEN 13

#define BLOCKSIZE 14000

#define CHOKE 0
#define UNCHOKE 1
#define INTERESTED 2
#define NOT_INTERESTED 3
#define HAVE 4
#define BITFIELD 5
#define REQUEST 6
#define PIECE 7
#define CANCEL 8
#define PORT 9

#define NO_CONNECTION 0
#define HANDSHAKE_RECVD 1


#define UNSET -1

typedef struct piece {
	char *block_bitmap; 
	char *requested_blocks;
	int offset;
	int len;
	int status;
	int num_blocks;
	char sha1[SHA_SIZE];
} piece_t;

typedef struct btfile {
	char filename[MAX_FILENAME];
	int offset;
	int fd;
	int len;
	char sha1[SHA_SIZE];
} btfile_t;

typedef struct block {
	int piece_idx;
	int block_idx;
} block_t;

typedef struct peer {
	char ip[INET_ADDRSTRLEN];
	char id[PEER_ID_SIZE];
	int cur_piece; //the current piece we are downloading from this peer
	uint16_t port;
	int status;
	int am_choking;
	int am_interested;
	int peer_chocking;
	int peer_interested;
	int sock;
	// list_t requested; should we keep a list of what blocks have been requested from this peer in case they choke or cancel?
	int num_requested; // the number of blocks we have requested from this peer (which havent been completed yet)
	pthread_t thread;
	char *bitmap;
} peer_t;

typedef struct torrent_ctrl {
	btfile_t *files;
	piece_t *pieces;
	peer_t *peers;
	pthread_mutex_t mtx;
	char *dest_dir;
	int downloaded;
	int uploaded;
	char *piece_bitmap;
	int torrent_len;
	int num_pieces;
	int num_files;
	int num_peers;
	int piece_length;
	char info_hash[SHA_SIZE]; //maybe depending on number of times it is used
	char tracker_url[1024];
	char *tracker_id;
} torrent_ctrl_t;

char *port;
char client_id[PEER_ID_SIZE];
torrent_ctrl_t tc;


void print_bitmap(char *bitmap, int numbits);
void send_message(int sock, uint32_t len, uint8_t id, char *payload);
void get_block(peer_t *peer, int *block, int *offset, int *length);
