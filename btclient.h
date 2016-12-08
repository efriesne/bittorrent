#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>

#define set_bit(A,k)     ( A[(k/8)] |= (1 << (k%8)) )
#define clear_bit(A,k)   ( A[(k/8)] &= ~(1 << (k%8)) )
#define get_bit(A,k)    ( (A[(k/8)] & (1 << (k%8))) >> (k%8))

#define NOT_STARTED 0
#define STARTED 1
#define COMPLETED 2

#define MAX_FILENAME 1024
#define PEER_ID_SIZE 20

typedef struct piece {
	char *block_bitmap; //does this have a predefined length or is it different from torrent to torrent
	int offset;
	int len;
	int status;
} piece_t;

typedef struct btfile {
	char filename[MAX_FILENAME];
	int offset;
	int fd;
	int len;
} btfile_t;

typedef struct peer {
	uint32_t ip;
	char id[PEER_ID_SIZE];
	//figure out what piece bitmap looks like
	int status;
	int choked;
	int choking;
	int interested;
	int interesting;
} peer_t;

typedef struct torrent_ctrl {
	btfile_t *files;
	piece_t *pieces;
	char *dest_dir;
	int downloaded;
	int uploaded;
	char *piece_bitmap;
	int torrent_len;
	int num_pieces;
	char *info_hash; //maybe depending on number of times it is used
	char *tracker_url;
} torrent_ctrl_t;

int port;
char client_id[PEER_ID_SIZE];
torrent_ctrl_t torrent_ctrl;


void print_bitmap(char *bitmap, int numbits);
