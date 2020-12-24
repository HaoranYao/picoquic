/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef PICOQUIC_SAMPLE_H
#define PICOQUIC_SAMPLE_H

#include "picoquic_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picosocks.h>
#include <picoquic_utils.h>
#include <autoqlog.h>
#include "picosocks.h"
#include <sys/socket.h>
#include "picoquic_packet_loop.h"
/* Header file for the picoquic sample project. 
 * It contains the definitions common to client and server */

#define PICOQUIC_SAMPLE_ALPN "picoquic_sample"
#define PICOQUIC_SAMPLE_SNI "test.example.com"

#define PICOQUIC_SAMPLE_NO_ERROR 0
#define PICOQUIC_SAMPLE_INTERNAL_ERROR 0x101
#define PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR 0x102
#define PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR 0x103
#define PICOQUIC_SAMPLE_FILE_READ_ERROR 0x104
#define PICOQUIC_SAMPLE_FILE_CANCEL_ERROR 0x105

#define PICOQUIC_SAMPLE_CLIENT_TICKET_STORE "sample_ticket_store.bin";
#define PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE "sample_token_store.bin";
#define PICOQUIC_SAMPLE_CLIENT_QLOG_DIR ".";
#define PICOQUIC_SAMPLE_SERVER_QLOG_DIR ".";

int picoquic_sample_client(char const* server_name, int server_port, char const* default_dir,
    int nb_files, char const** file_names);

int picoquic_sample_server(int server_port, const char* pem_cert, const char* pem_key, const char * default_dir);

int picoquic_sample_server_test_migration(int server_port, const char* pem_cert, const char* pem_key, const char * default_dir);

void * slave_quic(void * slave_para);
void * master_quic(void * master_para);
typedef struct st_picoquic_cnx_id_key_t {
    picoquic_connection_id_t cnx_id;
    picoquic_cnx_t* cnx;
    picoquic_local_cnxid_t* l_cid;
    struct st_picoquic_cnx_id_key_t* next_cnx_id;
} picoquic_cnx_id_key_t;


typedef struct master_thread_para
{
    picoquic_quic_t* quic;
    picoquic_quic_t** quic_back;
    struct hashmap_s* cnx_id_table;
    int** trans_flag;
    trans_data_master_t shared_data;
    pthread_cond_t* nonEmpty;
    pthread_mutex_t* buffer_mutex;
    int server_port;
}master_thread_para_t;

typedef struct slave_thread_para
{
    int id;
    picoquic_quic_t* quic;
    struct hashmap_s* cnx_id_table;
    int* trans_flag;
    trans_data_t shared_data;
    pthread_cond_t* nonEmpty;
    pthread_mutex_t* buffer_mutex;
    int server_port;
}slave_thread_para_t;

uint64_t picoquic_cnx_id_hash(const void* key);

int picoquic_cnx_id_compare(const void* key1, const void* key2);

#endif
