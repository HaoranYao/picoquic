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

/* Socket loop implements the "wait for messages" loop common to most servers
 * and many clients.
 *
 * Second step: support simple servers and simple client.
 *
 * The "call loop back" function is called: when ready, after receiving, and after sending. The
 * loop will terminate if the callback return code is not zero -- except for special processing
 * of the migration testing code.
 * TODO: in Windows, use WSA asynchronous calls instead of sendmsg, allowing for multiple parallel sends.
 * TODO: in Linux, use multiple send per call API
 * TDOO: trim the #define list.
 * TODO: support the QuicDoq scenario, manage extra socket.
 */

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif

#else /* Linux */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) ((long)(x))
#endif
#endif

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "picoquic_unified_log.h"

int picoquic_packet_loop_open_sockets(int local_port, int local_af, SOCKET_TYPE * s_socket, int * sock_af, int nb_sockets_max)
{
    int nb_sockets = (local_af == AF_UNSPEC) ? 2 : 1;

    /* Compute how many sockets are necessary */
    if (nb_sockets > nb_sockets_max) {
        DBG_PRINTF("Cannot open %d sockets, max set to %d\n", nb_sockets, nb_sockets_max);
        nb_sockets = 0;
    } else if (local_af == AF_UNSPEC) {
        sock_af[0] = AF_INET;
        sock_af[1] = AF_INET6;
    }
    else if (local_af == AF_INET || local_af == AF_INET6) {
        sock_af[0] = local_af;
    }
    else {
        DBG_PRINTF("Cannot open socket(AF=%d), unsupported AF\n", local_af);
        nb_sockets = 0;
    }
        // printf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC%d\n", nb_sockets);
    for (int i = 0; i < nb_sockets; i++) {
        int recv_set = 0;
        int send_set = 0;
        
        if ((s_socket[i] = socket(sock_af[i], SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET ||
            picoquic_socket_set_ecn_options(s_socket[i], sock_af[i], &recv_set, &send_set) != 0 ||
            picoquic_socket_set_pkt_info(s_socket[i], sock_af[i]) != 0 ||
            (local_port != 0 && picoquic_bind_to_port(s_socket[i], sock_af[i], local_port) != 0)) {
                
            DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", sock_af[i], local_port);
            for (int j = 0; j < i; j++) {
                if (s_socket[i] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[i]);
                    s_socket[i] = INVALID_SOCKET;
                }
            }
            nb_sockets = 0;
            break;
        }
    }
    
    return nb_sockets;
}

int picoquic_packet_loop(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    memset(sock_af, 0, sizeof(sock_af));

    if ((nb_sockets = picoquic_packet_loop_open_sockets(local_port, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    }

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    while (ret == 0) {
        int socket_rank = -1;
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        unsigned char received_ecn;

        if_index_to = 0;

        bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
            &addr_from,
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &socket_rank, &current_time);

        nb_loops++;
        if (nb_loops >= 100) {
            uint64_t loop_delta = current_time - loop_count_time;

            loop_count_time = current_time;
            DBG_PRINTF("Looped %d times in %llu microsec, file: %d, line: %d\n",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);
            picoquic_log_context_free_app_message(quic, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;
            uint16_t current_recv_port = socket_port;

            if (bytes_recv > 0) {
                /* track the local port value if not known yet */
                if (socket_port == 0 && nb_sockets == 1) {
                    struct sockaddr_storage local_address;
                    if (picoquic_get_local_address(s_socket[0], &local_address) != 0) {
                        memset(&local_address, 0, sizeof(struct sockaddr_storage));
                        fprintf(stderr, "Could not read local address.\n");
                    }
                    else if (addr_to.ss_family == AF_INET6) {
                        socket_port = ((struct sockaddr_in6*) & local_address)->sin6_port;
                    }
                    else if (addr_to.ss_family == AF_INET) {
                        socket_port = ((struct sockaddr_in*) & local_address)->sin_port;
                    }
                    current_recv_port = socket_port;
                }
                if (testing_migration) {
                    if (socket_rank == 0) {
                        current_recv_port = socket_port;
                    }
                    else {
                        current_recv_port = next_port;
                    }
                }
                /* Document incoming port */
                if (addr_to.ss_family == AF_INET6) {
                    ((struct sockaddr_in6*) & addr_to)->sin6_port = current_recv_port;
                }
                else if (addr_to.ss_family == AF_INET) {
                    ((struct sockaddr_in*) & addr_to)->sin_port = current_recv_port;
                }
                /* Submit the packet to the server */
                printf("byte is %d\n", bytes_recv);
                (void)picoquic_incoming_packet(quic, buffer,
                    (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                    (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                    current_time);

                if (loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                }
            }

            while (ret == 0) {
            
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;

                // once the migration is done call quic = quic_back
                ret = picoquic_prepare_next_packet(quic, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                /*
                
                ret = picoquic_prepare_next_packet(quic_back, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                */

                if (ret == 0 && send_length > 0) {
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    loop_count_time = current_time;
                    nb_loops = 0;
                    for (int i = 0; i < nb_sockets; i++) {
                        if (sock_af[i] == peer_addr.ss_family) {
                            send_socket = s_socket[i];
                            break;
                        }
                    }

                    if (send_socket == INVALID_SOCKET) {
                        sock_ret = -1;
                        sock_err = -1;
                    }
                    else {
                        if (testing_migration) {
                            /* This code path is only used in the migration tests */
                            uint16_t send_port = (local_addr.ss_family == AF_INET) ?
                                ((struct sockaddr_in*) & local_addr)->sin_port :
                                ((struct sockaddr_in6*) & local_addr)->sin6_port;

                            if (send_port == next_port) {
                                send_socket = s_socket[nb_sockets - 1];
                            }
                        }

                        sock_ret = picoquic_send_through_socket(send_socket,
                            (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                            (const char*)send_buffer, (int)send_length, &sock_err);
                    }

                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                            
                            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                                picoquic_notify_destination_unreachable(last_cnx, current_time,
                                    (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                                    sock_err);
                            }
                        }
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx);
            }
        }

        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            SOCKET_TYPE s_mig = INVALID_SOCKET;
            int s_mig_af;
            int sock_ret;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            
            next_port = (testing_nat) ? 0 : socket_port + 1;
            sock_ret = picoquic_packet_loop_open_sockets(next_port, sock_af[0], &s_mig, &s_mig_af, 1);
            if (sock_ret != 1 || s_mig == INVALID_SOCKET) {
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d, err=%d",
                        next_port, sock_af[0], sock_ret);
                }
            }
            else if (testing_nat) {
                if (s_socket[0] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[0]);
                }
                s_socket[0] = s_mig;
                ret = 0;
            } else {
                /* Testing organized migration */
                if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                    struct sockaddr_storage local_address;
                    picoquic_store_addr(&local_address, (struct sockaddr*)& last_cnx->path[0]->local_addr);
                    if (local_address.ss_family == AF_INET6) {
                        ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                    }
                    else if (local_address.ss_family == AF_INET) {
                        ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                    }
                    s_socket[nb_sockets] = s_mig;
                    nb_sockets++;
                    testing_migration = 1;
                    ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*)&last_cnx->path[0]->peer_addr,
                        (struct sockaddr*) &local_address, current_time);
                }
                else {
                    SOCKET_CLOSE(s_mig);
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(s_socket[i]);
            s_socket[i] = INVALID_SOCKET;
        }
    }

    return ret;
}



// int picoquic_packet_loop_with_migration_master(picoquic_quic_t* quic,
//     picoquic_quic_t* quic_back,
//     struct hashmap_s* cnx_id_table,
//     int* trans_flag,
//     int* trans_buffer,
//     // pthread_cond_t nonEmpty,
//     int local_port,
//     int local_af,
//     int dest_if,
//     picoquic_packet_loop_cb_fn loop_callback,
//     void* loop_callback_ctx)
// {



int picoquic_packet_loop_with_migration_master(picoquic_quic_t* quic,
    picoquic_quic_t* quic_back,
    struct hashmap_s* cnx_id_table,
    int* trans_flag,
    trans_data_t shared_data,
    pthread_cond_t* nonEmpty,
    pthread_mutex_t* buffer_mutex,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    int* trans_bytes = shared_data.trans_bytes;
    uint8_t* trans_buffer = shared_data.trans_buffer;
    // uint8_t* trans_send_buffer = shared_data.trans_send_buffer;
    unsigned char* trans_received_ecn = shared_data.trans_received_ecn;
    struct sockaddr_storage* trans_addr_to = shared_data.trans_addr_to;
    struct sockaddr_storage* trans_addr_from = shared_data.trans_addr_from;
    
    int* trans_if_index_to = shared_data.trans_if_index_to;
    int* trans_socket_rank = shared_data.trans_socket_rank;
    uint64_t* trans_current_time = shared_data.trans_current_time;

    struct sockaddr_storage* trans_peer_addr = shared_data.trans_peer_addr;
    struct sockaddr_storage* trans_local_addr = shared_data.trans_local_addr;
    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;


    SOCKET_TYPE* trans_s_socket = shared_data.trans_s_socket;
    int* trans_sock_af = shared_data.trans_sock_af;
    int* trans_nb_sockets = shared_data.trans_nb_sockets;

    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    memset(sock_af, 0, sizeof(sock_af));

    if ((nb_sockets = picoquic_packet_loop_open_sockets(local_port, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    }
    printf("ret is %d\n", ret);
    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    while (ret == 0) {
        int socket_rank = -1;
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        unsigned char received_ecn;

        if_index_to = 0;

        bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
            &addr_from,
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &socket_rank, &current_time);


        nb_loops++;
        if (nb_loops >= 100) {
            uint64_t loop_delta = current_time - loop_count_time;

            loop_count_time = current_time;
            DBG_PRINTF("Looped %d times in %llu microsec, file: %d, line: %d\n",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);
            picoquic_log_context_free_app_message(quic, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;
            uint16_t current_recv_port = socket_port;

            if (bytes_recv > 0) {
                /* track the local port value if not known yet */
                if (socket_port == 0 && nb_sockets == 1) {
                    struct sockaddr_storage local_address;
                    if (picoquic_get_local_address(s_socket[0], &local_address) != 0) {
                        memset(&local_address, 0, sizeof(struct sockaddr_storage));
                        fprintf(stderr, "Could not read local address.\n");
                    }
                    else if (addr_to.ss_family == AF_INET6) {
                        socket_port = ((struct sockaddr_in6*) & local_address)->sin6_port;
                    }
                    else if (addr_to.ss_family == AF_INET) {
                        socket_port = ((struct sockaddr_in*) & local_address)->sin_port;
                    }
                    current_recv_port = socket_port;
                }
                if (testing_migration) {
                    if (socket_rank == 0) {
                        current_recv_port = socket_port;
                    }
                    else {
                        current_recv_port = next_port;
                    }
                }
                /* Document incoming port */
                if (addr_to.ss_family == AF_INET6) {
                    ((struct sockaddr_in6*) & addr_to)->sin6_port = current_recv_port;
                }
                else if (addr_to.ss_family == AF_INET) {
                    ((struct sockaddr_in*) & addr_to)->sin_port = current_recv_port;
                }


                // before the incoming packet function we need to check the packet.
                // if the src port is in the hashmap we need to just continue

                char key[128];
                picoquic_cnx_t * connection_to_migrate = quic->cnx_list;
                if ((quic->cnx_list) != NULL && quic->cnx_list->callback_ctx!=NULL) {
                    if (((sample_server_migration_ctx_t *) (quic->cnx_list->callback_ctx))->migration_flag){
                        printf("migrated to the back-up server!!\n");
                        ((sample_server_migration_ctx_t *) (quic->cnx_list->callback_ctx))->migration_flag = 0;
                    // current_time = picoquic_get_quic_time(quic_back);
                    // loop_time = current_time;
                    // quic_back->cnx_list->next_wake_time = loop_time;
                    picoquic_shallow_migrate(quic, quic_back);
                    
                    // uint64_t key = picoquic_connection_id_hash(&connection_to_migrate->local_cnxid_first->cnx_id);
                    // char* string_key = uint64_to_string(key); 
                    picoquic_addr_text((struct sockaddr *)&connection_to_migrate->path[0]->peer_addr, key, sizeof(key));
                    printf("###################################################\n");
                    printf("%s\n",key);
                    if (cnx_id_table != NULL) {
                        printf("Add this migration connection to the hashmap!\n");
                        hashmap_put(cnx_id_table, key, strlen(key), "2");
                    } else {
                        printf("table is NULL\n");
                    }
                    printf("change quic!!!!!!!!!!!!!!!!!!!!!!!!!!!1\n");
                    *trans_flag =1;
                    // quic = quic_back;
                }
                }

                // char test_addr[128];
                // struct sockaddr * addr = (malloc(sizeof(struct sockaddr)));




            // void* const element = hashmap_get(cnx_id_table, key, strlen(key));
            // if (NULL == element) {
            //     // printf("NEW CONNECTION FIND! Set the trans_flag to 1\n");
            //     printf("Cant find the connection! Process the packet by myself!\n");
                
            //     // hashmap_put(cnx_id_table, string_key, strlen(string_key), "2");
            // } else {
            //     printf("FIND the connection in hashmap, set trans_flag to 1!\n");
            //     *trans_flag = 1;
            // }


                // check whether it belongs to this server
                if (hashmap_get(cnx_id_table, key, strlen(key)) != NULL) {
                    // trans_flag value is 1. We need to send this packet to the backup server.
                    printf("trans_flag is 1, set the trans_buffer!\n");
                    printf("size of buffer is %ld\n", sizeof(buffer));
                    pthread_mutex_lock(buffer_mutex);
                    *trans_bytes = bytes_recv;
                    *trans_received_ecn = received_ecn;
                    *trans_current_time = current_time;
                    *trans_socket_rank = socket_rank;
                    *trans_if_index_to = if_index_to;
                    memcpy(trans_addr_to, &addr_to, sizeof(struct sockaddr_storage));
                    memcpy(trans_addr_from, &addr_from, sizeof(struct sockaddr_storage));
                    memcpy(trans_peer_addr, &peer_addr, sizeof(struct sockaddr_storage));
                    memcpy(trans_local_addr, &local_addr, sizeof(struct sockaddr_storage));
                    memcpy(trans_sock_af, sock_af, sizeof(sock_af));
                    memcpy(trans_s_socket, s_socket, sizeof(s_socket));
                    *trans_nb_sockets = nb_sockets;
                    memcpy(trans_buffer, buffer, sizeof(buffer));
                    // memcpy(trans_send_buffer, send_buffer, sizeof(send_buffer));
                    // then trigger the backup thread and return.
                    pthread_cond_signal(nonEmpty);
                    pthread_mutex_unlock(buffer_mutex);
                    continue;
                }
                /* Submit the packet to the server */
                // set the migration flag in this function
                // ret = picoquic_incoming_packet_master(quic, cnx_id_table, trans_flag, buffer,
                //     (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                //     (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                //     current_time);
                ret = picoquic_incoming_packet(quic, buffer,
                (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                current_time);

                // TODO: if migrated has happened, send it to the target server.
                // 1. check the hashmap
                // 2. if the connection is in this hashmap, then it should send it to the target server. So, set trans_flag to 1 and return.
                // 3. if the connection is not in this map, continue to use this flag

                
                if (loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                }
            }

            while (ret == 0) {
            
                
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;
                // printf("migration flag in loop is%d\n",*migration_flag);
                                // printf("size of send_buffer is %ld", sizeof(send_buffer));
                // once the migration is done call quic = quic_back
                ret = picoquic_prepare_next_packet(quic, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);
                    printf("MASTER THREAD send length is %ld\n ", send_length);
                
                /*
                
                ret = picoquic_prepare_next_packet(quic_back, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                */

                if (ret == 0 && send_length > 0) {
                    // printf("send packet!\n");
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    loop_count_time = current_time;
                    nb_loops = 0;
                    for (int i = 0; i < nb_sockets; i++) {
                        if (sock_af[i] == peer_addr.ss_family) {
                            send_socket = s_socket[i];
                            break;
                        }
                    }

                    if (send_socket == INVALID_SOCKET) {
                        // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        sock_ret = -1;
                        sock_err = -1;
                    }
                    else {
                        if (testing_migration) {
                            /* This code path is only used in the migration tests */
                            uint16_t send_port = (local_addr.ss_family == AF_INET) ?
                                ((struct sockaddr_in*) & local_addr)->sin_port :
                                ((struct sockaddr_in6*) & local_addr)->sin6_port;

                            if (send_port == next_port) {
                                send_socket = s_socket[nb_sockets - 1];
                            }
                        }

                        sock_ret = picoquic_send_through_socket(send_socket,
                            (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                            (const char*)send_buffer, (int)send_length, &sock_err);
                        // printf("sock_ret is %d\n", sock_ret);
                    }

                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                            
                            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                                picoquic_notify_destination_unreachable(last_cnx, current_time,
                                    (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                                    sock_err);
                            }
                        }
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx);
            }
        }

        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            SOCKET_TYPE s_mig = INVALID_SOCKET;
            int s_mig_af;
            int sock_ret;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            
            next_port = (testing_nat) ? 0 : socket_port + 1;
            sock_ret = picoquic_packet_loop_open_sockets(next_port, sock_af[0], &s_mig, &s_mig_af, 1);
            if (sock_ret != 1 || s_mig == INVALID_SOCKET) {
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d, err=%d",
                        next_port, sock_af[0], sock_ret);
                }
            }
            else if (testing_nat) {
                if (s_socket[0] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[0]);
                }
                s_socket[0] = s_mig;
                ret = 0;
            } else {
                /* Testing organized migration */
                if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                    struct sockaddr_storage local_address;
                    picoquic_store_addr(&local_address, (struct sockaddr*)& last_cnx->path[0]->local_addr);
                    if (local_address.ss_family == AF_INET6) {
                        ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                    }
                    else if (local_address.ss_family == AF_INET) {
                        ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                    }
                    s_socket[nb_sockets] = s_mig;
                    nb_sockets++;
                    testing_migration = 1;
                    ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*)&last_cnx->path[0]->peer_addr,
                        (struct sockaddr*) &local_address, current_time);
                }
                else {
                    SOCKET_CLOSE(s_mig);
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(s_socket[i]);
            s_socket[i] = INVALID_SOCKET;
        }
    }

    return ret;
}


int picoquic_packet_loop_with_migration_slave(picoquic_quic_t* quic,
    // picoquic_quic_t* quic_back,
    struct hashmap_s* cnx_id_table,
    int* trans_flag,
    trans_data_t shared_data,
    pthread_cond_t* nonEmpty,
    pthread_mutex_t* buffer_mutex,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{

    int* trans_bytes = shared_data.trans_bytes;
    uint8_t* trans_buffer = shared_data.trans_buffer;
    // uint8_t* trans_send_buffer = shared_data.trans_send_buffer;
    unsigned char* trans_received_ecn = shared_data.trans_received_ecn;
    struct sockaddr_storage* trans_addr_to = shared_data.trans_addr_to;
    struct sockaddr_storage* trans_addr_from = shared_data.trans_addr_from;
    int* trans_if_index_to = shared_data.trans_if_index_to;
    int* trans_socket_rank = shared_data.trans_socket_rank;
    uint64_t* trans_current_time = shared_data.trans_current_time;
    struct sockaddr_storage* trans_peer_addr = shared_data.trans_peer_addr;
    struct sockaddr_storage* trans_local_addr = shared_data.trans_local_addr;

    SOCKET_TYPE* trans_s_socket = shared_data.trans_s_socket;
    int* trans_sock_af = shared_data.trans_sock_af;
    int* trans_nb_sockets = shared_data.trans_nb_sockets;

    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;

    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    // int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;

    picoquic_connection_id_t log_cid;

    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;

    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    memset(sock_af, 0, sizeof(sock_af));

    // if ((nb_sockets = picoquic_packet_loop_open_sockets(local_port+1, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
    //     ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    // }
    // else if (loop_callback != NULL) {
    //     ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    // }

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    while (ret == 0) {
        int socket_rank = -1;
        // int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);

        // bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
        //     &addr_from,
        //     &addr_to, &if_index_to, &received_ecn,
        //     buffer, sizeof(buffer),
        //     delta_t, &socket_rank, &current_time);
        // wait the bytes from the master thread
        pthread_mutex_lock(buffer_mutex);
        pthread_cond_wait(nonEmpty, buffer_mutex);
        unsigned char received_ecn = *trans_received_ecn;
        bytes_recv = *trans_bytes;
        if_index_to = *trans_if_index_to;
        socket_rank = *trans_socket_rank;
        current_time = *trans_current_time;
        memcpy(&addr_to, trans_addr_to, sizeof(struct sockaddr_storage));
        memcpy(&addr_from, trans_addr_from, sizeof(struct sockaddr_storage));
        memcpy(&peer_addr, trans_peer_addr, sizeof(struct sockaddr_storage));
        memcpy(&local_addr, trans_local_addr, sizeof(struct sockaddr_storage));
        memcpy(buffer, trans_buffer, sizeof(buffer));
        memcpy(sock_af, trans_sock_af, sizeof(sock_af));
        memcpy(s_socket, trans_s_socket, sizeof(s_socket));
        nb_sockets = *trans_nb_sockets;
        // memcpy(send_buffer, trans_send_buffer, sizeof(send_buffer));
        pthread_mutex_unlock(buffer_mutex);
        printf("slave thread receive packet!\n");

        nb_loops++;
        if (nb_loops >= 100) {
            uint64_t loop_delta = current_time - loop_count_time;

            loop_count_time = current_time;
            DBG_PRINTF("Looped %d times in %llu microsec, file: %d, line: %d\n",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);
            picoquic_log_context_free_app_message(quic, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;
            uint16_t current_recv_port = socket_port;

            if (bytes_recv > 0) {
                printf("GOOOOOOOOOOOOOOOOOOOOOOOOOOOO\n");
                /* track the local port value if not known yet */
                if (socket_port == 0 && nb_sockets == 1) {
                    struct sockaddr_storage local_address;
                    if (picoquic_get_local_address(s_socket[0], &local_address) != 0) {
                        memset(&local_address, 0, sizeof(struct sockaddr_storage));
                        fprintf(stderr, "Could not read local address.\n");
                    }
                    else if (addr_to.ss_family == AF_INET6) {
                        socket_port = ((struct sockaddr_in6*) & local_address)->sin6_port;
                    }
                    else if (addr_to.ss_family == AF_INET) {
                        socket_port = ((struct sockaddr_in*) & local_address)->sin_port;
                    }
                    current_recv_port = socket_port;
                }
                if (testing_migration) {
                    if (socket_rank == 0) {
                        current_recv_port = socket_port;
                    }
                    else {
                        current_recv_port = next_port;
                    }
                }
                /* Document incoming port */
                if (addr_to.ss_family == AF_INET6) {
                    ((struct sockaddr_in6*) & addr_to)->sin6_port = current_recv_port;
                }
                else if (addr_to.ss_family == AF_INET) {
                    ((struct sockaddr_in*) & addr_to)->sin_port = current_recv_port;
                }
                /* Submit the packet to the server */
                // set the migration flag in this function

                ret = picoquic_incoming_packet(quic, buffer,
                (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                current_time);
                // printf("RET SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS %d", ret);
                // TODO: if migrated has happened, send it to the target server.
                // 1. check the hashmap
                // 2. if the connection is in this hashmap, then it should send it to the target server. So, set trans_flag to 1 and return.
                // 3. if the connection is not in this map, continue to use this flag
                // if (*trans_flag == 1) {
                //     // trans_flag value is 1. We need to send this packet to the backup server.
                //     printf("trans_flag is 1, set the trans_buffer!\n");
                //     *trans_buffer = bytes_recv;
                //     // then trigger the backup thread and return.
                //     pthread_cond_signal(&nonEmpty);
                //     return ret;
                // }
                
                if (loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                }
            }

            while (ret == 0) {
            
                // struct sockaddr_storage peer_addr;
                // struct sockaddr_storage local_addr;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;
                // last_cnx = quic->cnx_list;
                // picoquic_cnx_t * connection_to_migrate = quic->cnx_list;
                // if ((quic->cnx_list) != NULL && quic->cnx_list->callback_ctx!=NULL) {
                //     if (((sample_server_migration_ctx_t *) (quic->cnx_list->callback_ctx))->migration_flag){
                //         printf("migrated to the back-up server!!\n");
                //         ((sample_server_migration_ctx_t *) (quic->cnx_list->callback_ctx))->migration_flag = 0;
                //     // current_time = picoquic_get_quic_time(quic_back);
                //     // loop_time = current_time;
                //     // quic_back->cnx_list->next_wake_time = loop_time;
                //     // picoquic_shallow_migrate(quic, quic_back);
                //     // TODO: change the hashmap
                //     // set the migration flag
                //     // return a value
                //     // let the back server continue to send
                //     uint64_t key = picoquic_connection_id_hash(&connection_to_migrate->local_cnxid_first->cnx_id);
                //     char* string_key = uint64_to_string(key); 
                //     if (cnx_id_table != NULL) {
                //         printf("Add this migration connection to the hashmap!\n");
                //         hashmap_put(cnx_id_table, string_key, strlen(string_key), "2");
                //     } else {
                //         printf("table is NULL\n");
                //     }
                //     quic = quic_back;
                // }
                // }
                // printf("migration flag in loop is%d\n",*migration_flag);
                
                // once the migration is done call quic = quic_back

                printf("SLAVE SEND PACKET!!!!!!!!\n");
                ret = picoquic_prepare_next_packet(quic, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);
                
                printf("SLAVE THREAD send length is %ld\n", send_length);

                /*
                
                ret = picoquic_prepare_next_packet(quic_back, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                */

                if (ret == 0 && send_length > 0) {
                    // printf("send packet!\n");
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    loop_count_time = current_time;
                    nb_loops = 0;
                    for (int i = 0; i < nb_sockets; i++) {
                        if (sock_af[i] == peer_addr.ss_family) {
                            send_socket = s_socket[i];
                            break;
                        }
                    }

                    if (send_socket == INVALID_SOCKET) {
                        // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        sock_ret = -1;
                        sock_err = -1;
                    }
                    else {
                        if (testing_migration) {
                            /* This code path is only used in the migration tests */
                            uint16_t send_port = (local_addr.ss_family == AF_INET) ?
                                ((struct sockaddr_in*) & local_addr)->sin_port :
                                ((struct sockaddr_in6*) & local_addr)->sin6_port;

                            if (send_port == next_port) {
                                send_socket = s_socket[nb_sockets - 1];
                            }
                        }

                        sock_ret = picoquic_send_through_socket(send_socket,
                            (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                            (const char*)send_buffer, (int)send_length, &sock_err);
                        // printf("sock_ret is %d\n", sock_ret);
                    }

                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                            
                            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                                picoquic_notify_destination_unreachable(last_cnx, current_time,
                                    (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                                    sock_err);
                            }
                        }
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx);
            }
        }

        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            SOCKET_TYPE s_mig = INVALID_SOCKET;
            int s_mig_af;
            int sock_ret;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            
            next_port = (testing_nat) ? 0 : socket_port + 1;
            sock_ret = picoquic_packet_loop_open_sockets(next_port, sock_af[0], &s_mig, &s_mig_af, 1);
            if (sock_ret != 1 || s_mig == INVALID_SOCKET) {
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d, err=%d",
                        next_port, sock_af[0], sock_ret);
                }
            }
            else if (testing_nat) {
                if (s_socket[0] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[0]);
                }
                s_socket[0] = s_mig;
                ret = 0;
            } else {
                /* Testing organized migration */
                if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                    struct sockaddr_storage local_address;
                    picoquic_store_addr(&local_address, (struct sockaddr*)& last_cnx->path[0]->local_addr);
                    if (local_address.ss_family == AF_INET6) {
                        ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                    }
                    else if (local_address.ss_family == AF_INET) {
                        ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                    }
                    s_socket[nb_sockets] = s_mig;
                    nb_sockets++;
                    testing_migration = 1;
                    ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*)&last_cnx->path[0]->peer_addr,
                        (struct sockaddr*) &local_address, current_time);
                }
                else {
                    SOCKET_CLOSE(s_mig);
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(s_socket[i]);
            s_socket[i] = INVALID_SOCKET;
        }
    }

    return ret;
}


int picoquic_packet_loop_with_migration(picoquic_quic_t* quic,
    picoquic_quic_t* quic_back,
    int* migration_flag,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    memset(sock_af, 0, sizeof(sock_af));

    if ((nb_sockets = picoquic_packet_loop_open_sockets(local_port, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    }

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    while (ret == 0) {
        int socket_rank = -1;
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        unsigned char received_ecn;

        if_index_to = 0;

        bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
            &addr_from,
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &socket_rank, &current_time);


        nb_loops++;
        if (nb_loops >= 100) {
            uint64_t loop_delta = current_time - loop_count_time;

            loop_count_time = current_time;
            DBG_PRINTF("Looped %d times in %llu microsec, file: %d, line: %d\n",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);
            picoquic_log_context_free_app_message(quic, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;
            uint16_t current_recv_port = socket_port;

            if (bytes_recv > 0) {
                /* track the local port value if not known yet */
                if (socket_port == 0 && nb_sockets == 1) {
                    struct sockaddr_storage local_address;
                    if (picoquic_get_local_address(s_socket[0], &local_address) != 0) {
                        memset(&local_address, 0, sizeof(struct sockaddr_storage));
                        fprintf(stderr, "Could not read local address.\n");
                    }
                    else if (addr_to.ss_family == AF_INET6) {
                        socket_port = ((struct sockaddr_in6*) & local_address)->sin6_port;
                    }
                    else if (addr_to.ss_family == AF_INET) {
                        socket_port = ((struct sockaddr_in*) & local_address)->sin_port;
                    }
                    current_recv_port = socket_port;
                }
                if (testing_migration) {
                    if (socket_rank == 0) {
                        current_recv_port = socket_port;
                    }
                    else {
                        current_recv_port = next_port;
                    }
                }
                /* Document incoming port */
                if (addr_to.ss_family == AF_INET6) {
                    ((struct sockaddr_in6*) & addr_to)->sin6_port = current_recv_port;
                }
                else if (addr_to.ss_family == AF_INET) {
                    ((struct sockaddr_in*) & addr_to)->sin_port = current_recv_port;
                }
                /* Submit the packet to the server */
                ret = picoquic_incoming_packet(quic, buffer,
                    (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                    (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                    current_time);

                // with and without migration
                // printf("picoquic_incoming_packet reture %d\n", ret);

                if (loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                }
            }

            while (ret == 0) {
            
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;
                if ((quic->cnx_list) != NULL && quic->cnx_list->callback_ctx!=NULL) {
                    if (((sample_server_migration_ctx_t *) (quic->cnx_list->callback_ctx))->migration_flag){
                        printf("migrated to the back-up server!!\n");
                        ((sample_server_migration_ctx_t *) (quic->cnx_list->callback_ctx))->migration_flag = 0;
                    // current_time = picoquic_get_quic_time(quic_back);
                    // loop_time = current_time;
                    // quic_back->cnx_list->next_wake_time = loop_time;
                    picoquic_shallow_migrate(quic, quic_back);
                    // quic_back->cnx_list->next_wake_time = loop_time;
                    // quic_back-> cnx_list = quic->cnx_list;
                    // quic_back->cnx_last = quic->cnx_last;
                    // last_cnx = quic->cnx_list;
                    quic = quic_back;
                }
                }
                // printf("migration flag in loop is%d\n",*migration_flag);
                
                // once the migration is done call quic = quic_back
                ret = picoquic_prepare_next_packet(quic, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                /*
                
                ret = picoquic_prepare_next_packet(quic_back, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                */

                if (ret == 0 && send_length > 0) {
                    // printf("send packet!\n");
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    loop_count_time = current_time;
                    nb_loops = 0;
                    for (int i = 0; i < nb_sockets; i++) {
                        if (sock_af[i] == peer_addr.ss_family) {
                            send_socket = s_socket[i];
                            break;
                        }
                    }

                    if (send_socket == INVALID_SOCKET) {
                        // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                        sock_ret = -1;
                        sock_err = -1;
                    }
                    else {
                        if (testing_migration) {
                            /* This code path is only used in the migration tests */
                            uint16_t send_port = (local_addr.ss_family == AF_INET) ?
                                ((struct sockaddr_in*) & local_addr)->sin_port :
                                ((struct sockaddr_in6*) & local_addr)->sin6_port;

                            if (send_port == next_port) {
                                send_socket = s_socket[nb_sockets - 1];
                            }
                        }

                        sock_ret = picoquic_send_through_socket(send_socket,
                            (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                            (const char*)send_buffer, (int)send_length, &sock_err);
                        // printf("sock_ret is %d\n", sock_ret);
                    }

                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                            
                            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                                picoquic_notify_destination_unreachable(last_cnx, current_time,
                                    (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                                    sock_err);
                            }
                        }
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx);
            }
        }

        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            SOCKET_TYPE s_mig = INVALID_SOCKET;
            int s_mig_af;
            int sock_ret;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            
            next_port = (testing_nat) ? 0 : socket_port + 1;
            sock_ret = picoquic_packet_loop_open_sockets(next_port, sock_af[0], &s_mig, &s_mig_af, 1);
            if (sock_ret != 1 || s_mig == INVALID_SOCKET) {
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d, err=%d",
                        next_port, sock_af[0], sock_ret);
                }
            }
            else if (testing_nat) {
                if (s_socket[0] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[0]);
                }
                s_socket[0] = s_mig;
                ret = 0;
            } else {
                /* Testing organized migration */
                if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                    struct sockaddr_storage local_address;
                    picoquic_store_addr(&local_address, (struct sockaddr*)& last_cnx->path[0]->local_addr);
                    if (local_address.ss_family == AF_INET6) {
                        ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                    }
                    else if (local_address.ss_family == AF_INET) {
                        ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                    }
                    s_socket[nb_sockets] = s_mig;
                    nb_sockets++;
                    testing_migration = 1;
                    ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*)&last_cnx->path[0]->peer_addr,
                        (struct sockaddr*) &local_address, current_time);
                }
                else {
                    SOCKET_CLOSE(s_mig);
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(s_socket[i]);
            s_socket[i] = INVALID_SOCKET;
        }
    }

    return ret;
}

int picoquic_packet_loop_test_migration(picoquic_quic_t* quic,
    picoquic_quic_t* quic_new,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;



    // test_count is only used for the migration testing.
    int test_count = 0;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    memset(sock_af, 0, sizeof(sock_af));

    if ((nb_sockets = picoquic_packet_loop_open_sockets(local_port, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    }

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    while (ret == 0) {
        int socket_rank = -1;
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        unsigned char received_ecn;

        if_index_to = 0;

        bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
            &addr_from,
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &socket_rank, &current_time);

        nb_loops++;
        if (nb_loops >= 100) {
            uint64_t loop_delta = current_time - loop_count_time;

            loop_count_time = current_time;
            DBG_PRINTF("Looped %d times in %llu microsec, file: %d, line: %d\n",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);
            picoquic_log_context_free_app_message(quic, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;
            uint16_t current_recv_port = socket_port;

            if (bytes_recv > 0) {
                /* track the local port value if not known yet */
                if (socket_port == 0 && nb_sockets == 1) {
                    struct sockaddr_storage local_address;
                    if (picoquic_get_local_address(s_socket[0], &local_address) != 0) {
                        memset(&local_address, 0, sizeof(struct sockaddr_storage));
                        fprintf(stderr, "Could not read local address.\n");
                    }
                    else if (addr_to.ss_family == AF_INET6) {
                        socket_port = ((struct sockaddr_in6*) & local_address)->sin6_port;
                    }
                    else if (addr_to.ss_family == AF_INET) {
                        socket_port = ((struct sockaddr_in*) & local_address)->sin_port;
                    }
                    current_recv_port = socket_port;
                }
                if (testing_migration) {
                    if (socket_rank == 0) {
                        current_recv_port = socket_port;
                    }
                    else {
                        current_recv_port = next_port;
                    }
                }
                /* Document incoming port */
                if (addr_to.ss_family == AF_INET6) {
                    ((struct sockaddr_in6*) & addr_to)->sin6_port = current_recv_port;
                }
                else if (addr_to.ss_family == AF_INET) {
                    ((struct sockaddr_in*) & addr_to)->sin_port = current_recv_port;
                }
                /* Submit the packet to the server */
                (void)picoquic_incoming_packet(quic, buffer,
                    (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                    (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                    current_time);

                if (loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                }
            }

            while (ret == 0) {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;

                test_count++;
                if (test_count == 100) {
                    picoquic_migrate(quic, quic_new);
                }
                ret = picoquic_prepare_next_packet(quic, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                if (ret == 0 && send_length > 0) {
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    loop_count_time = current_time;
                    nb_loops = 0;
                    for (int i = 0; i < nb_sockets; i++) {
                        if (sock_af[i] == peer_addr.ss_family) {
                            send_socket = s_socket[i];
                            break;
                        }
                    }

                    if (send_socket == INVALID_SOCKET) {
                        sock_ret = -1;
                        sock_err = -1;
                    }
                    else {
                        if (testing_migration) {
                            /* This code path is only used in the migration tests */
                            uint16_t send_port = (local_addr.ss_family == AF_INET) ?
                                ((struct sockaddr_in*) & local_addr)->sin_port :
                                ((struct sockaddr_in6*) & local_addr)->sin6_port;

                            if (send_port == next_port) {
                                send_socket = s_socket[nb_sockets - 1];
                            }
                        }

                        sock_ret = picoquic_send_through_socket(send_socket,
                            (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                            (const char*)send_buffer, (int)send_length, &sock_err);
                    }

                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                            
                            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                                picoquic_notify_destination_unreachable(last_cnx, current_time,
                                    (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                                    sock_err);
                            }
                        }
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx);
            }
        }

        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            SOCKET_TYPE s_mig = INVALID_SOCKET;
            int s_mig_af;
            int sock_ret;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            
            next_port = (testing_nat) ? 0 : socket_port + 1;
            sock_ret = picoquic_packet_loop_open_sockets(next_port, sock_af[0], &s_mig, &s_mig_af, 1);
            if (sock_ret != 1 || s_mig == INVALID_SOCKET) {
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d, err=%d",
                        next_port, sock_af[0], sock_ret);
                }
            }
            else if (testing_nat) {
                if (s_socket[0] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[0]);
                }
                s_socket[0] = s_mig;
                ret = 0;
            } else {
                /* Testing organized migration */
                if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                    struct sockaddr_storage local_address;
                    picoquic_store_addr(&local_address, (struct sockaddr*)& last_cnx->path[0]->local_addr);
                    if (local_address.ss_family == AF_INET6) {
                        ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                    }
                    else if (local_address.ss_family == AF_INET) {
                        ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                    }
                    s_socket[nb_sockets] = s_mig;
                    nb_sockets++;
                    testing_migration = 1;
                    ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*)&last_cnx->path[0]->peer_addr,
                        (struct sockaddr*) &local_address, current_time);
                }
                else {
                    SOCKET_CLOSE(s_mig);
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(s_socket[i]);
            s_socket[i] = INVALID_SOCKET;
        }
    }

    return ret;
}