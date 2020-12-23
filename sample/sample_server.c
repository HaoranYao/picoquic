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

/* The "sample" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The "sample_server" implements
 * the server components of the sample application. 
 *
 * Developing the server requires two main components:
 *  - the server "callback" that implements the server side of the
 *    application protocol, managing a server side application context
 *    for each connection.
 *  - the server loop, that reads messages on the socket, submits them
 *    to the Quic context, let the server prepare messages, and send
 *    them on the appropriate socket.
 *
 * The Sample Server uses the "qlog" option to produce Quic Logs as defined
 * in https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/.
 * This is an optional feature, which requires linking with the "loglib" library,
 * and using the picoquic_set_qlog() API defined in "autoqlog.h". . When a connection
 * completes, the code saves the log as a file named after the Initial Connection
 * ID (in hexa), with the suffix ".server.qlog".
 */

#include "picoquic_sample.h"


/* Server context and callback management:
 *
 * The server side application context is created for each new connection,
 * and is freed when the connection is closed. It contains a list of
 * server side stream contexts, one for each stream open on the
 * connection. Each stream context includes:
 *  - description of the stream state:
 *      name_read or not, FILE open or not, stream reset or not,
 *      stream finished or not.
 *  - the number of file name bytes already read.
 *  - the name of the file requested by the client.
 *  - the FILE pointer for reading the data.
 * Server side stream context is created when the client starts the
 * stream. It is closed when the file transmission
 * is finished, or when the stream is abandoned.
 *
 * The server side callback is a large switch statement, with one entry
 * for each of the call back events.
 */

// pthread_cond_t full  = PTHREAD_COND_INITIALIZER;
sample_server_stream_ctx_t * sample_server_create_stream_context(sample_server_ctx_t* server_ctx, uint64_t stream_id)
{
    sample_server_stream_ctx_t* stream_ctx = (sample_server_stream_ctx_t*)malloc(sizeof(sample_server_stream_ctx_t));

    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(sample_server_stream_ctx_t));

        if (server_ctx->last_stream == NULL) {
            server_ctx->last_stream = stream_ctx;
            server_ctx->first_stream = stream_ctx;
        }
        else {
            stream_ctx->previous_stream = server_ctx->last_stream;
            server_ctx->last_stream->next_stream = stream_ctx;
            server_ctx->last_stream = stream_ctx;
        }
        stream_ctx->stream_id = stream_id;
    }

    return stream_ctx;
}

sample_server_stream_ctx_t * sample_server_create_stream_context_for_migration(sample_server_migration_ctx_t* server_ctx, uint64_t stream_id)
{
    sample_server_stream_ctx_t* stream_ctx = (sample_server_stream_ctx_t*)malloc(sizeof(sample_server_stream_ctx_t));

    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(sample_server_stream_ctx_t));

        if (server_ctx->last_stream == NULL) {
            server_ctx->last_stream = stream_ctx;
            server_ctx->first_stream = stream_ctx;
        }
        else {
            stream_ctx->previous_stream = server_ctx->last_stream;
            server_ctx->last_stream->next_stream = stream_ctx;
            server_ctx->last_stream = stream_ctx;
        }
        stream_ctx->stream_id = stream_id;
    }

    return stream_ctx;
}

int sample_server_open_stream(sample_server_ctx_t* server_ctx, sample_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    char file_path[1024];

    /* Keep track that the full file name was acquired. */
    stream_ctx->is_name_read = 1;

    /* Verify the name, then try to open the file */
    if (server_ctx->default_dir_len + stream_ctx->name_length + 1 > sizeof(file_path)) {
        ret = PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR;
    }
    else {
        /* Verify that the default path is empty of terminates with "/" or "\" depending on OS,
         * and format the file path */
        size_t dir_len = server_ctx->default_dir_len;
        if (dir_len > 0) {
            memcpy(file_path, server_ctx->default_dir, dir_len);
            if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0]) {
                file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                dir_len++;
            }
        }
        memcpy(file_path + dir_len, stream_ctx->file_name, stream_ctx->name_length);
        file_path[dir_len + stream_ctx->name_length] = 0;

        /* Use the picoquic_file_open API for portability to Windows and Linux */
        stream_ctx->F = picoquic_file_open(file_path, "rb");

        if (stream_ctx->F == NULL) {
            ret = PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR;
        }
        else {
            /* Assess the file size, as this is useful for data planning */
            long sz;
            fseek(stream_ctx->F, 0, SEEK_END);
            sz = ftell(stream_ctx->F);

            if (sz <= 0) {
                stream_ctx->F = picoquic_file_close(stream_ctx->F);
                ret = PICOQUIC_SAMPLE_FILE_READ_ERROR;
            }
            else {
                stream_ctx->file_length = (size_t)sz;
                fseek(stream_ctx->F, 0, SEEK_SET);
                ret = 0;
            }
        }
    }

    return ret;
}

int sample_server_open_stream_for_migration(sample_server_migration_ctx_t* server_ctx, sample_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    char file_path[1024];

    /* Keep track that the full file name was acquired. */
    stream_ctx->is_name_read = 1;

    /* Verify the name, then try to open the file */
    if (server_ctx->default_dir_len + stream_ctx->name_length + 1 > sizeof(file_path)) {
        ret = PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR;
    }
    else {
        /* Verify that the default path is empty of terminates with "/" or "\" depending on OS,
         * and format the file path */
        size_t dir_len = server_ctx->default_dir_len;
        if (dir_len > 0) {
            memcpy(file_path, server_ctx->default_dir, dir_len);
            if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0]) {
                file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                dir_len++;
            }
        }
        memcpy(file_path + dir_len, stream_ctx->file_name, stream_ctx->name_length);
        file_path[dir_len + stream_ctx->name_length] = 0;

        /* Use the picoquic_file_open API for portability to Windows and Linux */
        stream_ctx->F = picoquic_file_open(file_path, "rb");

        if (stream_ctx->F == NULL) {
            ret = PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR;
        }
        else {
            /* Assess the file size, as this is useful for data planning */
            long sz;
            fseek(stream_ctx->F, 0, SEEK_END);
            sz = ftell(stream_ctx->F);

            if (sz <= 0) {
                stream_ctx->F = picoquic_file_close(stream_ctx->F);
                ret = PICOQUIC_SAMPLE_FILE_READ_ERROR;
            }
            else {
                stream_ctx->file_length = (size_t)sz;
                fseek(stream_ctx->F, 0, SEEK_SET);
                ret = 0;
            }
        }
    }

    return ret;
}

uint64_t picoquic_cnx_id_hash(const void* key)
{
    const picoquic_cnx_id_key_t* cid = (const picoquic_cnx_id_key_t*)key;
    return picoquic_connection_id_hash(&cid->cnx_id);
}

int picoquic_cnx_id_compare(const void* key1, const void* key2)
{
    const picoquic_cnx_id_key_t* cid1 = (const picoquic_cnx_id_key_t*)key1;
    const picoquic_cnx_id_key_t* cid2 = (const picoquic_cnx_id_key_t*)key2;

    return picoquic_compare_connection_id(&cid1->cnx_id, &cid2->cnx_id);
}

void sample_server_delete_stream_context(sample_server_ctx_t* server_ctx, sample_server_stream_ctx_t* stream_ctx)
{
    /* Close the file if it was open */
    if (stream_ctx->F != NULL) {
        stream_ctx->F = picoquic_file_close(stream_ctx->F);
    }

    /* Remove the context from the server's list */
    if (stream_ctx->previous_stream == NULL) {
        server_ctx->first_stream = stream_ctx->next_stream;
    }
    else {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }

    if (stream_ctx->next_stream == NULL) {
        server_ctx->last_stream = stream_ctx->previous_stream;
    }
    else {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }

    /* release the memory */
    free(stream_ctx);
}

void sample_server_delete_stream_context_for_migration(sample_server_migration_ctx_t* server_ctx, sample_server_stream_ctx_t* stream_ctx)
{
    /* Close the file if it was open */
    if (stream_ctx->F != NULL) {
        stream_ctx->F = picoquic_file_close(stream_ctx->F);
    }

    /* Remove the context from the server's list */
    if (stream_ctx->previous_stream == NULL) {
        server_ctx->first_stream = stream_ctx->next_stream;
    }
    else {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }

    if (stream_ctx->next_stream == NULL) {
        server_ctx->last_stream = stream_ctx->previous_stream;
    }
    else {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }

    /* release the memory */
    free(stream_ctx);
}

void sample_server_delete_context(sample_server_ctx_t* server_ctx)
{
    /* Delete any remaining stream context */
    while (server_ctx->first_stream != NULL) {
        sample_server_delete_stream_context(server_ctx, server_ctx->first_stream);
    }

    /* release the memory */
    free(server_ctx);
}

void sample_server_delete_context_for_migration(sample_server_migration_ctx_t* server_ctx)
{
    /* Delete any remaining stream context */
    while (server_ctx->first_stream != NULL) {
        sample_server_delete_stream_context_for_migration(server_ctx, server_ctx->first_stream);
    }

    /* release the memory */
    free(server_ctx);
}

int sample_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    sample_server_ctx_t* server_ctx = (sample_server_ctx_t*)callback_ctx;
    sample_server_stream_ctx_t* stream_ctx = (sample_server_stream_ctx_t*)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        server_ctx = (sample_server_ctx_t *)malloc(sizeof(sample_server_ctx_t));
        if (server_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            sample_server_ctx_t* d_ctx = (sample_server_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
            if (d_ctx != NULL) {
                memcpy(server_ctx, d_ctx, sizeof(sample_server_ctx_t));
            }
            else {
                /* This really is an error case: the default connection context should never be NULL */
                memset(server_ctx, 0, sizeof(sample_server_ctx_t));
                server_ctx->default_dir = "";
            }
            picoquic_set_callback(cnx, sample_server_callback, server_ctx);
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* Create and initialize stream context */
                stream_ctx = sample_server_create_stream_context(server_ctx, stream_id);
            }

            if (stream_ctx == NULL) {
                /* Internal error */
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                return(-1);
            }
            else if (stream_ctx->is_name_read) {
                /* Write after fin? */
                return(-1);
            }
            else {
                /* Accumulate data */
                size_t available = sizeof(stream_ctx->file_name) - stream_ctx->name_length - 1;

                if (length > available) {
                    /* Name too long: reset stream! */
                    sample_server_delete_stream_context(server_ctx, stream_ctx);
                    (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR);
                }
                else {
                    if (length > 0) {
                        memcpy(stream_ctx->file_name + stream_ctx->name_length, bytes, length);
                        stream_ctx->name_length += length;
                    }
                    if (fin_or_event == picoquic_callback_stream_fin) {
                        int stream_ret;

                        /* If fin, mark read, check the file, open it. Or reset if there is no such file */
                        stream_ctx->file_name[stream_ctx->name_length + 1] = 0;
                        stream_ctx->is_name_read = 1;
                        stream_ret = sample_server_open_stream(server_ctx, stream_ctx);

                        if (stream_ret == 0) {
                            /* If data needs to be sent, set the context as active */
                            ret = picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
                        }
                        else {
                            /* If the file could not be read, reset the stream */
                            sample_server_delete_stream_context(server_ctx, stream_ctx);
                            (void) picoquic_reset_stream(cnx, stream_id, stream_ret);
                        }
                    }
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* This should never happen */
            }
            else if (stream_ctx->F == NULL) {
                /* Error, asking for data after end of file */
            }
            else {
                /* Implement the zero copy callback */
                size_t available = stream_ctx->file_length - stream_ctx->file_sent;
                int is_fin = 1;
                uint8_t* buffer;

                if (available > length) {
                    available = length;
                    is_fin = 0;
                }
                
                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL) {
                    size_t nb_read = fread(buffer, 1, available, stream_ctx->F);

                    if (nb_read != available) {
                        /* Error while reading the file */
                        sample_server_delete_stream_context(server_ctx, stream_ctx);
                        (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_READ_ERROR);
                    }
                    else {
                        stream_ctx->file_sent += available;
                    }
                }
                else {
                /* Should never happen according to callback spec. */
                    ret = -1;
                }
            }
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            if (stream_ctx != NULL) {
                /* Mark stream as abandoned, close the file, etc. */
                sample_server_delete_stream_context(server_ctx, stream_ctx);
                picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_CANCEL_ERROR);
            }
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            sample_server_delete_context(server_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        break;
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

/* Change a migration server_ctx to normal migration server_ctx*/

int build_server_ctx_from_migration_ctx(sample_server_ctx_t* server_ctx, sample_server_migration_ctx_t* server_ctx_migration)
{
    int ret = 0;
    if (server_ctx != NULL && server_ctx_migration != NULL)
    {
        server_ctx->default_dir = server_ctx_migration->default_dir;
        server_ctx->default_dir_len = server_ctx_migration->default_dir_len;
        server_ctx->first_stream = server_ctx_migration->first_stream;
        server_ctx->last_stream = server_ctx_migration->last_stream;
    } else
    {
        ret = -1;
    }
    return ret;
}
/* New callback function to finish the migration function.
 * Different from the sample_server_callback:
 * Change the callback_ctx to callback_migration_ctx which includes another quic server.
 */
int sample_server_migration_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    sample_server_migration_ctx_t* server_ctx= (sample_server_migration_ctx_t*)callback_ctx;
    // sample_server_ctx_t* server_ctx = (sample_server_ctx_t*)callback_ctx;
    // ret = build_server_ctx_from_migration_ctx(server_ctx, server_ctx_migration);
    sample_server_stream_ctx_t* stream_ctx = (sample_server_stream_ctx_t*)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        server_ctx = (sample_server_migration_ctx_t *)malloc(sizeof(sample_server_migration_ctx_t));
        if (server_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            sample_server_migration_ctx_t* d_ctx = (sample_server_migration_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
            if (d_ctx != NULL) {
                memcpy(server_ctx, d_ctx, sizeof(sample_server_migration_ctx_t));
            }
            else {
                /* This really is an error case: the default connection context should never be NULL */
                memset(server_ctx, 0, sizeof(sample_server_migration_ctx_t));
                server_ctx->default_dir = "";
            }
            picoquic_set_callback(cnx, sample_server_migration_callback, server_ctx);
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            // printf("###EVENT case picoquic_callback_stream_fin\n");
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* Create and initialize stream context */
                stream_ctx = sample_server_create_stream_context_for_migration(server_ctx, stream_id);
            }

            if (stream_ctx == NULL) {
                /* Internal error */
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                return(-1);
            }
            else if (stream_ctx->is_name_read) {
                /* Write after fin? */
                return(-1);
            }
            else {
                /* Accumulate data */
                size_t available = sizeof(stream_ctx->file_name) - stream_ctx->name_length - 1;

                if (length > available) {
                    /* Name too long: reset stream! */
                    sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
                    (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR);
                }
                else {
                    if (length > 0) {
                        memcpy(stream_ctx->file_name + stream_ctx->name_length, bytes, length);
                        stream_ctx->name_length += length;
                    }
                    if (fin_or_event == picoquic_callback_stream_fin) {
                        int stream_ret;

                        /* If fin, mark read, check the file, open it. Or reset if there is no such file */
                        stream_ctx->file_name[stream_ctx->name_length + 1] = 0;
                        stream_ctx->is_name_read = 1;
                        stream_ret = sample_server_open_stream_for_migration(server_ctx, stream_ctx);

                        if (stream_ret == 0) {
                            /* If data needs to be sent, set the context as active */
                            ret = picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
                        }
                        else {
                            /* If the file could not be read, reset the stream */
                            sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
                            (void) picoquic_reset_stream(cnx, stream_id, stream_ret);
                        }
                    }
                    // start the migraton here?
                    
                        if (server_ctx->server_flag) {
                            memcpy(server_ctx->file_name, stream_ctx->file_name, 256*sizeof(uint8_t));
                            // printf("FILE NAME IS %s\n", server_ctx->file_name);
                            server_ctx->migration_flag = 1;
                        /* code */
                        }
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
            // printf("case prepare to send\n");
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* This should never happen */
            }
            else if (stream_ctx->F == NULL) {
                /* Error, asking for data after end of file */
            }
            else {
                /* Implement the zero copy callback */
                size_t available = stream_ctx->file_length - stream_ctx->file_sent;
                int is_fin = 1;
                uint8_t* buffer;

                if (available > length) {
                    available = length;
                    is_fin = 0;
                }
                
                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL) {
                    size_t nb_read = fread(buffer, 1, available, stream_ctx->F);

                    if (nb_read != available) {
                        /* Error while reading the file */
                        sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
                        (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_READ_ERROR);
                    }
                    else {
                        stream_ctx->file_sent += available;
                    }
                }
                else {
                /* Should never happen according to callback spec. */
                    ret = -1;
                }
            }
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            if (stream_ctx != NULL) {
                /* Mark stream as abandoned, close the file, etc. */
                sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
                picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_CANCEL_ERROR);
            }
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            sample_server_delete_context_for_migration(server_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
            // printf("###EVENT case picoquic_callback_almost_ready\n");
            // printf("server flag is %d\n", server_ctx->server_flag);
            // if (server_ctx->server_flag) {
            //     server_ctx->migration_flag = 1;
            //     /* code */
            // }
            // printf("server number is %d\n", server_ctx->server_flag);
            // printf("migration flag in callback is%d\n",server_ctx->migration_flag);
            break;
            // time to migrate
            
        case picoquic_callback_ready:

            // printf("###EVENT case picoquic_callback_ready\n");
            // if (server_ctx->server_flag) {
            //     server_ctx->migration_flag = 1;
            //     /* code */
            // }
            // printf("migration flag in callback is %d\n",server_ctx->migration_flag);
            // server_ctx_migration->flag = 1;
            // server_ctx_migration->flag = 1;
            /* Check that the transport parameters are what the sample expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}


/* Server loop setup:
 * - Create the QUIC context.
 * - Open the sockets
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the socket return an error. 
 */

int picoquic_sample_server(int server_port, const char* server_cert, const char* server_key, const char* default_dir)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    char const* qlog_dir = PICOQUIC_SAMPLE_SERVER_QLOG_DIR;
    uint64_t current_time = 0;
    sample_server_ctx_t default_context = { 0 };

    default_context.default_dir = default_dir;
    default_context.default_dir_len = strlen(default_dir);

    printf("Starting Picoquic Sample server on port %d\n", server_port);

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        sample_server_callback, &default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);
    
    // create a back server here

    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic, 2);

        picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

        picoquic_set_qlog(quic, qlog_dir);

        picoquic_set_log_level(quic, 1);

        picoquic_set_key_log_file_from_env(quic);
    }

    /* Wait for packets */
    if (ret == 0) {
        ret = picoquic_packet_loop(quic, server_port, 0, 0, NULL, NULL);
        // if migration finished we should use picoquic_packet_loop(q_back......)
    }

    /* And finish. */
    printf("Server exit, ret = %d\n", ret);

    
    /* Clean up */
    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

int picoquic_sample_server_test_migration(int server_port, const char* server_cert, const char* server_key, const char* default_dir)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_quic_t* quic_back = NULL;
    char const* qlog_dir = PICOQUIC_SAMPLE_SERVER_QLOG_DIR;
    uint64_t current_time = 0;
    sample_server_migration_ctx_t default_context = { 0 };
    // int trans_flag1 = 0;
    // int trans_buffer1 = 0;
    pthread_mutex_t buffer_mutex_global = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t nonEmpty_global  = PTHREAD_COND_INITIALIZER;
    
    int* trans_flag = malloc(sizeof(int));
    int* trans_bytes = malloc(sizeof(int));
    uint8_t* trans_buffer = malloc(1536 * sizeof(uint8_t));
    uint8_t* trans_send_buffer = malloc(1536 * sizeof(uint8_t));
    struct sockaddr_storage* trans_addr_to = malloc(sizeof(struct sockaddr_storage));
    struct sockaddr_storage* trans_addr_from = malloc(sizeof(struct sockaddr_storage));
    struct sockaddr_storage* trans_peer_addr = malloc(sizeof(struct sockaddr_storage));
    struct sockaddr_storage* trans_local_addr = malloc(sizeof(struct sockaddr_storage));

    int* trans_s_socket = malloc(2 * sizeof(int));
    int* trans_sock_af = malloc(2 * sizeof(int));
    int* trans_nb_sockets = malloc(sizeof(int));



    int* trans_if_index_to = malloc(sizeof(int));
    int* trans_socket_rank = malloc(sizeof(int));
    uint64_t* trans_current_time = malloc(sizeof(uint64_t));

    unsigned char* trans_received_ecn = malloc(sizeof(unsigned char));

    default_context.default_dir = default_dir;
    default_context.default_dir_len = strlen(default_dir);
    default_context.migration_flag = 0;
    default_context.server_flag = 0;

    printf("Starting Picoquic Sample server on port %d\n", server_port);
    struct hashmap_s hashmap;
    if (0 != hashmap_create(32, &hashmap)) {
        printf("create hashmap wrong!\n");
    }
    struct hashmap_s * cnx_id_table = &hashmap;

    current_time = picoquic_current_time();
    // create a back server here
    quic_back = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        sample_server_migration_callback, &default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

    if (quic_back == NULL) {
        fprintf(stderr, "Could not create server context\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic_back, 2);

        picoquic_set_default_congestion_algorithm(quic_back, picoquic_bbr_algorithm);

        picoquic_set_qlog(quic_back, qlog_dir);

        picoquic_set_log_level(quic_back, 1);

        picoquic_set_key_log_file_from_env(quic_back);
        
        printf("Build server 2 OK\n");
    }
    
    sample_server_migration_ctx_t default_migration_context = { 0 };
    default_migration_context.default_dir = default_dir;
    default_migration_context.default_dir_len = strlen(default_dir);
    default_migration_context.server_back = quic;
    default_migration_context.migration_flag = 0;
    default_migration_context.server_flag = 1;

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    // TODO: start another thread here and have this quic in this thread
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        sample_server_migration_callback, &default_migration_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic, 2);

        picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

        picoquic_set_qlog(quic, qlog_dir);

        picoquic_set_log_level(quic, 1);

        picoquic_set_key_log_file_from_env(quic);

        printf("Build server 1 OK\n");
    }
    /* Wait for packets */
    if (ret == 0) {
        
        // picohash_table* cnx_id_table = picohash_create((size_t)8 * 4, picoquic_cnx_id_hash, picoquic_cnx_id_compare);
        // free(cnx_id_table);
        // ret = picoquic_packet_loop(quic, server_port, 0, 0, NULL, NULL);
        // ret = picoquic_packet_loop_with_migration_master(quic, quic_back, cnx_id_table, trans_flag, trans_buffer ,nonEmpty ,server_port, 0, 0, NULL, NULL);
        // if migration finished we should use picoquic_packet_loop(q_back......)
        pthread_t thread[2];

        // strcpy(source,"hello world!");
        // buflen = strlen(source);
        /* create 2 threads*/
        /*
        pthread_create(&thread[2], NULL, (void *)watch, &thread_id[2]);
        */
        /* create one consumer and one producer */
        master_thread_para_t* master_para = malloc(sizeof(master_thread_para_t));
        master_para->quic = quic;
        master_para->quic_back = quic_back;
        master_para->cnx_id_table = cnx_id_table;
        master_para->trans_flag = trans_flag;
        master_para->shared_data.trans_buffer = trans_buffer;
        master_para->shared_data.trans_send_buffer = trans_send_buffer;
        master_para->shared_data.trans_bytes = trans_bytes;
        master_para->shared_data.trans_received_ecn = trans_received_ecn;
        master_para->shared_data.trans_addr_to = trans_addr_to;
        master_para->shared_data.trans_addr_from = trans_addr_from;
        master_para->shared_data.trans_peer_addr = trans_peer_addr;
        master_para->shared_data.trans_local_addr = trans_local_addr;
        master_para->shared_data.trans_if_index_to = trans_if_index_to;
        master_para->shared_data.trans_current_time = trans_current_time;
        master_para->shared_data.trans_socket_rank = trans_socket_rank;
        master_para->shared_data.trans_s_socket = trans_s_socket;
        master_para->shared_data.trans_sock_af = trans_sock_af;
        master_para->shared_data.trans_nb_sockets = trans_nb_sockets;
        master_para->nonEmpty = &nonEmpty_global;
        master_para->buffer_mutex = &buffer_mutex_global;
        master_para->server_port = server_port;
        

        slave_thread_para_t* slave_para = malloc(sizeof(slave_thread_para_t));
        slave_para->quic = quic_back;
        slave_para->cnx_id_table = cnx_id_table;
        slave_para->trans_flag = trans_flag;
        slave_para->shared_data.trans_buffer = trans_buffer;
        slave_para->shared_data.trans_send_buffer = trans_send_buffer;
        slave_para->shared_data.trans_bytes = trans_bytes;
        slave_para->shared_data.trans_received_ecn = trans_received_ecn;
        slave_para->shared_data.trans_addr_to = trans_addr_to;
        slave_para->shared_data.trans_addr_from = trans_addr_from;
        slave_para->shared_data.trans_peer_addr = trans_peer_addr;
        slave_para->shared_data.trans_local_addr = trans_local_addr;
        slave_para->shared_data.trans_if_index_to = trans_if_index_to;
        slave_para->shared_data.trans_current_time = trans_current_time;
        slave_para->shared_data.trans_socket_rank = trans_socket_rank;
        slave_para->shared_data.trans_s_socket = trans_s_socket;
        slave_para->shared_data.trans_sock_af = trans_sock_af;
        slave_para->shared_data.trans_nb_sockets = trans_nb_sockets;
        slave_para->nonEmpty = &nonEmpty_global;
        slave_para->buffer_mutex = &buffer_mutex_global;
        slave_para->server_port = server_port;
        

        pthread_create(&thread[0], NULL, (void *)slave_quic, slave_para);
        pthread_create(&thread[1], NULL, (void *)master_quic, master_para);
        // pthread_create(&thread[2], NULL, (void *)producer, &thread_id[2]);
        // pthread_join(thread[0], NULL);
        for(int i = 0; i<2 ; i++)
        {
            // printf("#######################thread_join!\n");
            pthread_join(thread[i], NULL);
            // printf("#######################thread_join!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        }
    }

    /* And finish. */
    printf("Server exit, ret = %d\n", ret);

    /* Clean up */
    if (quic != NULL) {
        picoquic_free(quic);
    }

    if (quic_back != NULL) {
        picoquic_free(quic_back);
    }
    return ret;
}



void * master_quic(void * master_para)
{
    
    master_thread_para_t* thread_para = (master_thread_para_t*) master_para;
    picoquic_quic_t* quic = thread_para->quic;
    picoquic_quic_t* quic_back = thread_para->quic_back;
    struct hashmap_s* cnx_id_table = thread_para->cnx_id_table;
    int* trans_flag = thread_para->trans_flag;
    trans_data_t trans_data = thread_para->shared_data;



    pthread_cond_t* nonEmpty = thread_para->nonEmpty;
    pthread_mutex_t* buffer_mutex = thread_para->buffer_mutex;
    int server_port = thread_para->server_port;
    printf("master?????????????????????????????????????????????\n");
    // int ret = 0;
    while (1)
    {
        printf("master\n");
        /* lock the variable */
        // pthread_mutex_lock(buffer_mutex);
        picoquic_packet_loop_with_migration_master(quic, quic_back, cnx_id_table, trans_flag, trans_data,nonEmpty ,buffer_mutex,server_port, 0, 0, NULL, NULL);
        /*unlock the variable*/
        // pthread_mutex_unlock(buffer_mutex);
    }
}



void * slave_quic(void * slave_para)
{
    // int first = 0;
    slave_thread_para_t* thread_para = (slave_thread_para_t*) slave_para;
    picoquic_quic_t* quic = thread_para->quic;
    struct hashmap_s* cnx_id_table = thread_para->cnx_id_table;
    int* trans_flag = thread_para->trans_flag;
    trans_data_t trans_data = thread_para->shared_data;
    pthread_cond_t* nonEmpty = thread_para->nonEmpty;
    pthread_mutex_t* buffer_mutex = thread_para->buffer_mutex;
    int server_port = thread_para->server_port;

    
    // int ret = 0;
    while (1)
    {
        printf("slave\n");
        /* lock the variable */
        // pthread_mutex_lock(&buffer_mutex);
        picoquic_packet_loop_with_migration_slave(quic, cnx_id_table, trans_flag, trans_data,nonEmpty ,buffer_mutex ,server_port, 0, 0, NULL, NULL);
        /*unlock the variable*/
        // pthread_mutex_unlock(&buffer_mutex);
    }

}