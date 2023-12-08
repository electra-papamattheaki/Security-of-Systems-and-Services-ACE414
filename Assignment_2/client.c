#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1

int OpenConnection(const char *hostname, int port)
{

    /* use the same variables as OpenListener */ 
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    /* Check if hostname given is correct */
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        /* --Print a message describing the meaning of the value of errno */
        perror(hostname);
        /* --Abort execution and generate a core-dump. */
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    /* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
     * For connectionless socket types, just set the default address to send to
     * and the only address from which to accept transmissions.
     * Return 0 on success, -1 for errors.*/
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        /* --close the file descriptor FD. */
        close(sd);
        /* --print a message describing the meaning of the value of errno */
        perror(hostname);
        /* --abort execution and generate a core-dump. */
        abort();
    }
    return sd;

}

SSL_CTX* InitCTX(void)
{
    /* --The SSL_CTX object uses method as connection method. 
     * The methods exist in a generic type (for client and server use), a server only type, 
     * and a client only type.*/
    SSL_METHOD *connection_method;
    SSL_CTX *ctx;

	/* Load cryptos, et.al. */
    OpenSSL_add_all_algorithms();

	/* Bring in and register error messages */
    SSL_load_error_strings();

	/* Create new client-method instance */
    /* -- We want TSL version 1.2 that's why we choose this. */
    connection_method = TLSv1_2_client_method(); 

	/* Create new context */
    ctx = SSL_CTX_new(connection_method);

    /* --check to make sure ssl is not null */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        /* -- If it's null abort execution and generate a core-dump. */
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

	/* get the server's certificate */
    cert = SSL_get_peer_certificate(ssl);

    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        
        /* print subject */
        printf("Subject: %s\n", line);
       	line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

        /* print issuer */   
        printf("Issuer: %s\n", line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        free(line);
    }
    else
    {
        printf("Info: No client certificates configured.\n");
    }
}

int main(int count, char *strings[])
{

    char *hostname;
    char *portnum;

    char data_buffer[1024];
    char request[1024] = {0};

    int server;
    int bytes_num;

    SSL_CTX *ssl_ctx;
    SSL *ssl;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    /* initialize ssl library */
    SSL_library_init();

    /* hostname is the first argument */
    hostname = strings[1];
    /* port num is the second argument */
    portnum  = strings[2];

    ssl_ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));

    /* create new SSL connection state */
	ssl = SSL_new(ssl_ctx);

    /* attach the socket descriptor */
    SSL_set_fd(ssl, server); 

	/* perform the connection */
    if ( SSL_connect(ssl) == FAIL )   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);

		/* construct reply */
        sprintf(request, cpRequestMessage, acUsername, acPassword);

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
   			
        /* get any certs */
        /* --use the function created above */
        ShowCerts(ssl); 

        /* encrypt & send message */
        SSL_write(ssl,request, strlen(request));

        /* get reply & decrypt */
        /*-- try to read num bytes from the specified ssl into the buffer */
        bytes_num = SSL_read(ssl, data_buffer, sizeof(data_buffer));

        data_buffer[bytes_num] = 0;

        /* print what you received from server */
        printf("Received from Server:\n");
        printf(" \"%s\"\n", data_buffer);

	    /* release connection state */
        SSL_free(ssl);
    }
	/* close socket */
    close(server);

	/* release context */
    SSL_CTX_free(ssl_ctx);

    return 0;
}
