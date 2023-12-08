#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include <fcntl.h>
#include <linux/limits.h>
#include <math.h>
#include <gmp.h>

FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* add your code here */
	/* Get Access Info */

	/* Get user ID */
	int uid = getuid();

	/* Get the path and name of the accessed file.*/
	char* real_path = realpath(path, NULL);

	/* Get the date & timestamp */
	time_t open_time = time(NULL); // initialize time
	struct tm *now = localtime(&open_time); 
	char date[10];
	char timestamp[10];
	sprintf(date, "%d/%d/%d", now->tm_mday, now->tm_mon + 1, now->tm_year + 1900);
    sprintf(timestamp, "%d:%d:%d",now->tm_hour, now->tm_min, now->tm_sec); 

	/* Get access type */
	int access_type; 

	if (access (real_path, F_OK)) 
        access_type = 0; // file creation 
    else{
        access_type = 1; // file opening
    }

	/* Check if action was denied */
	int is_action_denied;

	if (access(realpath(path, NULL), R_OK | W_OK)==0)
		is_action_denied = 0; // access granted
	else
		is_action_denied = 1; // access denied
	
	/* Get the file fingerprint */
	char *fingerprint;
	FILE *f = (*original_fopen)(real_path, "r");
	long f_length;
	MD5_CTX cxt;

    fseek(f, 0, SEEK_END);
    f_length = ftell(f);
    fseek(f,0,SEEK_SET);

    MD5_Init(&cxt);

    char data[f_length];
    int bytes;
        
    while (( bytes = fread(data, 1, f_length, f)) != 0) 
	{
        MD5_Update(&cxt, data, bytes);
    }

    fingerprint = (unsigned char*) malloc(f_length);
        
	MD5_Final(fingerprint, &cxt);
        
    fclose(f);
	
	/* Create a string with all the information */
	char * log = malloc(512);
	sprintf(log, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", uid, real_path, date, timestamp, access_type, is_action_denied, fingerprint);
       
   
	/* Write encrypted data to log file*/
	char *key_file = key_generator(); 
	encrypt_data(log, "file_logging.log", key_file);	

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	/* add your code here */

	/* Get Access Info */

	/* Get user ID */
	int uid = getuid();

	/* Get the path and name of the accessed file.*/
	int f = fileno(stream);
	char file_path[PATH_MAX];
	char *filename;

	sprintf(file_path, "/proc/self/fd/%d", f);
	filename = malloc(PATH_MAX);
	int n = readlink(f, filename, PATH_MAX);
	if (n < 0)
	{
		printf("Cannot read the symbolic link PATH"); 
		abort();
	}
	filename[n] = '\0';

	char* real_path = filename;

	/* Get the date & timestamp */
	time_t open_time = time(NULL); // initialize time
	struct tm *now = localtime(&open_time); 
	char date[10];
	char timestamp[10];
	sprintf(date, "%d/%d/%d", now->tm_mday, now->tm_mon + 1, now->tm_year + 1900);
    sprintf(timestamp, "%d:%d:%d", now->tm_hour, now->tm_min, now->tm_sec); 

	/* Set access type */
	int access_type = 2; // file writing

	int is_action_denied; 
	if (access(filename, W_OK)==0)
	{
		is_action_denied = 0; // access granted
	}
	else
	{
		is_action_denied = 1; // access denied 
	}

	/* Get the file fingerprint */
	char *fingerprint;
	FILE *file = (*original_fwrite)(real_path, "r");
	long f_length;
	MD5_CTX cxt;

    fseek(file, 0, SEEK_END);
    f_length = ftell(f);
    fseek(file,0,SEEK_SET);

    MD5_Init(&cxt);

    char data[f_length];
    int bytes;
        
    while (( bytes = fread(data, 1, f_length, file)) != 0) 
	{
        MD5_Update(&cxt, data, bytes);
    }

    fingerprint = (unsigned char*) malloc(f_length);
        
	MD5_Final(fingerprint, &cxt);
        
    fclose(file);

	/* Create a string with all the information */
	char * log = malloc(512);
	sprintf(log, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", uid, real_path, date, timestamp, access_type, is_action_denied, fingerprint);
    
	/* Write encrypted data to log file*/
	char *key_file = key_generator(); 
	encrypt_data(log, "file_logging.log", key_file);
	
	return original_fwrite_ret;
}

void encrypt_data(char *input_file, char *output_file, char *key_file)
{

    /* check to see if the user gave all the required files from the command line */
    if (strlen(input_file) == 0) 
    {
        printf("You didn't specify the input file. Please try again\n");
        exit(1);  
    }

    if (strlen(output_file) == 0)
    {   
        printf("You didn't specify the output file. Please try again\n");
        exit(1);  
    }

    if (strlen(key_file) == 0)
    {
        printf("You didn't specify the key file. Please try again\n");
        exit(1);  
    }

    /* if yes, continue... */
    FILE *plaintext; 
    FILE *cyphertext; 
    FILE *key; 

    int plaintext_size = 0; 
    char *plaintext_content;
    //int cyphertext_content[plaintext_size];
    mpz_t keyfromfile;
    mpz_t n;  

    mpz_init(keyfromfile); 
    mpz_init(n); 
 
    /* 
     * Open source file in 'r' and 
     * destination file in 'w' mode 
     */
    plaintext  = fopen(input_file, "r");
    cyphertext = fopen(output_file, "w"); 
    key = fopen(key_file, "r"); 

    /* if fopen() returns NULL it;s unable to open file in given mode. */
    if (plaintext == NULL)
    {
        printf("Please check that the input file you entered exists.\n");
        exit(1);
    }
    if (key == NULL)
    {
        printf("Please check that the key file you entered exists.\n");
        exit(1);
    }

    /* Read key and n from the key file and store them*/
    mpz_inp_raw(n, key);
    mpz_inp_raw(keyfromfile, key);

    fseek(plaintext, 0, SEEK_END);
    plaintext_size = ftell(plaintext);
    rewind(plaintext);

    int cyphertext_content[plaintext_size];

    plaintext_content = (char*) malloc(sizeof(char) * plaintext_size);
    fread(plaintext_content, 1, plaintext_size, plaintext);


    mpz_t plain_to_int; 
    mpz_init(plain_to_int);

    mpz_t encr_buffer;
    mpz_init(encr_buffer);

    size_t encrypted_text[plaintext_size]; 

    for (int i=0; i<plaintext_size-1; i++)
    {
        cyphertext_content[i] = (int) plaintext_content[i]; 

        mpz_set_ui(plain_to_int, (long) cyphertext_content[i]);

        mpz_powm (encr_buffer, plain_to_int, keyfromfile, n);
        mpz_export(&encrypted_text[i], 0, 1, sizeof(size_t), 0, 0, encr_buffer);
    }

    /* Finally write on the encrypted file */
    fwrite(encrypted_text, sizeof(size_t), plaintext_size, cyphertext); 
    
    /* close the files */
    fclose(plaintext);
    fclose(cyphertext); 
    fclose(key); 
}

FILE* key_generator()
{

    /* parameters needed */
    FILE* key = NULL;

    long p = 5641;
    long q = 7283;
    long n;
    long lambda_n; 
    long e;
    long d;

    /* Since p & q are prime numbers, calculate value n */
    n =  p * q; 
    
    /* calculate lambda(n) */

    lambda_n = (p-1)*(q-1);
    
    /* Choose prime e */
    mpz_t mod_res;
    mpz_t rop; 
    
    mpz_init(mod_res);
    mpz_init(rop);

    /* set e and d*/
    e = 2;
	
    for (long i = 1; e < lambda_n; i++)
	{
        if (((e % lambda_n) * (i % lambda_n)) % lambda_n == 1)
		{
            d = i; 
			break; 
		}
		else
		{
			d = 3; 
		}
		
	}

    /* Create the file for writing */
    key  = fopen("key.key", "w");

    /* Write on the public key file */
    /* The public key consists of n and d, in this order */
    fwrite(&n, sizeof(long), 1, key);
	fwrite(&d, sizeof(long), 1, key);

    /* close the files */
    fclose(key);

	return key;
}
