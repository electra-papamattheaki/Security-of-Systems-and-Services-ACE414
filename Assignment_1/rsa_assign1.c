/* RSA Algorithm */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <gmp.h>

/* functions */
void rsa_keyrepair_generator(); 
void decrypt_data(char *input_file, char *output_file, char *key_file);
void encrypt_data(char *input_file, char *output_file, char *key_file); 
char *readcontent(const char *filename);


int main(int argc, char *argv[])
{

    if(argc<=1) 
    {
    printf("You did not feed me arguments, I will die now :(\n");
    exit(1);
    }
 
    int count = 0;
    char* input_file = ""; 
    char* output_file = "";
    char* key_file = ""; 

    for (count=1; count<=argc-1; count=count+2) 
    { 
        /* Get path to input file */
        if (strcmp(argv[count],"-i")==0)
        {
            input_file = argv[count+1];
            
        }
        /* Get path to output file */
        else if (strcmp(argv[count],"-o")==0)
        {
            output_file = argv[count+1];   
        }
        /* Get path to key file */
        else if (strcmp(argv[count],"-k")==0)
        {
            key_file = argv[count+1];       
        }
        /* Get prime number */
        else if (strcmp(argv[count],"-g")==0)
        {
            rsa_keyrepair_generator(); 
        }
        /* Get Primitive Root for previous prime number */ 
        else if (strcmp(argv[count],"-d")==0)
        {
            decrypt_data(input_file, output_file, key_file); 
        }
        /*Get a for private key A*/
        else if (strcmp(argv[count],"-e")==0)
        {
            encrypt_data(input_file, output_file, key_file);            
        }
        /* Help Message */
        else if (strcmp(argv[count],"-h")==0)
        {
            printf("Options:\n"); 
            printf("\n");
            printf("-i\tpath\tPath to the input file\n"); 
            printf("-o\tpath\tPath to the output file\n");
            printf("-k\tpath\tPath to the key file\n");
            printf("-g\t\tPerform RSA key-pair generation\n");
            printf("-d\t\tDecrypt input and store results to output\n");
            printf("-e\t\tEncrypt input and store results to output\n");
            printf("-h\t\tThis help message\n");
            return 0;
        }
        else
        {
            printf("Invalid arguments. Try again\n"); 
            return 0;
        }
    }

return 0; 
}

void rsa_keyrepair_generator()
{

    /* parameters needed */
    FILE* public_key = NULL;
	FILE* private_key = NULL;

    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t lambda_n; 
    mpz_t e;
    mpz_t d;

    /* initializations */
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(lambda_n);
    mpz_init(e);
    mpz_init(d);

    int reps = 50;     // used to help the function determine if a number is prime
    int is_prime = 3;  // the result of the function will be returned in this value

    /* Get p */
    printf("Enter the prime number p: ");
    gmp_scanf("%Zd", p);

    /* test if p is a prime number */
    is_prime = mpz_probab_prime_p (p, reps);
    while  (is_prime!=2)
    {
        printf("The number you entered is not prime. Please try again.\nEnter the prime number p: ");
        gmp_scanf("%Zd", p);
        is_prime = mpz_probab_prime_p (p, reps);
    }

    fflush(stdin);

    /* Get q */
    printf("Enter the prime number q: ");
    gmp_scanf("%Zd", q);

    /* test if q is a prime number */
    is_prime = mpz_probab_prime_p (q, reps);
    while  (is_prime!=2)
    {
        printf("The number you entered is not prime. Please try again.\nEnter the prime number q: ");
        gmp_scanf("%Zd", q);
        is_prime = mpz_probab_prime_p (q, reps);
    }

    //gmp_printf("p: %Zd , q: %Zd\n", p, q);

    // generates p,q randomly
    /*gmp_randstate_t state; 
    gmp_randinit_default (state);
    mpz_t rand_num;
    mp_bitcnt_t nf = 10;
    mpz_urandomb (rand_num, state, nf); 
    mpz_nextprime(p, rand_num); 

    mpz_urandomb (rand_num, state, nf); 
    mpz_nextprime(q, rand_num); */

    /* Since p & q are prime numbers, calculate value n */
    mpz_mul (n, p, q); 
    
    //gmp_printf("n: %Zd\n", n);

    /* calculate lambda(n) */

    mpz_t p_minus_1; 
    mpz_t q_minus_1;

    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui (p_minus_1, p, 1);
    mpz_sub_ui (q_minus_1, q, 1);

    mpz_mul(lambda_n, p_minus_1, q_minus_1);
    
    //gmp_printf("lambda(n): %Zd\n", lambda_n);

    /* Choose prime e */
    mpz_t mod_res;
    mpz_t rop; 
    
    mpz_init(mod_res);
    mpz_init(rop);

    /* set e to the first prime number which is 2 */
    mpz_set_d (e, 2); 

    mpz_mod (mod_res, e, lambda_n);
    mpz_gcd (rop, e, lambda_n);

    while (mpz_cmp_d(mod_res,0)==0 && mpz_cmp_d(rop,1)!=0)
    {
        mpz_nextprime(e, e); 
        mpz_mod (mod_res, e, lambda_n);
        mpz_gcd (rop, e, lambda_n); 
    }
    
    //gmp_printf("e: %Zd\n", e);

    /* Choose d where d is the modular inverse of (e, lambda) */
    int is_modinv = mpz_invert(d, e, lambda_n);
    if (is_modinv == 0)
    {
        printf("The is no modular inverse. Keys generated might be wrong\n");
    } 
    
    //gmp_printf("d: %Zd\n", d);

    /* Create the files for writing */
    public_key = fopen("public.key", "w");
	private_key = fopen("private.key", "w");

    /* Write on the public key file */
    /* The public key consists of n and d, in this order */
    //fwrite(&n, sizeof(mpz_t), 1, public_key);
	//fwrite(&d, sizeof(mpz_t), 1, public_key);
    mpz_out_raw(public_key, n); 
    mpz_out_raw(public_key, d); 

    /* Write on the private key file */
    /* The private key consists of n and e, in this order */
	//fwrite(&n, sizeof(mpz_t), 1, private_key);
	//fwrite(&e, sizeof(mpz_t), 1, private_key);
    mpz_out_raw(private_key, n);
    mpz_out_raw(private_key, e);

    /* close the files */
    fclose(public_key);
	fclose(private_key);

}

void decrypt_data(char *input_file, char *output_file, char *key_file)
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

    int cyphertext_size = 0; // size of cyphertext file
    mpz_t keyfromfile; // key from key file
    mpz_t n;  // n from key file

    mpz_init(keyfromfile); 
    mpz_init(n); 

    plaintext  = fopen(output_file, "w");
    cyphertext = fopen(input_file, "r"); 
    key = fopen(key_file, "r");

    /* if fopen() returns NULL it;s unable to open file in given mode. */
    if (cyphertext == NULL)
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

    //if(cyphertext) 
    //{
        fseek(cyphertext, 0, SEEK_END);
        cyphertext_size = ftell(cyphertext);
        rewind(cyphertext);

        cyphertext_size = cyphertext_size/sizeof(size_t);

        size_t cyphertext_content[cyphertext_size]; 

        fread(cyphertext_content, sizeof(size_t), cyphertext_size, cyphertext);
        //printf("Content: %ld", plaintext_content[0]); 
    //}

    mpz_t cypher_to_mpz; 
    mpz_init(cypher_to_mpz);

    mpz_t decr_buffer;
    mpz_init(decr_buffer);

    char decrypted_text[cyphertext_size]; 
    //printf("%d\n", cyphertext_size);

    for (int i=0; i<cyphertext_size; i++)
    {

        mpz_set_ui(cypher_to_mpz, (long) cyphertext_content[i]);
        //gmp_printf("%Zd\n", cypher_to_mpz);

        mpz_powm (decr_buffer, cypher_to_mpz, keyfromfile, n);
        //decrypted_text[i] = (char)mpz_get_ui(decr_buffer);
        //mpz_export(&decrypted_text[i], NULL, 1, sizeof(char), 0, 0, decr_buffer);
        mpz_import(decr_buffer, 0, 1, sizeof(char), 0, 0, &decrypted_text[i]);  

        //printf("char: %c\n", decrypted_text[i]);
    }

    /* Finally write on the encrypted file */
    fputs(decrypted_text, plaintext); 

    /* close the files */
    fclose(plaintext);
    fclose(cyphertext); 
    fclose(key); 
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

    //if(plaintext) 
    //{
        fseek(plaintext, 0, SEEK_END);
        plaintext_size = ftell(plaintext);
        rewind(plaintext);

        int cyphertext_content[plaintext_size];

        plaintext_content = (char*) malloc(sizeof(char) * plaintext_size);
        fread(plaintext_content, 1, plaintext_size, plaintext);
        //printf("Content: %s", plaintext_content); 
    //}

    mpz_t plain_to_int; 
    mpz_init(plain_to_int);

    mpz_t encr_buffer;
    mpz_init(encr_buffer);

    size_t encrypted_text[plaintext_size]; 

    for (int i=0; i<plaintext_size-1; i++)
    {
        cyphertext_content[i] = (int) plaintext_content[i]; 
        //printf("%d\n", cyphertext_content[i]); 

        mpz_set_ui(plain_to_int, (long) cyphertext_content[i]);
        //gmp_printf("%Zd\n", plain_to_int);

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







