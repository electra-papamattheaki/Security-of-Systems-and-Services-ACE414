/* Diffie-Hellman Key Exchange Algorithm */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <gmp.h>

double p; // prime number
double g; // base
double a; // secret integer Alice chooses
double b; // secret integer Bob chooses

int main(int argc, char *argv[])
{
    double A;
    double B;
    double s1;
    double s2;

    if(argc<=1) 
    {
    printf("You did not feed me arguments, I will die now :(\n");
    exit(1);
    }
 
    int n = 0;
    char* output_file = ""; 

    for (n=1; n<=argc-1; n=n+2) 
    { 
        /* Get output file */
        if (strcmp(argv[n],"-o")==0)
        {
            output_file = argv[n+1];
            
        }
        /* Get prime number */
        else if (strcmp(argv[n],"-p")==0)
        {
            p = atoi(argv[n+1]);
        }
        /* Get Primitive Root for previous prime number */ 
        else if (strcmp(argv[n],"-g")==0)
        {
            g = atoi(argv[n+1]);
        }
        /*Get a for private key A*/
        else if (strcmp(argv[n],"-a")==0)
        {
            a = atoi(argv[n+1]);           
        }
        /*Get b for private key B*/
            else if (strcmp(argv[n],"-b")==0)
        {
            b = atoi(argv[n+1]);
        }
        else if (strcmp(argv[n],"-h")==0)
        {
            printf("Options:\n"); 
            printf("\n");
            printf("-o\tpath\tPath to the output file\n");
            printf("-p\tnumber\tPrime number\n");
            printf("-g\tnumber\tPrimitive Root for previous prime number\n");
            printf("-a\tnumber\tPrivate key A\n");
            printf("-b\tnumber\tPrivate key B\n");
            printf("-h\t\tThis help message\n");            
            return 0;
        }
        else
        {
            printf("Invalid arguments. \n"); 
            return 0;
        }
    }

    /* Check if a is less than p before continuing */
    if (a<p) 
    {
        A = fmod(pow(g,a),p); 
    }
    else 
    {
        printf("Secret Integer 'a' is not less than the prime number chosen \n");
        return 0; 
    }

    /* Check if b is less than p before continuing */
    if (b<p)
    {
        B = fmod(pow(g,b),p); 
    }
    else 
    {
        printf("Secret Integer 'b' is not less than the prime number chosen \n");
        return 0; 
    }
         
    s1 = fmod(pow(B,a),p);
    s2 = fmod(pow(A,b),p); 

    if (s1 == s2)
    {
        printf("Alice's secret key is %f\nBob's secret key is %f \n", s1, s2);
    }
    else
    {
        printf("Something went wrong, keys are not identical \n");
    }

    /* open the file to write in it */
    FILE* out_file = fopen(output_file,"w"); 
    /* write A,B and secret key */
    fprintf(out_file, "%f, %f, %f",A,B,s1); 
    /* close the file */
    fclose(out_file);

return 0;
}