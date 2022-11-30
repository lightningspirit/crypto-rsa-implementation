/**
 * @file assymetric.c
 * @author Vitor Carvalho (1401892@estudante.uab.pt)
 * @brief
 * @version 0.1
 * @date 2022-11-23
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

/**
 * @brief gets size of array
 * 
 * always useful macro
 */
#define ARR_SIZE(arr) ( sizeof((arr)) / sizeof((arr[0])) )

/**
 * @brief PU and PR file names
 * 
 */
#define PUBLIC_FILE "rsa_public"
#define PRIVATE_FILE "rsa_private"

/**
 * @brief this is used to get the ASCII int for each char.
 */

/**
 * @brief the usage message
 *
 * @param invoker
 */
void usage(char *invoker)
{
  fprintf(stderr, "Usage: %s <option> [args...]\n -w\t\t\twrite new public and private keys\n -e <plaintext>\t\tencrypt text message\n -d <ciphertext>\tdecrypt previously encrypted message\n", invoker);
}

/**
 * @brief a warning message
 *
 * @param message
 */
void warn(char *message)
{
  printf("Warning: %s\n", message);
}

/**
 * @brief an error message
 *
 * @param message
 */
void error(char *message)
{
  fprintf(stderr, "Error: %s\n", message);
}

/**
 * @brief 
 * 
 * @param file 
 */
void fileOpenError(char *file)
{
  char str[strlen(file) + 20];
  sprintf(str, "Cannot open %s file.", file);
  error(str);
}

/**
 * @brief open a key file and test readiness and read its content
 * 
 * @param p 
 * @param n 
 * @param path 
 */
void readKeyFile(int *p, int *n, char *path)
{
  FILE *file;

  if ((file = fopen(path, "r")) == NULL) {
    fileOpenError(path);
    exit(1);
  }

  fscanf(file, "%d %d", p, n);
  fclose(file);
}

/**
 * @brief reads the public key file
 * 
 * @param e 
 * @param n 
 */
void readPublicKeyFile(int *e, int *n)
{
  readKeyFile(e, n, PUBLIC_FILE);
}

/**
 * @brief reads the private key file
 * 
 * @param p 
 * @param n 
 */
void readPrivateKeyFile(int *d, int *n)
{
  readKeyFile(d, n, PRIVATE_FILE);
}

/**
 * @brief Exponential Modulus
 * 
 * Since using pow() and fmod() functions is a complex task
 * via C, this code was bored to produce the exponential
 * modulus calculations:
 * 
 * 1. M^e mod n
 * 2. C^d mod n
 * 
 * Source: https://www.topcoder.com/thrive/articles/Primality%20Testing%20:%20Non-deterministic%20Algorithms
 * 
 * @param a 
 * @param b 
 * @param n 
 * @return int 
 */
int modexp(int a, int b, int n){
  long long x = 1, y = a; 

  while (b > 0) {
    if (b % 2 == 1) {
      x = (x * y) % n; // multiplying with base
    }
    y = (y * y) % n; // squaring the base
    b /= 2;
  }

  return x % n;
}

/**
 * @brief Modular multiplicative inverse
 * 
 * Given two integers A and M, find the modular multiplicative
 * inverse of A under modulo M. The modular multiplicative
 * inverse is an integer X such that:
 * 
 *   A X ≅ 1 (mod M)   
 * 
 * Source: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
 * 
 * @param A 
 * @param M 
 * @return int 
 */
int modinv(int A, int M)
{
  int m0 = M;
  int y = 0, x = 1;

  if (M == 1)
      return 0;

  while (A > 1) {
    // q is quotient
    int q = A / M;
    int t = M;

    // m is remainder now, process same as
    // Euclid's algo
    M = A % M, A = t;
    t = y;

    // Update y and x
    y = x - q * y;
    x = t;
  }

  // Make x positive
  if (x < 0)
    x += m0;

  return x;
}

/**
 * @brief finds if a number is prime
 * 
 * Miller-Rabin primality test
 * https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
 * 
 * @param n 
 * @return int 
 */
int isPrimeNumber(int n)
{
  int i, c = 0;

  for (i = 0; i <= n; i++) {
    if (fmod(n, i) == 0.0) {
      c++;
    }
  }

  return c == 2 ? 1 : 0;
}

/**
 * @brief find the first co-prime
 * 
 * @param n
 * @return int 
 */
int findFirstCoPrime(int n, int start)
{
  for (int i = start; i < n; i++) {
    if (isPrimeNumber(i) && (n % i != 0)) {
      return i;
    }
  }

  return 0;
}

/**
 * @brief given a plaintext message, encrypts it
 * 
 * @param plaintext 
 */
void encryptMessage(char *plaintext)
{
  // types for keys
  int e = 0, n = 0, c = 0;

  // it reads the public key from file
  readPublicKeyFile(&e, &n);

  // for each character in the plaintext...
  for (int i = 0; plaintext[i] != '\0'; i++)
  {
    // ...calculate the C = M^e mod n
    // using the exponential modulus
    // otherwise intermediate calculations
    // will overflow with really big numbers
    c = modexp(plaintext[i], e, n);

    // print the result integer to the screen
    printf("%d ", c);
  }

  printf("\n");
}

/**
 * @brief given a ciphertext message, decrypts it
 * 
 * @param ciphertext 
 */
void decryptMessage(char *ciphertext)
{
  // define d, n for keys, a counter and the length of the ciphertext
  int d = 0, n = 0, i = 0, cipher_len = strlen(ciphertext);

  // unsgined char is important to use all 32bit (256 chars)
  // for (in theory) the extended ASCII table
  unsigned char plaintext[cipher_len];

  // split the ciphertext by spaces (isolated integers)
  char *word = strtok(ciphertext, " ");

  // reads the private key from file
  readPrivateKeyFile(&d, &n);

  // unless the word is empty
  while (word != NULL)
  {
    // convert "int" to int and calculate:
    //   M = C^d mod n
    // and put it in the right member of plaintext
    plaintext[i] = modexp(atoi(word), d, n);
    // continue splitting the phrase by spaces
    word = strtok(NULL, " ");
    i++;
  }

  // mark last member as null character to terminate
  // when outputing to stdout
  plaintext[i] = '\0';

  // and show the decripted message :)
  printf("%s\n", plaintext);
}

/**
 * @brief write key file and tests for readiness
 * 
 * @param path 
 * @param a 
 * @param b 
 */
void writeKeysInFile(char *path, int *a, int *b)
{
  FILE *file;

  if ((file = fopen(path, "w")) == NULL) {
    fileOpenError(path);
    exit(1);
  }

  fprintf(file, "%u %u", *a, *b);
  fclose(file);
}

/**
 * @brief Get one member from the first prime numbers
 * 
 * @return int 
 */
int getPrime()
{
  static int primes[] = {
    7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113
  };

  // pick one of the prime numbers
  return primes[rand() % ARR_SIZE(primes)];
}

/**
 * @brief generate new prime numbers and write keys
 *
 */
void writeNewKeys()
{
  // p and q
  int d, e, p = 17, q = 11, n, phi;

  // randomness from time (could be something better like urandom)
  srand(time(NULL));

  // generate first prime number
  p = getPrime();

  do {
    // keep generating q if its the same p number
    q = getPrime();
  } while(p == q);

  printf("generated primes are %d %d\n", p, q);

  // product of two primes
  n = p * q;

  // phi is ϕ(n)
  phi = (p - 1) * (q - 1);

  // Select e such that e is relatively prime to phi and less than phi
  e = findFirstCoPrime(phi, 1);

  // Determine d such that de = 1 (mod phi) and d < phi
  d = modinv(e, phi);

  // write the pair of keys
  writeKeysInFile(PUBLIC_FILE, &e, &n);
  writeKeysInFile(PRIVATE_FILE, &d, &n);

  // print the public and private keys
  printf("generated public {%d, %d} private {%d, %d} keys\n", e, n, d, n);
  printf("sucessfully wrote %s and %s\n", PUBLIC_FILE, PRIVATE_FILE);
}

/**
 * @brief
 *
 * @param argc
 * @param argv
 * @return int
 */
int main(int argc, char *argv[])
{
  int opt = getopt(argc, argv, "edwh");

  switch (opt)
  {
  case 'w':
  {
    writeNewKeys();
    break;
  }
  case 'e':
  case 'd':
    if (argc != 3)
    {
      error("encrypt and decrypt operations need argument text");
      return 1;
    }

    if (opt == 'e')
    {
      encryptMessage(argv[2]);
    }

    if (opt == 'd')
    {
      decryptMessage(argv[2]);
    }
    break;

  case 'h':
  default:
    usage(argv[0]);
    return 1;
  }

  return 0;
}