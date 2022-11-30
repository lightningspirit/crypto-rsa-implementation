/**
 * @file symetric.c
 * @author Vitor Carvalho (1401892@estudante.uab.pt)
 * @brief 
 * @version 0.1
 * @date 2022-11-24
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief the usage message
 *
 * @param invoker
 */
void usage(char *invoker)
{
  fprintf(stderr, "Usage: %s <option> [args...]\n -e <plaintext>\t\tencrypt text message\n -d <ciphertext>\tdecrypt previously encrypted message\n", invoker);
}

/**
 * @brief encrypts the plaintext
 * 
 * @param plaintext 
 */
void encryptMessage(char *plaintext)
{
  int i, shift = 3, c = 0;

  for (i = 0; plaintext[i] != '\0'; i++)
  {
    c = ((int) plaintext[i] + shift) % 128;
    printf("%d ", c);
  }

  printf("\n");
}

/**
 * @brief decrypts the ciphertext
 * 
 * @param ciphertext 
 */
void decryptMessage(char *ciphertext)
{
  int i = 0, shift = 3, cipher_len = strlen(ciphertext);
  char plaintext[cipher_len];
  char *word = strtok(ciphertext, " ");

  while (word != NULL)
  {
    plaintext[i] = (atoi(word) - shift) % 128;
    word = strtok(NULL, " ");
    i++;
  }

  plaintext[i] = '\0';

  printf("%s\n", plaintext);
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
  int opt = getopt(argc, argv, "edh");

  switch (opt)
  {
  case 'e':
    encryptMessage(argv[2]);
    break;
  case 'd':
    decryptMessage(argv[2]);
    break;

  case 'h':
  default:
    usage(argv[0]);
    return 1;
  }

  return 0;
}