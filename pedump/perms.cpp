
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// A Simple, Efficient P(n,k) Algorithm by Alistair Israel
// http://alistairisrael.wordpress.com/2009/09/22/simple-efficient-pnk-algorithm/
// c implementation by 2014 Randy Lai
// http://rtalks.net

static void swap(char *ar, unsigned int first, unsigned int second)
{
    char temp = ar[first];
    ar[first] = ar[second];
    ar[second] = temp;
}

static void reverse(char *ar, size_t len)
{
    unsigned int i, j;

    for (i = 0, j = len - 1; i < j; i++, j--) {
        swap(ar, i, j);
    }
}

char AInext_k_permutation(char *ar, size_t n, size_t k)
{
    long i;
    long j;
    long edge = k-1;

    if(k<n){
        j = k;
        // search for largest j such that a_j > a_edge (a is increasing for j>=k)
        while(j<n && ar[edge]>=ar[j]) j++;
    }
    if(k<n && j<n){
        swap(ar, edge, j);
    }else{
        if (k<n){
            reverse(ar+k, n-k);
        }

        // find rightmost ascent to left of edge
        i = edge -1;
        while(i>=0 && ar[i]>=ar[i+1]) i--;

        if (i<0) return 0;

        // find smallest j>=i+1 where a_j>a_i (a is decreasing for j>=i+1)
        j = n-1;
        while(j>i && ar[i] >= ar[j]) j--;

        swap(ar, i, j);

        reverse(ar+i+1, n-i-1);
    }

    return 1;
}

int permutations=0;
void kperm (char s[], int len, int start, char out[], int outlen)
{
  int i, slen=strlen(s);
  
  if (len==0) {
    printf ("\n%s", out);
    return;
  }
  for (i=start; i<=slen-len; i++) {
    out[outlen-len] = s[i];
    kperm (s, len-1, i+1, out, outlen);
  }
}

void tperm (void) {
  char str[]="12345678";
  int len=strlen(str);
  char buf[4];
  int outlen=3;
  
  memset (buf, 0, sizeof (buf));
  
  kperm (str, 3, 0, buf, outlen);
}

int main (int argc, char *argv[])
{
  char s[]="123456
  78";
  char c;
  char res[4];
  int t=0;

  tperm();
  return 0;
}
