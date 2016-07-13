#include <stdio.h>
#include <stdlib.h>

#define MAX_N (100)
#define MAX_K (100)

void swap(int *a, int *b)
{
	int tmp = *a;
	*a = *b;
	*b = tmp;
}

void perm_recursive(char *a[], int b[], int j, int k)
{
	int i;
	if (j >= k) {
		for (i = 0; i < k; i++) {
			printf(i < k-1 ? "%s " : "%s\n", a[b[i]]);
		}
	} else {
		for (i = j; i < k; i++) {
			swap(&b[i], &b[j]);
			perm_recursive(a, b, j+1, k);
			swap(&b[i], &b[j]);
		}
	}
}

void comb_recursive(char *a[], int n, int m, int b[], const int k)
{
	int i, j;
	for (i = n; i >= m; i--) {
		b[m-1] = i-1;
		if (m > 1) {
			comb_recursive(a, i-1, m-1, b, k);
		} else {
			perm_recursive(a, b, 0, k);
			/* for combination only
			for (j = 0; j < k; j++) {
				printf(j < k - 1 ? "%d " : "%d\n", a[b[j]]);
			}
			*/
		}
	}
}

// 8! / ((8 - 3)! * 3!) = 56

// 40320 / 120 * 6

// we also don't want any repititions


int main()
{
	int num[MAX_N], idx[MAX_K];
	char *a[] = {"one","two","three","four"};
	
  comb_recursive (a, 4, 4, idx, 4);
	exit(0);
}
