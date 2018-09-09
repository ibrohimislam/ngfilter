#include <linux/string.h>

#define NO_OF_CHARS 256
 
static void computeTransFun(const char *pat, __u32 M, __u32 TF[][NO_OF_CHARS]) {
  __u32 i, lps, x;
  __u8 symbol;

  lps = 0;

  for (x = 0; x < NO_OF_CHARS; x++)
     TF[0][x] = 0;
  
  symbol = (__u8) pat[0];
  TF[0][symbol] = 1;
 
  for (i = 1; i<= M; i++) {

    symbol = (__u8)pat[i];
    
    for (x = 0; x < NO_OF_CHARS; x++)
      TF[i][x] = TF[lps][x];
 
    TF[i][symbol] = i + 1;
 
    if (i < M)
      lps = TF[lps][symbol];
  }
}
 
bool string_match(const char *pattern, const char *text, const __u32 pattern_length, const __u32 text_length) {
  __u32 i, j;
  __u32 TF[pattern_length+1][NO_OF_CHARS];
 
  computeTransFun(pattern, pattern_length, TF);
 
  for (i=0, j=0; i < text_length; i++) {
    __u8 symbol = (__u8) text[i];
    j = TF[j][symbol];

    if (j == pattern_length) {
      return 1;
    }
  }

  return 0;
}