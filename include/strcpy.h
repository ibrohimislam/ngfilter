/********************************************************************************/
/* strcpy_safe - Copy src string to dst string, upto maxlen characters.         */
/* Safer than strncpy, because it does not fill destination string,             */
/* but only copies up to the length needed.  Src string should be               */
/* null-terminated, and must-be if its allocated length is shorter than maxlen. */
/* Up to maxlen-1 characters are copied to dst string. The dst string is always */
/* null-terminated.  The dst string should be pre-allocated to at least maxlen  */
/* bytes.  However, this function will work safely for dst arrays that are less */
/* than maxlen, as long as the null-terminated src string is known to be        */
/* shorter than the allocated length of dst, just like regular strcpy.          */
/********************************************************************************/

#ifndef _STRCPY_H
#define _STRCPY_H

void strcpy_safe( char *dst, const char *src, int maxlen )
{ 
  int j=0, oneless;

  oneless = maxlen - 1;
  while ((j < oneless) && (src[j] != '\0')) {
    dst[j] = src[j];
    j++;
  }
  dst[j] = '\0';
}

#endif /* _LINUX_NETFILTER_XT_NGFILTER_H */
