/*
 * Från Google..
 *
 */

#include <stdlib.h>
#include <string.h>

static unsigned char codetab[64]={
	'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
	'q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F',
	'G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V',
	'W','X','Y','Z','1','2','3','4','5','6','7','8','9','0','-','_'};


unsigned char decodetab(unsigned char ch)
{
unsigned char c;

  for(c=0;(ch!=codetab[c]) && (c<64);c++);
  if (c>63)
    return -1;
  return c;
}


unsigned char* uuencode(unsigned char* ptr,int len)
{
int s,c,codelen;
unsigned char* codestr;
unsigned long l;

  codelen=((len+2)/3)*4+1;
  
  codestr=(unsigned char*)calloc(codelen+1,1);

  codestr[0]=codetab[len-((len/3)*3)];

  for(s=0,c=1;s<len;s+=3,c+=4) {

    l=((ptr[s])*0x010000)+((ptr[s+1])*0x0100)+(ptr[s+2]);
  
    codestr[c+0]=codetab[(l & 0x00fc0000)>>18];
    codestr[c+1]=codetab[(l & 0x0003f000)>>12];
    codestr[c+2]=codetab[(l & 0x00000fc0)>>6];
    codestr[c+3]=codetab[l  & 0x0000003f];
  }
  
  codestr[codelen]=0;
  return codestr;
}


unsigned char* uudecode(unsigned char* codestr,int* len)
{
int s,c,codelen,sl;
unsigned char* ptr;
unsigned long l;
static int dlt[4] = {0, 2, 1, 0};

  codelen=strlen(codestr);

  (*len)=((codelen / 4) * 3);
  ptr=(unsigned char*)calloc((*len)+4,1);
  sl = dlt[decodetab(codestr[0]) & 3];
  if (*len >= sl) *len -= sl;

  for(s=0,c=1;c<codelen;s+=3,c+=4) {

    l= ((decodetab(codestr[c+0]))<<18);
    l+=((decodetab(codestr[c+1]))<<12);
    l+=((decodetab(codestr[c+2]))<<6);
    l+= (decodetab(codestr[c+3]));

    ptr[s+0]=((l & 0x00ff0000)>>16);
    ptr[s+1]=((l & 0x0000ff00)>>8);
    ptr[s+2]= (l & 0x000000ff);
    
  }
  ptr[s] = 0;

  return ptr;
}

#ifdef MAIN
main()
{
  char str[] = "qwertyuiopasdf";
  int i;

  for (i = 0; i < sizeof(str); i++) {
    char *ptr, *ptr2;
    int len;

    ptr = uuencode(str, i);
    ptr2 = uudecode(ptr, &len);
    printf("%s %s %d %d\n", ptr, ptr2, i, len);
  }
}
#endif
