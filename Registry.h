//
// Registry.h
//

#ifdef __cplusplus
extern "C" {
#endif

extern long _RegFindFirst(const char *szPath, struct _finddatai64_t *pfd, DWORD dwType);
extern int _RegFindNext(long handle, struct _finddatai64_t *pfd);
extern int _RegFindClose(long handle);

#ifdef __cplusplus
}
#endif
