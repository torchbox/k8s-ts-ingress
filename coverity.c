/*
 * This is not a source file and cannot be compiled.  It provides a Coverity
 * model for the TS API to enable better detection of errors.
 */

struct tsapi_file;
typedef struct tsapi_file *TSFile;
struct tsapi_mbuffer;
typedef struct tsapi_mbuffer *TSMBuffer;
struct tsapi_mloc;
typedef struct tsapi_mloc *TSMLoc;
struct tsapi_mimeparser;
typedef struct tsapi_mimeparser *TSMimeParser;
struct tsapi_httpparser;
typedef struct tsapi_httpparser *TSHttpParser;
struct tsapi_mutex;
typedef struct tsapi_mutex *TSMutex;
struct tsapi_cachekey;
typedef struct tsapi_cachekey *TSCacheKey;
struct tsapi_config;
typedef struct tsapi_config *TSConfig;
struct tsapi_ssl_context;
typedef struct tsapi_ssl_context *TSSslContext;
struct tsapi_httptxn;
typedef struct tsapi_httptxn *TSHttpTxn;
struct tsapi_protocol_set;
typedef struct tsapi_protocol_set *TSNextProtocolSet;
struct tsapi_cont;
typedef struct tsapi_cont *TSCont;
typedef struct tsapi_cont *TSVConn;
struct tsapi_iobuffer;
typedef struct tsapi_iobuffer *TSIOBuffer;
struct tsapi_iobufferblock;
typedef struct tsapi_iobuffer *TSIOBufferBlock;
struct tsapi_iobufferreader;
typedef struct tsapi_iobuffer *TSIOBufferReader;
struct tsapi_iobufferdata;
typedef struct tsapi_iobuffer *TSIOBufferData;
struct tsapi_uuid;
typedef struct tsapi_uuid *TSUuid;
struct tsapi_net_accept;
typedef struct tsapi_net_accept *TSAcceptor;
typedef enum {
  TS_ERROR   = -1,
  TS_SUCCESS = 0,
} TSReturnCode;
typedef int TSEvent;
typedef int TSLifecycleHookID;
typedef int TSHttpHookID;
typedef int TSIOBufferSizeIndex;
typedef int (*TSEventFunc)(TSCont contp, TSEvent event, void *edata);
typedef int int64_t;

void *_TSmalloc(size_t size, const char *path) {
  return __coverity_alloc__(size);
}

void *_TSrealloc(void *ptr, size_t size, const char *path) {
  __coverity_free__(ptr);
  return __coverity_alloc__(size);
}

char *_TSstrdup(const char *str, int64_t length, const char *path) {
  return __coverity_alloc__(length);
}

void _TSfree(void *ptr) {
  __coverity_free__(ptr);
}

TSReturnCode TSHandleMLocRelease(TSMBuffer bufp, TSMLoc parent, TSMLoc mloc) {
  __coverity_free__(mloc);
}

TSFile TSfopen(const char *filename, const char *mode) {
  return __coverity_alloc_nosize__();
}

void TSfclose(TSFile filep) {
  __coverity_free__(filep);
}

size_t TSfread(TSFile filep, void *buf, size_t length) {
  __coverity_tainted_data_argument__(buf);
  __coverity_tainted_data_sink__(length);
}

size_t TSfwrite(TSFile filep, const void *buf, size_t length) {
  __coverity_tainted_data_sink__(length);
}

char *TSfgets(TSFile filep, char *buf, size_t length) {
  __coverity_tainted_data_sink__(length);
  __coverity_tainted_data_argument__(buf);
}

void TSError(const char *fmt, ...) {
  __coverity_format_string_sink__(fmt);
}

void _TSReleaseAssert(const char *txt, const char *f, int l) {
  __coverity_panic__();
}

int _TSAssert(const char *txt, const char *f, int l) {
  __coverity_panic__();
}

TSMBuffer TSMBufferCreate(void) {
  return __coverity_alloc_nosize__();
}

TSReturnCode TSMBufferDestroy(TSMBuffer bufp) {
  __coverity_free__(bufp);
}

TSReturnCode TSUrlCreate(TSMBuffer bufp, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSUrlClone(TSMBuffer dest_bufp, TSMBuffer src_bufp, TSMLoc src_url, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

char *TSUrlStringGet(TSMBuffer bufp, TSMLoc offset, int *length) {
 return __coverity_alloc_nosize__();
}


TSMimeParser TSMimeParserCreate(void) {
  return __coverity_alloc_nosize__();
}

void TSMimeParserDestroy(TSMimeParser parser) {
  __coverity_free__(parser);
}


TSReturnCode TSMimeHdrCreate(TSMBuffer bufp, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSMimeHdrClone(TSMBuffer dest_bufp, TSMBuffer src_bufp, TSMLoc src_hdr, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSMLoc TSMimeHdrFieldGet(TSMBuffer bufp, TSMLoc hdr, int idx) {
  return __coverity_alloc_nosize__();
}

TSMLoc TSMimeHdrFieldFind(TSMBuffer bufp, TSMLoc hdr, const char *name, int length) {
  return __coverity_alloc_nosize__();
}

TSReturnCode TSMimeHdrFieldCreate(TSMBuffer bufp, TSMLoc hdr, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSMimeHdrFieldCreateNamed(TSMBuffer bufp, TSMLoc mh_mloc, const char *name, int name_len, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSMimeHdrFieldClone(TSMBuffer dest_bufp, TSMLoc dest_hdr, TSMBuffer src_bufp, TSMLoc src_hdr, TSMLoc src_field, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSMLoc TSMimeHdrFieldNext(TSMBuffer bufp, TSMLoc hdr, TSMLoc field) {
  return __coverity_alloc_nosize__();
}

TSMLoc TSMimeHdrFieldNextDup(TSMBuffer bufp, TSMLoc hdr, TSMLoc field) {
  return __coverity_alloc_nosize__();
}

TSHttpParser TSHttpParserCreate(void) {
  return __coverity_alloc_nosize__();
}

void TSHttpParserDestroy(TSHttpParser parser) {
  __coverity_free__(parser);
}

TSMLoc TSHttpHdrCreate(TSMBuffer bufp) {
  return __coverity_alloc_nosize__();
}

TSReturnCode TSHttpHdrClone(TSMBuffer dest_bufp, TSMBuffer src_bufp, TSMLoc src_hdr, TSMLoc *locp) {
  int ok;
  if (ok) {
    *locp = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSMutex TSMutexCreate(void) {
  return __coverity_alloc_nosize__();
}

void TSMutexDestroy(TSMutex mutexp) {
  __coverity_free__(mutexp);
}

void TSMutexLock(TSMutex mutexp) {
  __coverity_exclusive_lock_acquire__(mutexp);
}

TSReturnCode TSMutexLockTry(TSMutex mutexp) {
  int unlocked;
  if (unlocked) {
    __coverity_exclusive_lock_acquire__(mutexp);
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

void TSMutexUnlock(TSMutex mutexp) {
  __coverity_exclusive_lock_release__(mutexp);
}

TSCacheKey TSCacheKeyCreate(void) {
  return __coverity_alloc_nosize__();
}

TSReturnCode TSCacheKeyDestroy(TSCacheKey key) {
  __coverity_free__(key);
}

TSConfig TSConfigGet(unsigned int id) {
  return __coverity_alloc_nosize__();
}

void TSConfigRelease(unsigned int id, TSConfig configp) {
  __coverity_free__(configp);
}

TSCont TSContCreate(TSEventFunc funcp, TSMutex mutexp) {
  __coverity_free__(mutexp);
  return __coverity_alloc_nosize__();
}

void TSContDestroy(TSCont contp) {
  __coverity_free__(contp);
}

void TSLifecycleHookAdd(TSLifecycleHookID id, TSCont contp) {
  __coverity_escape__(contp);
}

void TSHttpHookAdd(TSHttpHookID id, TSCont contp) {
  __coverity_escape__(contp);
}

TSSslContext TSSslServerContextCreate(void) {
  return __coverity_alloc_nosize__();
}

void TSSslContextDestroy(TSSslContext ctx) {
  __coverity_free__(ctx);
}

TSNextProtocolSet TSGetcloneProtoSet(TSAcceptor tna) {
  return __coverity_alloc_nosize__();
}

TSReturnCode TSHttpTxnClientReqGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSHttpTxnClientRespGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSHttpTxnServerReqGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSHttpTxnServerRespGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSHttpTxnCachedReqGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSHttpTxnCachedRespGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}


TSReturnCode TSFetchPageRespGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSHttpTxnTransformRespGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  int ok;
  if (ok) {
    *offset = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

TSReturnCode TSHttpTxnPristineUrlGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *url_loc) {
  int ok;
  if (ok) {
    *url_loc = __coverity_alloc_nosize__();
    return TS_SUCCESS;
  } else {
    return TS_ERROR;
  }
}

char *TSHttpTxnEffectiveUrlStringGet(TSHttpTxn txnp, int *length) {
  return __coverity_alloc_nosize__();
}

void TSHttpTxnErrorBodySet(TSHttpTxn txnp, char *buf, size_t buflength, char *mimetype) {
  __coverity_escape__(buf);
  __coverity_escape__(mimetype);
}

TSVConn TSHttpConnectWithPluginId(struct sockaddr const *addr, const char *tag, int64_t id) {
  return __coverity_alloc_nosize__();
}

TSVConn TSHttpConnect(struct sockaddr const *addr) {
  return __coverity_alloc_nosize__();
}

TSVConn TSHttpConnectTransparent(struct sockaddr const *client_addr, struct sockaddr const *server_addr) {
  return __coverity_alloc_nosize__();
}

TSIOBuffer TSIOBufferCreate(void) {
  return __coverity_alloc_nosize__();
}

TSIOBuffer TSIOBufferSizedCreate(TSIOBufferSizeIndex index) {
  return __coverity_alloc_nosize__();
}

void TSIOBufferDestroy(TSIOBuffer bufp) {
  __coverity_free__(bufp);
}

TSIOBufferReader TSIOBufferReaderAlloc(TSIOBuffer bufp) {
  return __coverity_alloc_nosize__();
}

TSIOBufferReader TSIOBufferReaderClone(TSIOBufferReader readerp) {
  return __coverity_alloc_nosize__();
}

void TSIOBufferReaderFree(TSIOBufferReader readerp) {
  __coverity_free__(readerp);
}

void TSDebug(const char *tag, const char *format_str, ...) {
  __coverity_format_string_sink__(format_str);
}

TSVConn TSVConnCreate(TSEventFunc event_funcp, TSMutex mutexp) {
  __coverity_escape__(mutexp);
  return __coverity_alloc_nosize__();
}

TSVConn TSVConnFdCreate(int fd) {
  __coverity_escape__(fd);
  return __coverity_alloc_nosize__();
}

void TSHttpTxnRedirectUrlSet(TSHttpTxn txnp, const char *url, const int url_len) {
  __coverity_escape__(url);
}

void TSRedirectUrlSet(TSHttpTxn txnp, const char *url, const int url_len) {
  __coverity_escape__(url);
}

TSReturnCode TSHttpTxnCachedRespModifiableGet(TSHttpTxn txnp, TSMBuffer *bufp, TSMLoc *offset) {
  *bufp = __coverity_alloc_nosize__();
  *offset = __coverity_alloc_nosize__();
}

TSUuid TSUuidCreate(void) {
  return __coverity_alloc_nosize__();
}

void TSUuidDestroy(TSUuid uuid) {
  __coverity_free__(uuid);
}

const char *TSUrlSchemeGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSUrlUserGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSUrlPasswordGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSUrlHostGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSUrlPathGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSUrlHttpParamsGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSUrlHttpQueryGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSUrlHttpFragmentGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSMimeHdrFieldNameGet(TSMBuffer bufp, TSMLoc hdr, TSMLoc field, int *length) {
  return __coverity_string_null_return__();
}

const char *TSMimeHdrFieldValueStringGet(TSMBuffer bufp, TSMLoc hdr, TSMLoc field, int idx, int *value_len_ptr) {
  return __coverity_string_null_return__();
}

const char *TSHttpHdrMethodGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSHttpHdrHostGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

const char *TSHttpHdrReasonGet(TSMBuffer bufp, TSMLoc offset, int *length) {
  return __coverity_string_null_return__();
}

char *xstrndup(const char *, int len) {
  return __coverity_alloc__(len + 1);
}
