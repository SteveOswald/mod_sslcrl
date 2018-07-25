/**
 * CRL check for SSL client certificates.
 * See http://opensource.adnovum.ch/mod_sslcrl/ for further details.
 *
 * Copyright (C) 2010-2016 Pascal Buchbinder
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*                      _             _           _ 
 *  _ __ ___   ___   __| |    ___ ___| | ___ _ __| |
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |/ __| '__| |
 * | | | | | | (_) | (_| |   \__ \__ \ | (__| |  | |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|\___|_|  |_|
 *                      |_____|                     
 */

/************************************************************************
 * Version
 ***********************************************************************/
static const char revision[] = "$Id: mod_sslcrl.c,v 1.81 2016/06/18 14:51:45 pbuchbinder Exp $";
static const char g_revision[] = "1.10";

/************************************************************************
 * Includes
 ***********************************************************************/

#include <Windows.h>


/* openssl */
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

/* apache */
#include <httpd.h>
#include <http_core.h>
#include <http_main.h>
#include <http_request.h>
#include <http_connection.h>
#include <http_protocol.h>
#define CORE_PRIVATE
#include <http_config.h>
#undef CORE_PRIVATE
#include <http_log.h>
#include <util_filter.h>
#include <mod_ssl.h>
//#include <mod_proxy.h>
#include <mod_status.h>

/* apr */
#include <apr_lib.h>
#include <apr_hooks.h>
#include <apr_strings.h>
#ifdef AP_NEED_SET_MUTEX_PERMS
#include <unixd.h>
#endif
#include <apr_date.h>

/* apr network */
#include <apr_network_io.h>
#include <apr_errno.h>
#include <apr_general.h>
#include <apr_lib.h>

/************************************************************************
 * defines
 ***********************************************************************/
#define SSLCRL_LOG_PFX(id)  "mod_sslcrl("#id"): "
#define SSLCRL_SESSIONID    "SSLCRL_SESSION_ID"
#define SSLCRLLCK           ".lck"
#define SSLCRLSM            ".sem"
#define SSLCRL_USR_SPE      "SSLCRLSHM"
#define SSLCRL_MAX_DEPTH    10
#ifndef SSLCRL_MIN_INTERVAL
#define SSLCRL_MIN_INTERVAL 60
#endif
#define SSLCRL_MAX_RES_LEN  5242880
#define SSLCRL_VRF          "verify"
#define SSLCRL_CONN         "sslcrl::download"
// Apache 2.4 compat
#if (AP_SERVER_MINORVERSION_NUMBER == 4)
#define SSLCRL_ISDEBUG(s) APLOG_IS_LEVEL(s, APLOG_DEBUG)
#else
#define SSLCRL_ISDEBUG(s) s->loglevel >= APLOG_DEBUG
#endif

#undef SSLCRL_DISABLE_DEBUG 1

/************************************************************************
 * structures
 ***********************************************************************/

typedef struct {
  apr_uri_t parsed_uri;
  char *proxyhost;
  int proxyport;
  int verifiedonly;
} sslcrl_entry_t;

typedef struct {
  apr_interval_time_t nextupdate;
  apr_interval_time_t fileupdate;
  int status;
} sslcrl_shm_t;

typedef struct {
  char *host;
  int port;
  apr_sockaddr_t *addr;
} sslcrl_host_t;

typedef struct {
  apr_table_t *crlurltable;
  apr_global_mutex_t *lock;
  char *lockfile;
  const char *cache_file;
  X509_STORE *crl;
  int failclose;
  apr_interval_time_t interval;
  apr_table_t *chains;
  apr_table_t *contenttypes;
  char *headername;
  char *headervalue;
  int proxyenabled;
  apr_table_t *signaturAlgorithms;
} sslcrl_config_t;

typedef struct {
  int enabled;
} sslcrl_dir_config_t;

typedef struct {
  int counter;
  int processed;
  conn_rec *c;
  sslcrl_config_t *sconf;
} sslcrl_outf_t;

/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA sslcrl_module;

// per process update flag
static apr_interval_time_t m_loadstore = 0;

static APR_OPTIONAL_FN_TYPE(ssl_proxy_enable) *sslcrl_m_ssl_enable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_engine_disable) *sslcrl_m_ssl_disable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *sslcrl_var = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *sslcrl_is_https = NULL;

/************************************************************************
 * private
 ***********************************************************************/

static apr_status_t sslcrl_download_crl(sslcrl_config_t *sconf, const char *host, int port, const char *url, char **body, int *body_len)
{
	apr_status_t rv;
	apr_pool_t *mp;
	apr_socket_t *s;

	apr_initialize();
	apr_pool_create(&mp, NULL);

	rv = sslcrl_download_crl_connect(&s, mp, host, port);
	if (rv != APR_SUCCESS) {
		char errbuf[256];
		apr_strerror(rv, errbuf, sizeof(errbuf));

		*body = apr_pstrcat(mp, "Error: ", errbuf, NULL);

		apr_terminate();
		return rv;
	}

	rv = sslcrl_download_crl_send_request(s, url, host, mp, body, body_len);
	if (rv != APR_SUCCESS) {
		char errbuf[256];
		apr_strerror(rv, errbuf, sizeof(errbuf));

		*body = apr_pstrcat(mp, "Error: ", errbuf, NULL);

		apr_terminate();
		return rv;
	}

	apr_socket_close(s);
	apr_pool_clear(mp);
	apr_terminate();

	return APR_SUCCESS;
}

/**
* Connect to the remote host
*/
static apr_status_t sslcrl_download_crl_connect(apr_socket_t **sock, apr_pool_t *mp, const char *host, int port)
{
	apr_sockaddr_t *sa;
	apr_socket_t *s;
	apr_status_t rv;

	rv = apr_sockaddr_info_get(&sa, host, APR_INET, port, 0, mp);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	rv = apr_socket_create(&s, sa->family, SOCK_STREAM, APR_PROTO_TCP, mp);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	/* it is a good idea to specify socket options explicitly.
	* in this case, we make a blocking socket with timeout. */
	apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
	apr_socket_timeout_set(s, (APR_USEC_PER_SEC * 30));

	rv = apr_socket_connect(s, sa);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	/* see the tutorial about the reason why we have to specify options again */
	apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
	apr_socket_timeout_set(s, (APR_USEC_PER_SEC * 30));

	*sock = s;
	return APR_SUCCESS;
}

/**
* Send a request as a simple HTTP request protocol.
* Write the received response to the standard output until the EOF.
*/
static apr_status_t sslcrl_download_crl_send_request(apr_socket_t *sock, const char *filepath, const char *host, apr_pool_t *mp, char **body, int *body_len)
{
	apr_status_t rv;
	const char *req_hdr = apr_pstrcat(mp, "GET ", filepath, " HTTP/1.1", CRLF, "Host: ", host, CRLF, CRLF, NULL);
	apr_size_t len = strlen(req_hdr);
	char *output = "";

	rv = apr_socket_send(sock, req_hdr, &len);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	while (1) {
		char buf[4096];
		apr_size_t len = sizeof(buf);

		rv = apr_socket_recv(sock, buf, &len);
		if (rv == APR_EOF || len == 0) {
			rv = APR_SUCCESS;
			break;
		}

		output = apr_pstrcat(mp, output, apr_pstrmemdup(mp, buf, len), NULL);
	}

	*body = output;
	*body_len = strlen(output);

	return rv;
}



/**
 * Allocates the shared memory which is used to signalize updates.
 *
 * @param ppool Process/user pool (persitent/survives server config reload).
 * @param sconf
 * @return
 */
static sslcrl_shm_t *sslcrl_get_shm(apr_pool_t *ppool, sslcrl_config_t *sconf) {
  void *v;
  sslcrl_shm_t *u;
  apr_pool_userdata_get(&v, SSLCRL_USR_SPE, ppool);
  u = v;
  if(v) {
    return v;
  } else {
    char *file = "-";
    apr_interval_time_t now = apr_time_sec(apr_time_now());
    apr_shm_t *m;
    /* use anonymous shm by default */
    apr_size_t size = APR_ALIGN_DEFAULT(sizeof(sslcrl_shm_t)) + 1024;
    apr_status_t res = apr_shm_create(&m, size, NULL, ppool);
    if(APR_STATUS_IS_ENOTIMPL(res)) {
      file = apr_psprintf(ppool, "%s"SSLCRLSM, sconf->cache_file);
      apr_shm_remove(file, ppool);
      res = apr_shm_create(&m, size, file, ppool);
    }
    if(res != APR_SUCCESS) {
      char buf[MAX_STRING_LEN];
      apr_strerror(res, buf, sizeof(buf));
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL,
                   SSLCRL_LOG_PFX(000)"failed to create shared memory (%s):"
                   " %s (%"APR_SIZE_T_FMT" bytes)",
                   file, buf, size);
      return NULL;
    }
    u = apr_shm_baseaddr_get(m);
    u->nextupdate = ((now / sconf->interval) * sconf->interval) + sconf->interval;
    u->fileupdate = u->nextupdate + (SSLCRL_MIN_INTERVAL / 2);
    u->status = -1;
    m_loadstore = 0;
    apr_pool_userdata_set(u, SSLCRL_USR_SPE, apr_pool_cleanup_null, ppool);
    return u;
  }
}

#ifndef SSLCRL_DISABLE_DEBUG
/**
 * debug only - logs the content of the loaded CRL store
 */
static void sslcrl_dumpcrl(server_rec *s, const char *cpFile) {
  BIO *in = BIO_new(BIO_s_file_internal());
  BIO_read_filename(in, cpFile);
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
               "child %d - load CRL store '%s'",
               getpid(), cpFile);

  for(;;) {
    X509_CRL *x = NULL;
    X509_NAME *xn = NULL;
    x = PEM_read_bio_X509_CRL(in, NULL ,NULL,NULL);
    if(x == NULL) {
      break;
    }
    if((xn = X509_CRL_get_issuer(x)) == NULL) {
      X509_CRL_free(x);
      break;
    } else {
      char name_buf[256];
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                   "child %d ==> CRL issued by '%s'",
                   getpid(),
                   X509_NAME_oneline(xn, name_buf, sizeof(name_buf)));
    }
    X509_CRL_free(x);
  }
  BIO_free(in);
}

/**
 * debug only - logs the content of the loaded CA stores
 */
static void sslcrl_dumpstore(server_rec * s, const char *cpFile) {
  STACK_OF(X509_NAME) *sk;
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
               "child %d - load CA file '%s'",
               getpid(), cpFile);
  sk = (STACK_OF(X509_NAME) *)SSL_load_client_CA_file(cpFile);
  if(sk) {
    int n;
    for(n = 0; n < sk_X509_NAME_num(sk); n++) {
      char name_buf[256];
      X509_NAME *name = sk_X509_NAME_value(sk, n);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                   "child %d ==> CA certificate '%s'",
                   getpid(),
                   X509_NAME_oneline(name, name_buf, sizeof(name_buf)));
      X509_NAME_free(name);
    }
    sk_X509_NAME_free(sk);
  }
}
#endif

/**
 * Loads the CA certificates which are used to validate the received CRLs
 *
 * @param cpPath File path-
 * @return Cert store
 */
static X509_STORE *sslcrl_X509_STORE_create_path(server_rec *s, const char *cpPath) {
  X509_STORE *pStore;
  X509_LOOKUP *pLookup;
  int rv = 1;
  if (cpPath == NULL) {
    return NULL;
  }
  if ((pStore = X509_STORE_new()) == NULL) {
    return NULL;
  }
  pLookup = X509_STORE_add_lookup(pStore, X509_LOOKUP_hash_dir());
  if(pLookup == NULL) {
    X509_STORE_free(pStore);
    return NULL;
  }
  rv = X509_LOOKUP_add_dir(pLookup, cpPath, X509_FILETYPE_PEM);

#ifndef SSLCRL_DISABLE_DEBUG
  if(SSLCRL_ISDEBUG(s)) {
    if(rv == 1) {
      apr_pool_t *ptemp;
      apr_dir_t *dir;
      apr_finfo_t direntry;
      apr_int32_t finfo_flags = APR_FINFO_TYPE|APR_FINFO_NAME;
      apr_pool_create(&ptemp, NULL);

      if(apr_dir_open(&dir, cpPath, ptemp) == APR_SUCCESS) {
        while((apr_dir_read(&direntry, finfo_flags, dir)) == APR_SUCCESS) {
          const char *file;
          if(direntry.filetype == APR_DIR) {
            continue;
          }
          file = apr_pstrcat(ptemp, cpPath, "/", direntry.name, NULL);
          sslcrl_dumpstore(s, file);
        }
      }
      apr_pool_destroy(ptemp);
    }
  }
#endif

  return rv == 1 ? pStore : NULL;
}

/**
 * Loads the cached CRL store resp. a CA chain file.
 *
 * @param s
 * @param cpFile Path to the file storing the PEM encoded CRLs.
 * @param crl Indicates, if we load a CRL or CA store (for debugging only)
 * @return CRL or CA store
 */
static X509_STORE *sslcrl_X509_STORE_create(server_rec * s, const char *cpFile,
                                            int crl) {
  X509_STORE *pStore;
  X509_LOOKUP *pLookup;
  int rv = 1;
  if(cpFile == NULL) {
    return NULL;
  }
  if((pStore = X509_STORE_new()) == NULL) {
    return NULL;
  }
  pLookup = X509_STORE_add_lookup(pStore, X509_LOOKUP_file());
  if(pLookup == NULL) {
    X509_STORE_free(pStore);
    return NULL;
  }
  rv = X509_LOOKUP_load_file(pLookup, cpFile, X509_FILETYPE_PEM);

#ifndef SSLCRL_DISABLE_DEBUG
  if(SSLCRL_ISDEBUG(s)) {
    if(rv == 1) {
      if(crl) {
        sslcrl_dumpcrl(s, cpFile);
      } else {
        sslcrl_dumpstore(s, cpFile);
      }
    }
  }
#endif

  return rv == 1 ? pStore : NULL;
}

/**
 * Method to fetch a CRL from the CRL store.
 *
 * @param pStore CRL store
 * @param nType Object type to search (X509_LU_CRL)
 * @param pName Name of the object (either issuer or subject).
 * @param pObj Object to store result to
 * @return
 */

static int sslcrl_X509_STORE_lookup(X509_STORE *pStore, int nType,
                                    X509_NAME *pName, X509_OBJECT *pObj) {
  X509_STORE_CTX pStoreCtx;
  int rc;
  X509_STORE_CTX_init(&pStoreCtx, pStore, NULL, NULL);
  rc = X509_STORE_get_by_subject(&pStoreCtx, nType, pName, pObj);
  X509_STORE_CTX_cleanup(&pStoreCtx);
  return rc;
}

/**
 * Sessionid, subject and issuer which is used to recognize a cache entry
 *
 * @param r
 * @return Id
 */
static char *sslcrl_sid(request_rec *r) {
  const char *sid = sslcrl_var(r->pool, r->server, r->connection, r, "SSL_SESSION_ID");
  const char *sdn = sslcrl_var(r->pool, r->server, r->connection, r, "SSL_CLIENT_S_DN");
  const char *idn = sslcrl_var(r->pool, r->server, r->connection, r, "SSL_CLIENT_I_DN");
  char *id = apr_pstrcat(r->pool, sid, sdn, idn, NULL);
  return id;
}

/**
 * Check for a certificate (either the client cert or any issuer within
 * the chain) for revocation.
 *
 * @param r
 * @param sconf
 * @param cert Certificate to check
 * @return DECLINED if okay, HTTP_FORBIDDEN if revoked
 */
static int sslcrl_check_cert(request_rec *r, sslcrl_config_t *sconf, X509 *cert) {
  int status = DECLINED;
  X509_CRL *crl = NULL;
  X509_OBJECT *obj = apr_pcalloc(r->pool, sizeof(X509_OBJECT));
  X509_NAME *subject = NULL;
  X509_NAME *issuer = NULL;

  issuer  = X509_get_issuer_name(cert);
  subject = X509_get_subject_name(cert);

   if(sconf->signaturAlgorithms != NULL) {
    char sigAlg[256];
    OBJ_obj2txt(sigAlg, sizeof(sigAlg), cert->sig_alg->algorithm, 0);
    if(apr_table_get(sconf->signaturAlgorithms, sigAlg) == NULL) {
      char *cp = X509_NAME_oneline(subject, NULL, 0);
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    SSLCRL_LOG_PFX(035)"signature algorithm '%s' of"
                    " certificate [%s] is not allowed",
                    sigAlg, cp);
      apr_table_set(r->notes, "error-notes", "mod_sslcrl(035)");
      OPENSSL_free(cp);
      return HTTP_FORBIDDEN;
    }
  }

  if(SSLCRL_ISDEBUG(r->server)) {
    char *cp = X509_NAME_oneline(subject, NULL, 0);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "revocation check [%s]", cp);
    OPENSSL_free(cp);
  }
  apr_global_mutex_lock(sconf->lock);                   /* >@CRT2 */
  crl = NULL;
  if(sconf->crl) {
    if(sslcrl_X509_STORE_lookup(sconf->crl, X509_LU_CRL, issuer, obj) > 0) {
      apr_pool_t *cpool;
      apr_pool_create(&cpool, r->pool);
      crl = obj->data.crl;
      apr_pool_cleanup_register(cpool, (void*)obj, (int(*)(void*))X509_OBJECT_free_contents,
                                apr_pool_cleanup_null);
    }
  }
  if(crl) {
    int i;
    int n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
    if(SSLCRL_ISDEBUG(r->server)) {
      char *cp = X509_NAME_oneline(subject, NULL, 0);
      char *is = X509_NAME_oneline(issuer, NULL, 0);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "found issuer's [%s] CRL to check [%s]", is, cp);
      OPENSSL_free(cp);
      OPENSSL_free(is);
    }
    for(i = 0; i < n; i++) {
      X509_REVOKED *revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
      ASN1_INTEGER *sn = revoked->serialNumber;
      if(!ASN1_INTEGER_cmp(sn, X509_get_serialNumber(cert))) {
        char *cp = X509_NAME_oneline(issuer, NULL, 0);
        long serial = ASN1_INTEGER_get(sn);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      SSLCRL_LOG_PFX(034)"certificate with serial %ld has been revoked"
                      " (per CRL from issuer '%s')", serial, cp);
        apr_table_set(r->notes, "error-notes", "mod_sslcrl(034)");
        OPENSSL_free(cp);
        status = HTTP_FORBIDDEN;
        break;
      }
    }
  } else {
    char *cp = X509_NAME_oneline(subject, NULL, 0);
    char *is = X509_NAME_oneline(issuer, NULL, 0);
    int severity = APLOG_WARNING;
    if(sconf->failclose == 1) {
      severity = APLOG_ERR;
      status = HTTP_FORBIDDEN;
    }
    ap_log_rerror(APLOG_MARK, severity, 0, r,
                  SSLCRL_LOG_PFX(041)"no CRL of issuer [%s] available,"
                  " can't verify [%s] [hint: SSLCRL_Url]", is, cp);
    OPENSSL_free(cp);
    OPENSSL_free(is);
  }
  apr_global_mutex_unlock(sconf->lock);                 /* <@CRT2 */

  return status;
}

/**
 * Verifies the signer/CA certificate
 *
 * @param r
 * @param sconf
 * @param cert Certificate to verifiy
 * @return DECLINED if okay, HTTP_FORBIDDEN if CRL is not valid
 */
static int sslcrl_check_ca(request_rec *r, sslcrl_config_t *sconf, X509 *cert) {
  int status = DECLINED;
  X509_CRL *crl = NULL;
  X509_OBJECT *obj = apr_pcalloc(r->pool, sizeof(X509_OBJECT));
  X509_NAME *subject = NULL;
  
  subject = X509_get_subject_name(cert);
  if(SSLCRL_ISDEBUG(r->server)) {
    char *cp = X509_NAME_oneline(subject, NULL, 0);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "CA check [%s]", cp);
    OPENSSL_free(cp);
  }
  apr_global_mutex_lock(sconf->lock);                   /* >@CRT1 */
  crl = NULL;
  if(sconf->crl) {
    if(sslcrl_X509_STORE_lookup(sconf->crl, X509_LU_CRL, subject, obj) > 0) {
      apr_pool_t *cpool;
      apr_pool_create(&cpool, r->pool);
      crl = obj->data.crl;
      apr_pool_cleanup_register(cpool, (void*)obj, (int(*)(void*))X509_OBJECT_free_contents,
                                apr_pool_cleanup_null);
    }
  }
  if(crl) {
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    int rc = X509_CRL_verify(crl, pubkey);
#ifdef OPENSSL_VERSION_NUMBER
    /* Only refcounted in OpenSSL */
    if (pubkey) {
      EVP_PKEY_free(pubkey);
    }
#endif
    if(rc <= 0) {
      char *cp = X509_NAME_oneline(subject, NULL, 0);
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    SSLCRL_LOG_PFX(031)"invalid signature on CRL (%s)", cp);
      OPENSSL_free(cp);
      apr_table_set(r->notes, "error-notes", "mod_sslcrl(031)");
      status = HTTP_FORBIDDEN;
    } else {
      rc = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));
      if(rc == 0) {
        char *cp = X509_NAME_oneline(subject, NULL, 0);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      SSLCRL_LOG_PFX(032)"found CRL has invalid nextUpdate field (%s)", cp);
        apr_table_set(r->notes, "error-notes", "mod_sslcrl(032)");
        OPENSSL_free(cp);
        status = HTTP_FORBIDDEN;
      }
      if(rc < 0) {
        char *cp = X509_NAME_oneline(subject, NULL, 0);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      SSLCRL_LOG_PFX(033)"found CRL is expired - "
                      "revoking all certificates until you get updated CRL (%s)", cp);
        apr_table_set(r->notes, "error-notes", "mod_sslcrl(033)");
        OPENSSL_free(cp);
        status = HTTP_FORBIDDEN;
      }            
    }
  }
  apr_global_mutex_unlock(sconf->lock);                 /* <@CRT1 */
  return status;
}

/**
 * Checks all certs in the chain.
 *
 * @param r
 * @param sconf
 * @param cert
 * @return DECLINED if okay, otherwise HTTP_FORBIDDEN
 */
static int sslcrl_check_chain(request_rec *r, sslcrl_config_t *sconf, X509 *cert) {
  int depth = 0;
  int status = DECLINED;
  X509_NAME *issuer  = X509_get_issuer_name(cert);
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->chains)->elts;
  apr_pool_t *cpool;
  apr_pool_create(&cpool, r->pool);

  // search the rigth chain
  for(i = 0; i < apr_table_elts(sconf->chains)->nelts; i++) {
    X509 *cacert = NULL;
    X509_OBJECT *obj = apr_pcalloc(r->pool, sizeof(X509_OBJECT));
    X509_STORE *store = (X509_STORE *)entry[i].val;
    // lookup() function may need a sort on the stack
    apr_global_mutex_lock(sconf->lock);                 /* >@CRT8 */
    if(sslcrl_X509_STORE_lookup(store, X509_LU_X509, issuer, obj) > 0) {
      cacert = obj->data.x509;
      apr_pool_cleanup_register(cpool, (void*)obj, (int(*)(void*))X509_OBJECT_free_contents,
                                apr_pool_cleanup_null);
    }
    apr_global_mutex_unlock(sconf->lock);               /* <@CRT8 */
    if(cacert) {
      // this is the correct chain...
      X509 *next = cacert;
      while(next && (depth < SSLCRL_MAX_DEPTH)) {
        X509_NAME *subject = issuer;
        if(sslcrl_check_cert(r, sconf, next) != DECLINED) {
          return HTTP_FORBIDDEN;
        }
        if(sslcrl_check_ca(r, sconf, next) != DECLINED) {
          return HTTP_FORBIDDEN;
        }
        issuer = X509_get_issuer_name(next);
        if(!X509_name_cmp(issuer, subject)) {
          // self signed, end of chain
          next = NULL;
        } else {
          obj = apr_pcalloc(r->pool, sizeof(X509_OBJECT));
          apr_global_mutex_lock(sconf->lock);            /* >@CRT9 */
          if(sslcrl_X509_STORE_lookup(store, X509_LU_X509, issuer, obj) > 0) {
            next = obj->data.x509;
            apr_pool_cleanup_register(cpool, (void*)obj, 
                                      (int(*)(void*))X509_OBJECT_free_contents,
                                      apr_pool_cleanup_null);
          } else {
            next = NULL;
          }
          apr_global_mutex_unlock(sconf->lock);          /* <@CRT9 */
        }
        depth++;
      }
      break;
    }
  }
  return status;
}

/**
 * Starts crl verification steps.
 *
 * @param r
 * @param sconf
 * @param pem Cert from mod_ssl
 * @return DECLINED if okay
 */
static int sslcrl_check(request_rec *r, sslcrl_config_t *sconf, const char *pem) {
  int status = DECLINED;
  char *sid;
  BIO *bio = BIO_new(BIO_s_mem());
  X509 *cert = NULL;
  
  BIO_write(bio, pem, strlen(pem));
  PEM_read_bio_X509(bio, &cert, NULL, NULL);
  BIO_free(bio);
  if(cert == NULL) {
    // failed to cread cert?!
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  SSLCRL_LOG_PFX(030)"failed to read client certificate (%d)",
                  HTTP_INTERNAL_SERVER_ERROR);
    apr_table_set(r->notes, "error-notes", "mod_sslcrl(030)");
    return HTTP_INTERNAL_SERVER_ERROR;
  } else {
    apr_pool_t *cpool;
    apr_pool_create(&cpool, r->pool);
    apr_pool_cleanup_register(cpool, (void*)cert, (int(*)(void*))X509_free,
                              apr_pool_cleanup_null);
  }
  if(sslcrl_check_cert(r, sconf, cert) != DECLINED) {
    // no more checks
    return HTTP_FORBIDDEN;
  }
  if(sslcrl_check_chain(r, sconf, cert) != DECLINED) {
    // no more checks
    return HTTP_FORBIDDEN;
  }
  // everything is okay, check only once
  sid = sslcrl_sid(r);
  apr_table_set(r->connection->notes, SSLCRL_SESSIONID, sid);
  return status;
}

/**
 * Resolve hostname to connect to
 *
 * @param pool
 * @param host Server name
 * @param port
 * @param msg Erro message if lookup has failed
 * @return NULL on error
 */
static sslcrl_host_t* sslcrl_resolve(apr_pool_t *pool, const char *host, int port, char **msg) {
  sslcrl_host_t *h = apr_pcalloc(pool, sizeof(sslcrl_host_t));
  *msg = NULL;
  h->host = apr_pstrdup(pool, host);
  h->port = port;
  if(apr_sockaddr_info_get(&h->addr, host, APR_INET, port, 0, pool) != APR_SUCCESS) {
    *msg = apr_psprintf(pool, "Could not resolve hostname '%s:%d'.", host, port);
    return NULL;
  }
  return h;
}

/** creates recques_rec */
static request_rec *sslcrl_make_fake_req(conn_rec *c, apr_pool_t *pool) {
  request_rec *rp = apr_pcalloc(pool, sizeof(request_rec));
  rp->pool            = pool;
  rp->status          = HTTP_OK;
  rp->headers_in      = apr_table_make(pool, 50);
#if (AP_SERVER_MINORVERSION_NUMBER == 2) && (AP_SERVER_PATCHLEVEL_NUMBER >= 29)
  /* Apache 2.2.29 breaks binary compatibility and the module has to be
     re-compiled */
  rp->trailers_in     = apr_table_make(pool, 5);
  rp->trailers_out    = apr_table_make(pool, 5);
#endif
  rp->subprocess_env  = apr_table_make(pool, 50);
  rp->headers_out     = apr_table_make(pool, 12);
  rp->err_headers_out = apr_table_make(pool, 5);
  rp->notes           = apr_table_make(pool, 5);
  rp->server = c->base_server;
  //  rp->proxyreq = PROXYREQ_PROXY;
  rp->proxyreq = PROXYREQ_NONE;
  rp->request_time = apr_time_now();
  rp->connection      = c;
  rp->output_filters  = c->output_filters;
  rp->input_filters   = c->input_filters;
  rp->proto_output_filters  = c->output_filters;
  rp->proto_input_filters   = c->input_filters;
  rp->request_config  = ap_create_request_config(pool);
  return rp;
}

/**
 * Validates, if response is a PEM CRL
 *
 * @param pool
 * @param body CRL data
 * @param body_len
 * @return 1 or okay
 */
static int validate_pem(apr_pool_t *pool, char *body, int body_len) {
  BIO *bio = BIO_new(BIO_s_mem());
  X509_CRL *x=NULL;
  BIO_write(bio, body, body_len);
  PEM_read_bio_X509_CRL(bio, &x, NULL, NULL);
  BIO_free(bio);
  if(x == NULL) {
    return 0;
  }
  X509_CRL_free(x);
  return 1;
}

/**
 * Converts a DER encoded CRL to PEM
 *
 * @param pool
 * @param der 
 * @param der_len
 * @param err
 * @return The PEM encoded CRL or NULL on error (see message in err).
 */
static char *sslcrl_der2pem(apr_pool_t *pool, const unsigned char *der, int der_len, char **err) {
  char *pem = NULL;
  X509_CRL *cert = NULL;
  int n;
  BIO *bio;
  cert = d2i_X509_CRL(NULL, &der, der_len);
  if(cert == NULL) {
    *err = apr_psprintf(pool, "Failed to convert DER data.");
    return NULL;
  }
  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_CRL(bio, cert);
  n = BIO_pending(bio);
  pem = apr_pcalloc(pool, n+1);
  n = BIO_read(bio, pem, n);
  pem[n] = '\0';
  BIO_free(bio);

  return pem;
}

/**
 * Verifies the signature or a downloaded CRL
 *
 * @param pool
 * @param s
 * @param sconf
 * @param pem CRL to check 
 * @param msg Error message
 * @param url URL we have downloaded the CRL from (for logging)
 * @return 1 if signature could be verified, 0 if not
 */
static int sslcrl_verify_crl_sig(apr_pool_t *pool, server_rec *s, sslcrl_config_t *sconf,
                                 const char *pem, char **msg, const char *url) {
  int valid = 0; // 1=signed by loaded ca
  int found = 0;
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->chains)->elts;
  BIO *bio = BIO_new(BIO_s_mem());
  X509_CRL *x=NULL;
  X509_NAME *issuer = NULL;
  *msg = NULL;
  BIO_write(bio, pem, strlen(pem));
  PEM_read_bio_X509_CRL(bio, &x, NULL, NULL);
  BIO_free(bio);
  if(x == NULL) {
    return valid;
  }
  issuer = X509_CRL_get_issuer(x);
  if(X509_CRL_get_nextUpdate(x)) {
    time_t ptime = time(NULL) + sconf->interval;
    int n = X509_cmp_time(X509_CRL_get_nextUpdate(x), &ptime);
    if(n < 0) {
      ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                   SSLCRL_LOG_PFX(040)"CRL from '%s' expires before next update", url);
    }
  }
  if(issuer) {
    for(i = 0; i < apr_table_elts(sconf->chains)->nelts; i++) {
      EVP_PKEY *pkey = NULL;
      X509_STORE *store = (X509_STORE *)entry[i].val;
      X509_OBJECT *obj = apr_pcalloc(pool, sizeof(X509_OBJECT));
      apr_global_mutex_lock(sconf->lock);                  /* >@CRT12 */
      if(sslcrl_X509_STORE_lookup(store, X509_LU_X509, issuer, obj) > 0) {
        apr_pool_t *cpool;
        apr_pool_create(&cpool, pool);
        found = 1;
        apr_pool_cleanup_register(cpool, (void*)obj, (int(*)(void*))X509_OBJECT_free_contents,
                                  apr_pool_cleanup_null);
        pkey = X509_get_pubkey(obj->data.x509);
      }
      apr_global_mutex_unlock(sconf->lock);                /* <@CRT12 */
      if(pkey) {
        int res = X509_CRL_verify(x, pkey);
        EVP_PKEY_free(pkey);
        if(res > 0) {
          if(SSLCRL_ISDEBUG(s)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "child %d - downloaded CRL '%s' is valid",
                         getpid(), url);
          }
          valid = 1;
        } else {
          *msg = apr_pstrdup(pool, "invalid signature");
        }
      }
    }
  }
  X509_CRL_free(x);
  if(!found) {
    *msg = apr_pstrdup(pool, "no CA certificate found");
  }    
  return valid;
}

/**
 * Downloads a CRL
 * 
 * @param pool
 * @param s
 * @param sconf
 * @param e One of the configured CRL entries
 * @param err Error message if downloads failed
 * @return PEM encoded CRL or NULL on error
 */
static char *sslcrl_req(apr_pool_t *pool, server_rec *s, sslcrl_config_t *sconf,
                        sslcrl_entry_t *e, char **err) {
  int port = 80;
  apr_uri_t *parsed_uri = &e->parsed_uri;
  char *hostname = parsed_uri->hostname;
  char *path = parsed_uri->path;
  char *body = NULL;
  int body_len = 0;
  char *buf = NULL;

  if(strcasecmp(parsed_uri->scheme, "https") == 0) {
	  *err = apr_psprintf(pool, "Failed to download CRL from %s. (SSL is currently not supported!)", parsed_uri->hostname);
	  return NULL;
  }

  if(parsed_uri->port) {
    port = parsed_uri->port;
  }

  if(parsed_uri->query) {
    path = apr_pstrcat(pool, path, "?", parsed_uri->query, NULL);
  }

  if (sslcrl_download_crl(sconf, hostname, port, path, &body, &body_len) != APR_SUCCESS) {
	  *err = apr_psprintf(pool, "Failed to download CRL from %s. (%s)", hostname, body);
	  return NULL;
  }

  buf = apr_pstrmemdup(pool, body + 9, 3);

  if (apr_strnatcasecmp(buf, "200") != 0) {
	  *err = apr_psprintf(pool, "Failed to download CRL from %s. (The host did respond with code '%s'.)", hostname, buf);
	  return NULL;
  }

  buf = strstr(body, "-----BEGIN X509 CRL-----");

  if (buf == NULL) {
	  *err = apr_psprintf(pool, "Failed to download CRL from %s. (Couldn't find body.)", hostname);
	  return NULL;
  }

  return buf;
}

/**
 * Loads the CRLs from the configured cache file
 *
 * @param s
 * @param sconf
 */
static void sslcrl_loadcrl(server_rec *s, sslcrl_config_t *sconf) {
  sslcrl_shm_t *u = sslcrl_get_shm(s->process->pool, sconf);
  if(sconf->crl) {
    X509_STORE_free(sconf->crl);
  }
  sconf->crl = sslcrl_X509_STORE_create(s, sconf->cache_file, 1);
  if(!sconf->crl) {
    // continue without crl check
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                 SSLCRL_LOG_PFX(020)"child %d - failed to load CRL store from file '%s'",
                 getpid(), sconf->cache_file);
  } else {
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 SSLCRL_LOG_PFX(061)"child %d - load CRL store from file '%s'",
                 getpid(), sconf->cache_file);
  }
  m_loadstore = u->fileupdate;
}

/**
 * CRL update function called at connection close. Updates all certificates if the
 * defined interval has been reached. Stores the CRL files in the store and notifies all
 * other child processes to relead the store.
 *
 * @param c
 * @return
 */
static apr_status_t sslcrl_update(conn_rec *c) {
  apr_pool_t *pool;
  char *err = NULL;
  int update = 0;
  sslcrl_config_t *sconf = ap_get_module_config(c->base_server->module_config, &sslcrl_module);
  sslcrl_shm_t *u = sslcrl_get_shm(c->base_server->process->pool, sconf);
  apr_interval_time_t now = apr_time_sec(apr_time_now());
  apr_pool_create(&pool, NULL);
  apr_global_mutex_lock(sconf->lock);                          /* >@CRT3 */
  if((u->nextupdate - now) <= 0) {
    // require download
    update = 1;
    u->nextupdate = ((now / sconf->interval) * sconf->interval) + sconf->interval;
  }
  apr_global_mutex_unlock(sconf->lock);                        /* <@CRT3 */
  if(update) {
    char *crl = "";
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->crlurltable)->elts;
    for(i = 0; i < apr_table_elts(sconf->crlurltable)->nelts; i++) {
      sslcrl_entry_t *e = (sslcrl_entry_t *)entry[i].val;
      char *add;
      char *viaProxyMsg = "";
      if(e->proxyhost != NULL) {
        viaProxyMsg = apr_psprintf(pool, " (via proxy %s)", e->proxyhost);
      }
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server,
                   SSLCRL_LOG_PFX(062)"download CRL from '%s'%s",
                   entry[i].key, viaProxyMsg);
      add = sslcrl_req(pool, c->base_server, sconf, e, &err);
      if(add == NULL) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, c->base_server,
                     SSLCRL_LOG_PFX(021)"failed to download CRL from '%s' (%s)",
                     entry[i].key, err ? err : "-");
        // adjust u->nextupdate: retry in SSLCRL_MIN_INTERVAL seconds
        apr_global_mutex_lock(sconf->lock);                    /* >@CRT7 */
        u->nextupdate = now + SSLCRL_MIN_INTERVAL;
        u->status = 0;
        apr_global_mutex_unlock(sconf->lock);                  /* <@CRT7 */
        goto end;
      }
      if(!sslcrl_verify_crl_sig(pool, c->base_server, sconf, add, &err, entry[i].key)) {
        if(e->verifiedonly) {
          ap_log_error(APLOG_MARK, APLOG_CRIT, 0, c->base_server,
                       SSLCRL_LOG_PFX(023)"failed to verify signature of CRL from '%s'%s: %s"
                       " (cancel update)",
                       entry[i].key, viaProxyMsg, err ? err : "-");
          // adjust u->nextupdate: retry in SSLCRL_MIN_INTERVAL seconds
          apr_global_mutex_lock(sconf->lock);                  /* >@CRT10 */
          u->nextupdate = now + SSLCRL_MIN_INTERVAL;
          u->status = 0;
          apr_global_mutex_unlock(sconf->lock);                /* <@CRT10 */
          goto end;
        }
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, c->base_server,
                     SSLCRL_LOG_PFX(023)"failed to verify signature of CRL from '%s'%s: %s",
                     entry[i].key, viaProxyMsg, err ? err : "-");
      }
      crl = apr_pstrcat(pool, crl, add, "\n", NULL);
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server,
                 SSLCRL_LOG_PFX(063)"child %d - store new CRL file '%s'",
                 getpid(), sconf->cache_file);
    apr_global_mutex_lock(sconf->lock);                        /* >@CRT4 */
    u->fileupdate = now; // signal update
    u->status = 1;
    {
      apr_file_t *cache = NULL;
      apr_status_t res = apr_file_open(&cache, sconf->cache_file,
                                       APR_WRITE|APR_CREATE|APR_TRUNCATE,
                                       APR_OS_DEFAULT, pool);
      if(res == APR_SUCCESS) {
        apr_file_printf(cache, "%s", crl);
        apr_file_close(cache);
      } else {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, c->base_server,
                     SSLCRL_LOG_PFX(022)"failed to store new CRL file '%s'",
                     sconf->cache_file);
      }
    }
    sslcrl_loadcrl(c->base_server, sconf);
    apr_global_mutex_unlock(sconf->lock);                      /* <@CRT4 */
  }
  apr_global_mutex_lock(sconf->lock);                          /* >@CRT6 */
  /* update if new file is available */
  if(m_loadstore != u->fileupdate) {
    sslcrl_loadcrl(c->base_server, sconf);
  }
  apr_global_mutex_unlock(sconf->lock);                        /* <@CRT6 */

 end:
  apr_pool_destroy(pool);
  return APR_SUCCESS;
}

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * Filter to perform clr verfication for outgoing connections
 */
static apr_status_t sslcrl_proxy_out_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
  sslcrl_outf_t *ctx = f->ctx;
  conn_rec *c = ctx->c;
  ctx->counter++;
  if(ctx->counter < 3) {
    /* 1  first call is HS
     * 2  second checks cert (if available)
     * 3+ ignores others (does not support renego by another certificate
     *    => maybe we should use sslcrl_sid() to track cert changes) */
    if(ctx->processed == 0) {
      const char *evar = sslcrl_var(c->pool, c->base_server, c, NULL, "SSL_CLIENT_CERT");
      if(evar && evar[0]) {
        // we have a server cert: perform crl check for this certificate and its chain
        request_rec *r = sslcrl_make_fake_req(c, c->pool);
        int rc = sslcrl_check(r, ctx->sconf, evar);
        ctx->processed = 1;
        if(rc != DECLINED) {
          return rc;
        }
      }
    }
  }
  return ap_pass_brigade(f->next, bb);
}

/**
 * used to register out filter for proxy connections (mod_proxy, 
 * mod_auth_oid, others)
 */
static int sslcrl_pre_connection(conn_rec *c, void *skt) {
  if(sslcrl_is_https && sslcrl_is_https(c)) {
    if(c->sbh == NULL) {
      /* proxy/outgoing connections do NOT have any relation to
         the score board (this is not an incomming connection) */
      sslcrl_config_t *sconf = ap_get_module_config(c->base_server->module_config, &sslcrl_module);
      if(sconf->proxyenabled == 1) { // outgoing check has been enabled
        if(apr_table_get(c->notes, SSLCRL_CONN) == NULL) { // not a crl fetch
          sslcrl_outf_t *ctx = apr_pcalloc(c->pool, sizeof(sslcrl_outf_t));
          ctx->counter = 0;
          ctx->processed = 0;
          ctx->c = c;
          ctx->sconf = sconf;
          ap_add_output_filter("sslcrl_proxy_out_filter", ctx, NULL, c);
        }
      }
    }
  }
  return DECLINED;
}

/**
 * Connection destructor used to trigger CRL download.
 */
static int sslcrl_process_connection(conn_rec *c) {
  sslcrl_config_t *sconf = ap_get_module_config(c->base_server->module_config, &sslcrl_module);
  if(sconf && (apr_table_elts(sconf->crlurltable)->nelts > 0) && sconf->cache_file) {
    apr_pool_t *cpool;
    apr_pool_create(&cpool, c->pool);
    apr_pool_cleanup_register(cpool, (void*)c, (int(*)(void*))sslcrl_update,
                              apr_pool_cleanup_null);
  } 
  return DECLINED;
}

/**
 * Access checker used to verify the client certificate against the available CRLs
 *
 * @param r
 * @return DECLINED if access is granted, HTTP_FORBIDDEN if certificate is not valid
 */
static int sslcrl_access(request_rec *r) {
  sslcrl_config_t *sconf = ap_get_module_config(r->server->module_config, &sslcrl_module);
  if(ap_is_initial_req(r) && sconf && sconf->cache_file) {
    sslcrl_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &sslcrl_module);
    if(!dconf || dconf->enabled) {
      if(sslcrl_is_https && sslcrl_is_https(r->connection)) {
        const char *evar;
        const char *verifiedsid = apr_table_get(r->connection->notes, SSLCRL_SESSIONID);
        if(verifiedsid) {
          char *sid = sslcrl_sid(r);
          if(sid && (strcmp(sid, verifiedsid) == 0)) {
            // we have already checked the certificate for this connection
            return DECLINED;
          }
        }
        evar = sslcrl_var(r->pool, r->server, r->connection, r, "SSL_CLIENT_CERT");
        if(evar && evar[0]) {
          // we have a client cert: perform crl check for this certificate and its chain
          int rc = sslcrl_check(r, sconf, evar);
          if(rc != DECLINED) {
            return rc;
          }
        }
      }
    }
  }
  // nothing to do (no ssl, no cert, no check)
  return DECLINED;
}

/**
 * Status hook (registered to mod_status)
 */
static int sslcrl_ext_status_hook(request_rec *r, int flags) {
  sslcrl_config_t *sconf = ap_get_module_config(r->server->module_config, &sslcrl_module);
  if(sconf->cache_file) {
    char *status = "UNKNOWN";
    sslcrl_shm_t *u = sslcrl_get_shm(r->server->process->pool, sconf);
    apr_interval_time_t nextupdate = u->nextupdate;
    apr_interval_time_t now = apr_time_sec(apr_time_now());
    apr_table_entry_t *entry;
    int i;
    nextupdate = nextupdate - now;
    if(nextupdate < 0) {
      nextupdate = 0;
    }
    if(u->status == 0) {
      status = apr_pstrdup(r->pool, "FAILED");
    } else if(u->status == 1) {
      status = apr_pstrdup(r->pool, "OK");
    }
    if(apr_table_elts(sconf->crlurltable)->nelts == 0) {
      status = apr_pstrdup(r->pool, "OFFLINE");
    }
    if(flags & AP_STATUS_SHORT) {
      if(apr_table_elts(sconf->crlurltable)->nelts > 0) {
        ap_rprintf(r, "SSLCRL_UpdateInterval.next: %"APR_TIME_T_FMT"\n", nextupdate);
      }
      ap_rprintf(r, "SSLCRL_UpdateInterval.status: %s\n", status);
      return OK;
    }
    ap_rputs("<hr>\n", r);
    ap_rputs("<table cellspacing=0 cellpadding=0>\n", r);
    ap_rputs("<tr><td bgcolor=\"#000000\">\n", r);
    ap_rputs("<b><font color=\"#ffffff\" face=\"Arial,Helvetica\">mod_sslcrl Status:</font></b>\r", r);
    ap_rputs("</td></tr>\n", r);
    if(apr_table_elts(sconf->crlurltable)->nelts > 0) {
      ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
      ap_rprintf(r, "next update in: <b>%"APR_TIME_T_FMT"</b> seconds", nextupdate);
      ap_rputs("</td></tr>\n", r);
    }
    ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
    ap_rprintf(r, "status: <b>%s</b>", status);
    ap_rputs("</td></tr>\n", r);
    ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
    ap_rprintf(r, "cache: %s", ap_escape_html(r->pool, sconf->cache_file));
    ap_rputs("</td></tr>\n", r);
    entry = (apr_table_entry_t *)apr_table_elts(sconf->chains)->elts;
    if(apr_table_elts(sconf->chains)->nelts == 0) {
      ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
      ap_rprintf(r, "CA cert source: NONE");
      ap_rputs("</td></tr>\n", r);
    }
    for(i = 0; i < apr_table_elts(sconf->chains)->nelts; i++) {
      ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
      ap_rprintf(r, "CA cert source %d: %s", i, ap_escape_html(r->pool, entry[i].key));
      ap_rputs("</td></tr>\n", r);
    }
    ap_rputs("</table>\n", r);
  } else {
    if(flags & AP_STATUS_SHORT) {
      return OK;
    }
    ap_rputs("<hr>\n", r);
    ap_rputs("<table cellspacing=0 cellpadding=0>\n", r);
    ap_rputs("<tr><td bgcolor=\"#000000\">\n", r);
    ap_rputs("<b><font color=\"#ffffff\" face=\"Arial,Helvetica\">mod_sslcrl Status:</font></b>\r", r);
    ap_rputs("</td></tr>\n", r);
    ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
    ap_rprintf(r, "disabled\n");
    ap_rputs("</td></tr>\n", r);
    ap_rputs("</table>\n", r);
  }
  return OK;
}

/**
 * Test hook
 */
static void sslcrl_test(apr_pool_t *pconf, server_rec *s) {
  sslcrl_config_t *sconf = ap_get_module_config(s->module_config, &sslcrl_module);
  if(sconf->cache_file == NULL &&
     (apr_table_elts(sconf->crlurltable)->nelts > 0)) {
    /* url but no chache file */
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                 SSLCRL_LOG_PFX(003)"found SSLCRL_Url but no SSLCRL_Cache directive");
  }
}

/**
 * Loads the most recent CRL db for each child process
 */
static void sslcrl_child_init(apr_pool_t *p, server_rec *bs) {
  sslcrl_config_t *sconf = ap_get_module_config(bs->module_config, &sslcrl_module);
  if(sconf->cache_file) {
    apr_global_mutex_child_init(&sconf->lock, sconf->lockfile, p);
    apr_global_mutex_lock(sconf->lock);                        /* >@CRT5 */
    sslcrl_loadcrl(bs, sconf);
    apr_global_mutex_unlock(sconf->lock);                      /* <@CRT5 */
  }
  return;
}

/**
 * we search for mod_ssl directives to determine the used ca chain files
 */
static void sslcrl_search_chains(apr_pool_t *pconf, server_rec *bs, sslcrl_config_t *sconf,
                                 ap_directive_t *node,
                                 apr_pool_t *cpool) {
  ap_directive_t *pdir;
  static const char *path[] = { "SSLCACertificateFile",
                                "SSLProxyCACertificateFile",
                                NULL };
  static const char *dir[] = { "SSLCACertificatePath", 
                               "SSLProxyCACertificatePath",
                               NULL };
  const char **var;
  if(cpool == NULL) {
    apr_pool_create(&cpool, apr_table_elts(sconf->chains)->pool);
  }
  for(pdir = node; pdir != NULL; pdir = pdir->next) {
    var = path;
    while(var[0]) {
      if(strcasecmp(pdir->directive, var[0]) == 0) {
        char *chainFile = ap_server_root_relative(cpool, pdir->args);
        if(apr_table_get(sconf->chains, chainFile) == NULL) {
          X509_STORE *store = sslcrl_X509_STORE_create(bs, chainFile, 0);
          if(store) {
            apr_pool_cleanup_register(cpool, (void*)store, (int(*)(void*))X509_STORE_free,
                                      apr_pool_cleanup_null);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, bs,
                         SSLCRL_LOG_PFX(064)"found %s directive for file '%s'",
                         var[0],
                         chainFile);
            apr_table_addn(sconf->chains, chainFile, (char *)store);
          }
        }
      }
      var++;
    }
    var = dir;
    while(var[0]) {
      if(strcasecmp(pdir->directive, var[0]) == 0) {
        char *chainPath = ap_server_root_relative(cpool, pdir->args);
        if(apr_table_get(sconf->chains, chainPath) == NULL) {
          X509_STORE *store = sslcrl_X509_STORE_create_path(bs, chainPath);
          if(store) {
            apr_pool_cleanup_register(cpool, (void*)store, (int(*)(void*))X509_STORE_free,
                                      apr_pool_cleanup_null);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, bs,
                         SSLCRL_LOG_PFX(064)"found %s directive for path '%s'",
                         var[0],
                         chainPath);
            apr_table_addn(sconf->chains, chainPath, (char *)store);
          }
        }
      }
      var++;
    }
    if(pdir->first_child != NULL) {
      sslcrl_search_chains(pconf, bs, sconf, pdir->first_child, cpool);
    }
  }
}

static int sslcrl_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp) {
#ifdef SSLCRL_ADD_ALGORITHMS
  OpenSSL_add_all_algorithms();
#endif
  return OK;
}

static int sslcrl_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *bs) {
  sslcrl_config_t *sconf = ap_get_module_config(bs->module_config, &sslcrl_module);
  char *vs = apr_psprintf(pconf, "mod_sslcrl/%s", g_revision);
  ap_add_version_component(pconf, vs);
  sslcrl_m_ssl_enable = APR_RETRIEVE_OPTIONAL_FN(ssl_proxy_enable);
  sslcrl_m_ssl_disable = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);
  sslcrl_var = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
  sslcrl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

  if(sslcrl_var == NULL || sslcrl_is_https == NULL) {
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs,
                 SSLCRL_LOG_PFX(004)"mod_ssl not loaded");
    return !OK;
  }
  APR_OPTIONAL_HOOK(ap, status_hook, sslcrl_ext_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
  
  if(sconf->cache_file == NULL && apr_table_elts(sconf->crlurltable)->nelts > 0) {
    // TODO: add test handler
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs,
                 SSLCRL_LOG_PFX(001)"requires directive SSLCRL_Cache");
    return !OK;
  }

  if(sconf->cache_file) {
    ap_directive_t *pdir = ap_conftree;
    apr_status_t res;
    sslcrl_shm_t *u;
    sconf->lockfile = apr_psprintf(pconf, "%s"SSLCRLLCK, sconf->cache_file);
    res = apr_global_mutex_create(&sconf->lock, sconf->lockfile, APR_LOCK_DEFAULT, pconf);
    if(res != APR_SUCCESS) {
      char buf[MAX_STRING_LEN];
      apr_strerror(res, buf, sizeof(buf));
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs,
                   SSLCRL_LOG_PFX(002)"failed to create mutex (%s): %s", sconf->lockfile, buf);
      return !OK;
    }
    u = sslcrl_get_shm(bs->process->pool, sconf);
    if(!u) {
      return !OK;
    }
    // TODO: test handler, check file permissions for sconf->cache_file
    // init crl store
    sconf->crl = sslcrl_X509_STORE_create(bs, sconf->cache_file, 1);
    if(!sconf->crl) {
      // no store available?
      apr_interval_time_t now = apr_time_sec(apr_time_now());
      u->nextupdate = now;
    } 
    sslcrl_search_chains(pconf, bs, sconf, pdir, NULL);
  }

  return DECLINED;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
static void *sslcrl_srv_config_create(apr_pool_t *p, server_rec *s) {
  sslcrl_config_t *sconf = apr_pcalloc(p, sizeof(sslcrl_config_t));
  sconf->crlurltable = apr_table_make(p, 3);
  sconf->crl = NULL;
  sconf->interval = 86400;
  sconf->cache_file = NULL;
  sconf->chains = apr_table_make(p, 4);
  sconf->contenttypes = apr_table_make(p, 4);
  sconf->headername = NULL;
  sconf->headervalue = NULL;
  sconf->proxyenabled = -1;
  /* default is fail-open (it's a configuration issue if crl is 
     not available and the sysadmin has to fix this!) */
  sconf->failclose = 0;
  return sconf;
}

static void *sslcrl_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  // base server config only
  return basev;
}

static void *sslcrl_dir_config_create(apr_pool_t *p, char *d) {
  sslcrl_dir_config_t *dconf = apr_pcalloc(p, sizeof(sslcrl_dir_config_t));
  dconf->enabled = -1;
  return dconf;
}
static void *sslcrl_dir_config_merge(apr_pool_t *p, void *basev, void *addv) {
  sslcrl_dir_config_t *b = (sslcrl_dir_config_t *)basev;
  sslcrl_dir_config_t *o = (sslcrl_dir_config_t *)addv;
  sslcrl_dir_config_t *dconf = apr_pcalloc(p, sizeof(sslcrl_dir_config_t));
  if(o->enabled != -1) {
    dconf->enabled = o->enabled;
  } else {
    dconf->enabled = b->enabled;
  }
  return dconf;
}

const char *sslcrl_cache_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->cache_file = ap_server_root_relative(cmd->pool, path);
  return NULL;
}

const char *sslcrl_alg_cmd(cmd_parms *cmd, void *dcfg, const char *alg) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if(sconf->signaturAlgorithms == NULL) {
    sconf->signaturAlgorithms = apr_table_make(cmd->pool, 5);
  }
  apr_table_set(sconf->signaturAlgorithms, alg, "");
  return NULL;
}

const char *sslcrl_url_cmd(cmd_parms *cmd, void *dcfg, const char *url,
                           const char *arg2,
                           const char *arg3) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  sslcrl_entry_t *entry = apr_pcalloc(cmd->pool, sizeof(sslcrl_entry_t));
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  const char *proxy = NULL;
  entry->verifiedonly = 0;
  if (err != NULL) {
    return err;
  }
  if((apr_uri_parse(cmd->pool, url, &entry->parsed_uri) != APR_SUCCESS) ||
     !entry->parsed_uri.scheme ||
     !entry->parsed_uri.hostname ||
     !entry->parsed_uri.hostname[0] ||
     !entry->parsed_uri.path ||
     ((strcasecmp(entry->parsed_uri.scheme, "http") != 0) && 
      (strcasecmp(entry->parsed_uri.scheme, "https") != 0))) {
    return apr_psprintf(cmd->pool, "%s: invalid url",
                        cmd->directive->directive);
  }
  if(arg3 != NULL) {
    if(strcasecmp(arg3, SSLCRL_VRF) != 0) {
      return apr_psprintf(cmd->pool, "%s: invalid argument",
                          cmd->directive->directive);
    } else {
      proxy = arg2;
      entry->verifiedonly = 1;
    }
  } else if(arg2 != NULL) {
    if(strcasecmp(arg2, SSLCRL_VRF) == 0) {
      entry->verifiedonly = 1;
    } else {
      proxy = arg2;
    }
  }
  if(proxy) {
    char *port;
    if(strcasecmp(entry->parsed_uri.scheme, "https") == 0) {
      return apr_psprintf(cmd->pool, "%s: forward proxy may be used for HTTP only (not HTTPS)",
                          cmd->directive->directive);
    }
    entry->proxyhost = apr_pstrdup(cmd->pool, proxy);
    entry->proxyport = 0;
    port = strchr(entry->proxyhost, ':');
    if(port) {
      port[0] = '\0';
      port++;
      entry->proxyport = atoi(port);
    }
    if(entry->proxyport <= 0) {
      return apr_psprintf(cmd->pool, "%s: invalid proxy hostname and port",
                          cmd->directive->directive);
    }
  } else {
    entry->proxyhost = NULL;
   }
  apr_table_setn(sconf->crlurltable, apr_pstrdup(cmd->pool, url), (char *)entry);
  return NULL;
}

const char *sslcrl_interval_cmd(cmd_parms *cmd, void *dcfg, const char *interval) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->interval = atol(interval);
  // min interval
  if(sconf->interval < SSLCRL_MIN_INTERVAL) {
    return apr_psprintf(cmd->pool, "%s: invalid interval (requires numeric value >= %d)",
                        cmd->directive->directive, SSLCRL_MIN_INTERVAL);
  }
  return NULL;
}

const char *sslcrl_contenttype_cmd(cmd_parms *cmd, void *dcfg, const char *header,
                                  const char *enc) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if(strcasecmp(enc, "DER") != 0 && strcasecmp(enc, "PEM") != 0) {
    return apr_psprintf(cmd->pool, "%s: invalid encoding",
                        cmd->directive->directive);
  }
  apr_table_set(sconf->contenttypes, header, enc);
  return NULL;
}

const char *sslcrl_header_cmd(cmd_parms *cmd, void *dcfg, const char *name,
                              const char *value) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if(strchr(name, ':')) {
    return apr_psprintf(cmd->pool, "%s: invalid request header name",
                        cmd->directive->directive);
  }
  sconf->headername = apr_pstrdup(cmd->pool, name);
  sconf->headervalue = apr_pstrdup(cmd->pool, value);
  return NULL;
}

const char *sslcrl_enable_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  sslcrl_dir_config_t *dconf = (sslcrl_dir_config_t *)dcfg;
  dconf->enabled = flag;
  return NULL;
}

const char *sslcrl_proxyenable_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
#if (AP_SERVER_MINORVERSION_NUMBER == 4)
  return apr_psprintf(cmd->pool, "%s directive is not supported for Apache 2.4",
                      cmd->directive->directive);
#else
  sconf->proxyenabled = flag;
  return NULL;
#endif
}

const char *sslcrl_failclose_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  sslcrl_config_t *sconf = ap_get_module_config(cmd->server->module_config,
                                                &sslcrl_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->failclose = flag;
  return NULL;
}

static const command_rec sslcrl_config_cmds[] = {
  AP_INIT_TAKE1("SSLCRL_Cache", sslcrl_cache_cmd, NULL,
                RSRC_CONF,
                "SSLCRL_Cache <path>, defines the file in which CRL data is stored."
                " Make sure that the Apache child processes have write access to"
                " this file. The file must always be specified."),
  AP_INIT_TAKE123("SSLCRL_Url", sslcrl_url_cmd, NULL,
                  RSRC_CONF,
                  "SSLCRL_Url <url> [<proxyname>:<proxyport>] ['"SSLCRL_VRF"'],"
                  " defines an HTTP URL to download the CRL"
                  " files from. You can define multiple URLs for several CAs."
                  " The cache file (defined by SSLCRL_Cache) is only updated if"
                  " all(!) CRLs can be fetched. '<proxyname>:<proxyport>' is used to"
                  " specify a forward proxy to use. The '"SSLCRL_VRF"' option is used"
                  " to cancel cache file upload if the signature of a downloaded"
                  " CRL can't be verified."),
  AP_INIT_TAKE1("SSLCRL_UpdateInterval", sslcrl_interval_cmd, NULL,
                RSRC_CONF,
                "SSLCRL_UpdateInterval <seconds>, defines the interval in"
                " which mod_sslcrl should download new CRL data."),
  AP_INIT_FLAG("SSLCRL_Enable", sslcrl_enable_cmd, NULL,
               ACCESS_CONF,
               "SSLCRL_Enable 'on'|'off', enables or disables CRL verification"
               " on a per location basis. Default is 'on'."),
  AP_INIT_FLAG("SSLCRL_ProxyEnable", sslcrl_proxyenable_cmd, NULL,
               RSRC_CONF,
               "SSLCRL_ProxyEnable 'on'|'off', enables or disables CRL verification"
               " for outgoing requests. Default is 'off'."),
  AP_INIT_FLAG("SSLCRL_FailClose", sslcrl_failclose_cmd, NULL,
               RSRC_CONF,
               "SSLCRL_FailClose 'on'|'off', defines if certificates"
               " are denied if no CRL is available for validation."
               " Default is 'off' (fail-open)."),
  AP_INIT_TAKE2("SSLCRL_ContentType", sslcrl_contenttype_cmd, NULL,
                RSRC_CONF,
                "SSLCRL_ContentType <content-type> 'DER'|'PEM',"
                " defines if the downloaded CRL format is DER or PEM encoded"
                " for the specified HTTP response header 'content-type'."),
  AP_INIT_TAKE2("SSLCRL_RequestHeader", sslcrl_header_cmd, NULL,
                RSRC_CONF,
                "SSLCRL_RequestHeader <name> <value>,"
                " defines a request header to be added to the HTTP request"
                " when downloading a CRL."),
  AP_INIT_ITERATE("SSLCRL_SigAlg", sslcrl_alg_cmd, NULL,
                  RSRC_CONF,
                  "SSLCRL_SigAlg <signature algorithm>, defines the"
                  " accepted certificate signature algorithm. Accepts"
                  " any if not defined."),
  { NULL }
};


/************************************************************************
 * apache register 
 ***********************************************************************/
static void sslcrl_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_ssl.c",  "mod_proxy.c", NULL };
  ap_hook_pre_config(sslcrl_pre_config, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(sslcrl_post_config, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_test_config(sslcrl_test, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init(sslcrl_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_pre_connection(sslcrl_pre_connection, NULL, NULL, APR_HOOK_LAST);

  ap_register_output_filter("sslcrl_proxy_out_filter", sslcrl_proxy_out_filter,
                            NULL, AP_FTYPE_CONNECTION+6);
  ap_hook_process_connection(sslcrl_process_connection, NULL, NULL, APR_HOOK_MIDDLE);

  ap_hook_access_checker(sslcrl_access, pre, NULL, APR_HOOK_MIDDLE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA sslcrl_module ={ 
  STANDARD20_MODULE_STUFF,
  sslcrl_dir_config_create,                 /**< dir config creater */
  sslcrl_dir_config_merge,                  /**< dir merger */
  sslcrl_srv_config_create,                 /**< server config */
  sslcrl_srv_config_merge,                  /**< server merger */
  sslcrl_config_cmds,                       /**< command table */
  sslcrl_register_hooks,                    /**< hook registery */
};
