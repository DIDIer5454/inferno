/*
 *  devtls - TLS transparent layer using OpenSSL (Memory BIOs)
 *  Replaces ancient Inferno devssl with modern TLS 1.2/1.3
 *  Structure based on original devssl.c for robustness
 */

#include "dat.h"
#include "fns.h"
#include "error.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define BIO_BUF_SIZE 16384

typedef struct TlsSession TlsSession;
struct TlsSession
{
	SSL_CTX	*ctx;
	SSL	*ssl;
	BIO	*rbio;		/* Input (Network -> SSL) */
	BIO	*wbio;		/* Output (SSL -> Network) */
	int	is_server;	/* 0 = client, 1 = server */
	int	handshake_done;
};

typedef struct Dstate Dstate;
struct Dstate
{
	Chan	*c;		/* Underlying network Chan (socket fd) */
	int	ref;
	char	*user;
	int	perm;

	/* OpenSSL session */
	TlsSession *tls;

	int	state;		/* S_Handshaking, S_Established, ... */
	int	opened;		/* data opened at least once? */
	int	vers;		/* negotiated TLS version (SSL_version) */

	/* Stats */
	ulong	datain;
	ulong	dataout;
	ulong	handin;
	ulong	handout;
};

/* Connection state */
enum {
	S_Handshaking = 0,
	S_Established,
	S_RemoteClosed,
	S_LocalClosed,
	S_Errored
};

enum {
	Maxdmsg		= 1<<16,
	Maxdstate	= 1<<10,	/* absolute limit */
};

/* Qid layout */
enum {
	Qtopdir		= 1,
	Qclonus,
	Qconvdir,
	Qdata,
	Qctl,
};

#define TYPE(x) 	((ulong)(x).path & 0xf)
#define CONV(x) 	((ulong)(x).path >> 4)
#define QID(c, y) 	(((c)<<4) | (y))

Lock	dslock;
int	dshiwat;
int	maxdstate = 20;
Dstate **dstate;

/* Protos */
static void	dsnew(Chan *c, Dstate **);
static void	tlshangup(Dstate*);
static void	dsclone(Chan *c);
static Chan*	buftochan(char *p);
static long	ctlspecific_read(Chan *c, void *a, long n);
static long	tls_data_read(Chan *c, void *a, long n);
static void	flush_wbio_to_network(Dstate *s);

/* ---------- OpenSSL helpers ---------- */

static void
tlsinit(void)
{
	/* For OpenSSL >= 1.1.0, library is auto‑initialized.
	 * Keep hook here if explicit init is ever needed. */
	/* static int inited;
	if(inited) return;
	OPENSSL_init_ssl(0, nil);
	inited = 1;
	*/
}

static TlsSession*
new_tls_session(int is_server)
{
	TlsSession *s;
	const SSL_METHOD *method;

	s = mallocz(sizeof(TlsSession), 1);
	if(s == nil)
		error(Enomem);

	if(is_server)
		method = TLS_server_method();
	else
		method = TLS_client_method();

	s->ctx = SSL_CTX_new(method);
	if(s->ctx == nil){
		free(s);
		error("OpenSSL CTX creation failed");
	}

	if(is_server){
		/* Load server cert/key from current emu directory.
		 * Expect server.crt and server.key to exist. */
		if(SSL_CTX_use_certificate_file(s->ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
			print("devtls: failed to load server.crt\n");
		if(SSL_CTX_use_PrivateKey_file(s->ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
			print("devtls: failed to load server.key\n");
		if(!SSL_CTX_check_private_key(s->ctx))
			print("devtls: invalid or mismatched private key\n");
	}

	SSL_CTX_set_mode(s->ctx, SSL_MODE_AUTO_RETRY);

	s->ssl = SSL_new(s->ctx);
	if(s->ssl == nil){
		SSL_CTX_free(s->ctx);
		free(s);
		error("OpenSSL SSL_new failed");
	}

	s->rbio = BIO_new(BIO_s_mem());
	s->wbio = BIO_new(BIO_s_mem());
	if(s->rbio == nil || s->wbio == nil){
		if(s->rbio) BIO_free(s->rbio);
		if(s->wbio) BIO_free(s->wbio);
		SSL_free(s->ssl);
		SSL_CTX_free(s->ctx);
		free(s);
		error("OpenSSL BIO_new failed");
	}

	SSL_set_bio(s->ssl, s->rbio, s->wbio);

	if(is_server)
		SSL_set_accept_state(s->ssl);
	else
		SSL_set_connect_state(s->ssl);

	s->is_server = is_server;
	s->handshake_done = 0;

	return s;
}

static void
free_tls_session(TlsSession *s)
{
	if(s == nil)
		return;
	if(s->ssl)
		SSL_free(s->ssl);	/* frees rbio/wbio too */
	if(s->ctx)
		SSL_CTX_free(s->ctx);
	free(s);
}

/* Pump encrypted data from wbio -> network Chan */
static void
flush_wbio_to_network(Dstate *s)
{
	char buf[BIO_BUF_SIZE];
	int n;
	Block *b;

	if(s == nil || s->c == nil || s->tls == nil)
		return;

	for(;;){
		n = BIO_read(s->tls->wbio, buf, sizeof(buf));
		if(n <= 0)
			break;

		b = allocb(n);
		if(b == nil)
			error(Enomem);

		memmove(b->wp, buf, n);
		b->wp += n;

		/* Count as handshake or data depending on state */
		if(!s->tls->handshake_done)
			s->handout += n;
		else
			s->dataout += n;

		devtab[s->c->type]->bwrite(s->c, b, s->c->offset);
	}
}

/* ---------- directory / qid generation ---------- */

static int
tlsgen(Chan *c, char *dname, Dirtab *d, int nd, int s, Dir *dp)
{
	Qid q;
	Dstate *ds;
	char *p, *nm;

	USED(dname);
	USED(nd);
	USED(d);

	q.type = QTFILE;
	q.vers = 0;

	if(s == DEVDOTDOT){
		q.path = QID(0, Qtopdir);
		q.type = QTDIR;
		devdir(c, q, "#a", 0, eve, 0555, dp);
		return 1;
	}

	switch(TYPE(c->qid)){
	case Qtopdir:
		if(s < dshiwat){
			q.path = QID(s, Qconvdir);
			q.type = QTDIR;
			ds = dstate[s];
			if(ds != nil)
				nm = ds->user;
			else
				nm = eve;
			snprint(up->genbuf, sizeof(up->genbuf), "%d", s);
			devdir(c, q, up->genbuf, 0, nm, DMDIR|0555, dp);
			return 1;
		}
		if(s == dshiwat){
			q.path = QID(0, Qclonus);
			devdir(c, q, "clone", 0, eve, 0660, dp);
			return 1;
		}
		return -1;

	case Qclonus:
		q.path = QID(0, Qclonus);
		devdir(c, q, "clone", 0, eve, 0666, dp);
		return 1;

	case Qconvdir:
		ds = dstate[CONV(c->qid)];
		if(ds != nil)
			nm = ds->user;
		else
			nm = eve;

		switch(s){
		case 0:
			q.path = QID(CONV(c->qid), Qctl);
			p = "ctl";
			break;
		case 1:
			q.path = QID(CONV(c->qid), Qdata);
			p = "data";
			break;
		default:
			return -1;
		}
		devdir(c, q, p, 0, nm, 0660, dp);
		return 1;
	}
	return -1;
}

/* ---------- attach / walk / stat ---------- */

static Chan*
tlsattach(char *spec)
{
	Chan *c;

	if(dstate == nil){
		dstate = mallocz(sizeof(Dstate*) * maxdstate, 1);
		if(dstate == nil)
			error(Enomem);
		tlsinit();
	}

	c = devattach('a', spec);
	c->qid.path = QID(0, Qtopdir);
	c->qid.type = QTDIR;
	c->qid.vers = 0;
	return c;
}

static Walkqid*
tlswalk(Chan *c, Chan *nc, char **name, int nname)
{
	return devwalk(c, nc, name, nname, nil, 0, tlsgen);
}

static int
tlsstat(Chan *c, uchar *db, int n)
{
	return devstat(c, db, n, nil, 0, tlsgen);
}

/* ---------- open / close ---------- */

static Chan*
tlsopen(Chan *c, int omode)
{
	Dstate *s;
	int perm = 0;

	omode &= 3;
	switch(omode){
	case OREAD:  perm = 4; break;
	case OWRITE: perm = 2; break;
	case ORDWR:  perm = 6; break;
	}

	switch(TYPE(c->qid)){
	default:
		error(Eperm);

	case Qtopdir:
	case Qconvdir:
		if(omode != OREAD)
			error(Eperm);
		break;

	case Qclonus:
		dsclone(c);	/* turns this Chan into ctl of new conv */
		break;

	case Qctl:
	case Qdata:
		lock(&dslock);
		if(waserror()){
			unlock(&dslock);
			nexterror();
		}
		s = dstate[CONV(c->qid)];
		if(s == nil)
			error(Ehungup);

		if(strcmp(up->env->user, s->user) != 0 &&
		   strcmp(eve, up->env->user) != 0)
			error(Eperm);

		s->ref++;
		if(TYPE(c->qid) == Qdata)
			s->opened = 1;
		unlock(&dslock);
		poperror();
		break;
	}

	c->mode = openmode(omode);
	c->flag |= COPEN;
	c->offset = 0;
	return c;
}

static void
tlsclose(Chan *c)
{
	Dstate *s;

	if((c->flag & COPEN) == 0)
		return;

	switch(TYPE(c->qid)){
	case Qctl:
	case Qdata:
		s = dstate[CONV(c->qid)];
		if(s == nil)
			break;

		lock(&dslock);
		if(--s->ref > 0){
			unlock(&dslock);
			break;
		}
		dstate[CONV(c->qid)] = nil;
		unlock(&dslock);

		tlshangup(s);
		free(s->user);
		free_tls_session(s->tls);
		if(s->c)
			cclose(s->c);
		free(s);
		break;
	}
}

/* ---------- read path ---------- */

static long
tlsread(Chan *c, void *a, long n, vlong offset)
{
	Dstate *s;
	int t;

	if(c->qid.type & QTDIR)
		return devdirread(c, a, n, nil, 0, tlsgen);

	t = TYPE(c->qid);

	if(t == Qclonus){
		/* Return conv number like /dev/ssl clone */
		char buf[16];

		snprint(buf, sizeof buf, "%d", CONV(c->qid));
		return readstr(offset, a, n, buf);
	}

	s = dstate[CONV(c->qid)];
	if(s == nil)
		error(Ehungup);

	if(t == Qctl)
		return ctlspecific_read(c, a, n);

	if(t == Qdata)
		return tls_data_read(c, a, n);

	error(Ebadusefd);
	return -1;	/* not reached */
}

/* ----- ctl read ----- */

static char*
statestr(int st)
{
	switch(st){
	case S_Handshaking:	return "handshaking";
	case S_Established:	return "established";
	case S_RemoteClosed:	return "remoteclosed";
	case S_LocalClosed:	return "localclosed";
	case S_Errored:		return "errored";
	}
	return "unknown";
}

static long
ctlspecific_read(Chan *c, void *a, long n)
{
	Dstate *s;
	char buf[256];
	int m;
	char *cipher, *verstr;

	s = dstate[CONV(c->qid)];
	if(s == nil)
		error(Ehungup);

	cipher = "none";
	verstr = "unknown";
	if(s->tls != nil && s->tls->ssl != nil && s->tls->handshake_done){
		cipher = (char*)SSL_get_cipher_name(s->tls->ssl);
		verstr = (char*)SSL_get_version(s->tls->ssl);
	}

	m = snprint(buf, sizeof buf,
		"state %s\n"
		"cipher %s\n"
		"version %s\n"
		"datain %lud\n"
		"dataout %lud\n"
		"handin %lud\n"
		"handout %lud\n",
		statestr(s->state),
		cipher,
		verstr,
		s->datain,
		s->dataout,
		s->handin,
		s->handout
	);

	if(n > m)
		n = m;
	memmove(a, buf, n);
	return n;
}

/* ----- data read ----- */

static long
tls_data_read(Chan *c, void *a, long n)
{
	Dstate *s;
	char *ua;
	int ret, err;
	Block *b;

	s = dstate[CONV(c->qid)];
	if(s == nil)
		error(Ehungup);

	if(s->tls == nil)
		error("TLS not configured");

	ua = a;

	for(;;){
		ret = SSL_read(s->tls->ssl, ua, n);
		if(ret > 0){
			/* First successful app data -> handshake finished */
			if(!s->tls->handshake_done && SSL_is_init_finished(s->tls->ssl)){
				s->tls->handshake_done = 1;
				s->state = S_Established;
				s->vers = SSL_version(s->tls->ssl);
			}
			s->datain += ret;
			flush_wbio_to_network(s);
			return ret;
		}

		err = SSL_get_error(s->tls->ssl, ret);

		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
			flush_wbio_to_network(s);

			if(err == SSL_ERROR_WANT_WRITE)
				continue;

			/* WANT_READ: feed rbio with network data */
			b = devtab[s->c->type]->bread(s->c, BIO_BUF_SIZE, 0);
			if(b == nil){
				s->state = S_RemoteClosed;
				return 0;
			}

			if(!s->tls->handshake_done)
				s->handin += BLEN(b);
			else
				s->datain += BLEN(b);	/* if post‑handshake appdata */

			BIO_write(s->tls->rbio, b->rp, BLEN(b));
			freeb(b);
			continue;
		}

		if(err == SSL_ERROR_ZERO_RETURN){
			s->state = S_RemoteClosed;
			return 0;
		}

		s->state = S_Errored;
		error("SSL read error");
	}
}

/* ---------- write path ---------- */

static long
tlswrite(Chan *c, void *a, long n, vlong offset)
{
	Dstate *s;
	int t;

	USED(offset);

	s = dstate[CONV(c->qid)];
	if(s == nil)
		error(Ehungup);

	t = TYPE(c->qid);

	/* ctl commands */
	if(t == Qctl){
		char buf[128];
		char *p;

		if(n >= sizeof buf)
			error(Ebadarg);
		strncpy(buf, a, n);
		buf[n] = 0;
		p = strchr(buf, '\n');
		if(p != nil)
			*p = 0;

		if(strncmp(buf, "fd", 2) == 0){
			p = strchr(buf, ' ');
			if(p == nil)
				error(Ebadarg);
			s->c = buftochan(p+1);
			if(s->tls == nil){
				s->tls = new_tls_session(0);	/* client by default */
				s->state = S_Handshaking;
			}
			return n;
		}

		if(strncmp(buf, "server", 6) == 0){
			if(s->tls)
				free_tls_session(s->tls);
			s->tls = new_tls_session(1);
			s->state = S_Handshaking;
			return n;
		}

		if(strncmp(buf, "client", 6) == 0){
			if(s->tls)
				free_tls_session(s->tls);
			s->tls = new_tls_session(0);
			s->state = S_Handshaking;
			return n;
		}

		error(Ebadarg);
	}

	/* data path */
	if(t != Qdata)
		error(Ebadusefd);
	if(s->tls == nil)
		error("TLS session not initialized");

	for(;;){
		int ret = SSL_write(s->tls->ssl, a, n);
		if(ret > 0){
			if(!s->tls->handshake_done && SSL_is_init_finished(s->tls->ssl)){
				s->tls->handshake_done = 1;
				s->state = S_Established;
				s->vers = SSL_version(s->tls->ssl);
			}
			s->dataout += ret;
			flush_wbio_to_network(s);
			return ret;
		}

		int err = SSL_get_error(s->tls->ssl, ret);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
			flush_wbio_to_network(s);

			/* If only WANT_WRITE, just loop to let OpenSSL generate more */
			if(err == SSL_ERROR_WANT_WRITE)
				continue;

			/* WANT_READ: need more from network */
			Block *b = devtab[s->c->type]->bread(s->c, BIO_BUF_SIZE, 0);
			if(b == nil){
				s->state = S_RemoteClosed;
				error("TLS connection closed during handshake");
			}

			if(!s->tls->handshake_done)
				s->handin += BLEN(b);
			else
				s->datain += BLEN(b);

			BIO_write(s->tls->rbio, b->rp, BLEN(b));
			freeb(b);
			continue;
		}

		if(err == SSL_ERROR_ZERO_RETURN){
			s->state = S_RemoteClosed;
			return 0;
		}

		s->state = S_Errored;
		error("SSL write error");
	}
}

/* ---------- helpers ---------- */

static void
tlshangup(Dstate *s)
{
	if(s == nil)
		return;
	if(s->state != S_RemoteClosed && s->state != S_Errored)
		s->state = S_LocalClosed;
}

/* "fd -> Chan" helper */
static Chan*
buftochan(char *p)
{
	Chan *c;
	int fd;

	if(p == nil)
		error(Ebadarg);
	fd = strtoul(p, 0, 0);
	if(fd < 0)
		error(Ebadarg);
	c = fdtochan(up->env->fgrp, fd, -1, 0, 1);
	return c;
}

/* Clone: find empty slot or grow table (like devssl) */
static void
dsclone(Chan *ch)
{
	Dstate **pp, **ep, **np;
	int newmax;

	lock(&dslock);
	if(waserror()){
		unlock(&dslock);
		nexterror();
	}

	ep = &dstate[maxdstate];
	for(pp = dstate; pp < ep; pp++){
		if(*pp == nil){
			dsnew(ch, pp);
			goto Done;
		}
	}

	if(maxdstate >= Maxdstate)
		error(Enodev);

	newmax = 2 * maxdstate;
	if(newmax > Maxdstate)
		newmax = Maxdstate;

	np = realloc(dstate, sizeof(Dstate*) * newmax);
	if(np == nil)
		error(Enomem);

	dstate = np;
	pp = &dstate[maxdstate];
	memset(pp, 0, sizeof(Dstate*) * (newmax - maxdstate));

	maxdstate = newmax;
	dsnew(ch, pp);

Done:
	poperror();
	unlock(&dslock);
}

static void
dsnew(Chan *ch, Dstate **pp)
{
	Dstate *s;
	int t, idx;

	idx = pp - dstate;
	if(idx < 0 || idx >= maxdstate){
		print("devtls: dsnew invalid pp=%p dstate=%p\n", pp, dstate);
		error(Egreg);
	}

	*pp = s = mallocz(sizeof(Dstate), 1);
	if(s == nil)
		error(Enomem);

	if(idx >= dshiwat)
		dshiwat = idx + 1;

	s->ref = 1;
	kstrdup(&s->user, up->env->user);
	s->perm = 0660;
	s->state = S_Handshaking;
	s->datain = s->dataout = 0;
	s->handin = s->handout = 0;
	s->opened = 0;
	s->vers = 0;

	t = TYPE(ch->qid);
	if(t == Qclonus)
		t = Qctl;

	ch->qid.path = QID(idx, t);
	ch->qid.vers = 0;
	ch->qid.type = QTFILE;
}

/* ---------- Dev table ---------- */

Dev tlsdevtab = {
	'a',
	"tls",

	devinit,
	tlsattach,
	tlswalk,
	tlsstat,
	tlsopen,
	devcreate,
	tlsclose,
	tlsread,
	devbread,
	tlswrite,
	devbwrite,
	devremove,
	devwstat,
};
