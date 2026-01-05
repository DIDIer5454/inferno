/*
 *  devtls - TLS transparent layer using OpenSSL (Memory BIOs)
 *  Replaces ancient Inferno devssl with modern TLS 1.2/1.3
 *  Structure based on original devssl.c for robustness
 */
#include	"dat.h"
#include	"fns.h"
#include	"error.h"

// Headers OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// Taille des buffers IO pour OpenSSL
#define BIO_BUF_SIZE 16384

typedef struct TlsSession TlsSession;
struct TlsSession
{
	SSL_CTX	*ctx;
	SSL	*ssl;
	BIO	*rbio;		// Input (Network -> SSL)
	BIO	*wbio;		// Output (SSL -> Network)
	int	is_server;	// 0 = client, 1 = server
	int	handshake_done;
};

typedef struct Dstate Dstate;
struct Dstate
{
	Chan	*c;		// Le canal vers le réseau (fd socket)
	int	ref;		// Compteur de références
	char	*user;
	int	perm;
	
	// Session OpenSSL
	TlsSession *tls;

	// --- Champs manquants que tu dois ajouter ---
	int	state;		// État (Handshaking, Established...)
	int	opened;		// Data activé ?
	int	vers;		// Version TLS

	// Stats
	ulong	datain;
	ulong	dataout;
	ulong	handin;
	ulong	handout;
};

// Et ajoute cet Enum juste avant ou après la struct :
enum {
	S_Handshaking = 0,
	S_Established,
	S_RemoteClosed,
	S_LocalClosed,
	S_Errored
};
enum
{
	Maxdmsg=	1<<16,
	Maxdstate=	1<<10, /* Limite absolue */
};

Lock	dslock;
int	dshiwat;
int	maxdstate = 20; /* Taille initiale du tableau, augmentera dynamiquement */
Dstate** dstate;

enum{
	Qtopdir		= 1,
	Qclonus,
	Qconvdir,
	Qdata,
	Qctl,
};

#define TYPE(x) 	((ulong)(x).path & 0xf)
#define CONV(x) ((ulong)(x).path >> 4)
#define QID(c, y) 	(((c)<<4) | (y))

static void	dsnew(Chan *c, Dstate **);
static void	tlshangup(Dstate*);
static void dsclone(Chan *c);
static Chan* buftochan(char *p);
static long ctlspecific_read(Chan *c, void *a, long n);
static long tls_data_read(Chan *c, void *a, long n);

// --- Fonctions Helpers OpenSSL ---

static void
tlsinit(void)
{
	// OpenSSL >= 1.1.0 s'initialise tout seul, mais on peut forcer si besoin
	// static int inited = 0;
	// if(inited) return;
	// OPENSSL_init_ssl(0, NULL);
	// inited = 1;
}

static TlsSession*
new_tls_session(int is_server)
{
    TlsSession *s;
    const SSL_METHOD *method;

    s = mallocz(sizeof(TlsSession), 1);
    if(s == nil) error(Enomem);

    if(is_server)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    s->ctx = SSL_CTX_new(method);
    if(!s->ctx){
        free(s);
        error("OpenSSL CTX creation failed");
    }
    
    // --- AJOUT CRITIQUE POUR LE SERVEUR ---
    if(is_server){
        // On charge les certificats depuis le dossier courant de l'emu
        // Assure-toi que server.crt et server.key existent !
        if(SSL_CTX_use_certificate_file(s->ctx, "server.crt", SSL_FILETYPE_PEM) <= 0){
            print("devtls: echec chargement server.crt\n");
        }
        if(SSL_CTX_use_PrivateKey_file(s->ctx, "server.key", SSL_FILETYPE_PEM) <= 0){
            print("devtls: echec chargement server.key\n");
        }
        if(!SSL_CTX_check_private_key(s->ctx)){
            print("devtls: cle privee invalide ou incompatible\n");
        }
    }
    // --------------------------------------

    // Mode auto-retry pour simplifier la machine d'état
    SSL_CTX_set_mode(s->ctx, SSL_MODE_AUTO_RETRY);

    s->ssl = SSL_new(s->ctx);
    
    s->rbio = BIO_new(BIO_s_mem());
    s->wbio = BIO_new(BIO_s_mem());
    
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
	if(s == nil) return;
	if(s->ssl) SSL_free(s->ssl); // Libère aussi les BIOs
	if(s->ctx) SSL_CTX_free(s->ctx);
	free(s);
}

// Pompe les données chiffrées depuis OpenSSL (wbio) vers le réseau (Chan *c)
static void
flush_wbio_to_network(Dstate *s)
{
	char buf[BIO_BUF_SIZE];
	int n;
	Block *b;
	
	if(s->c == nil || s->tls == nil) return;

	while(1){
		n = BIO_read(s->tls->wbio, buf, sizeof(buf));
		if(n <= 0) break; // Plus rien à envoyer pour l'instant
		
		b = allocb(n);
		memmove(b->wp, buf, n);
		b->wp += n;
		
		// Ecriture dans le vrai socket réseau
		devtab[s->c->type]->bwrite(s->c, b, s->c->offset);
	}
}

// --- Fonctions Structurelles (inspirées de devssl.c) ---

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
	// Gestion du .. (parent)
	if(s == DEVDOTDOT){
		q.path = QID(0, Qtopdir);
		q.type = QTDIR;
		devdir(c, q, "#a", 0, eve, 0555, dp); // #a pour tls
		return 1;
	}

	switch(TYPE(c->qid)) {
	case Qtopdir:
		// Liste les dossiers numériques
		if(s < dshiwat) {
			q.path = QID(s, Qconvdir);
			q.type = QTDIR;
			ds = dstate[s];
			if(ds != 0)
				nm = ds->user;
			else
				nm = eve;
			snprint(up->genbuf, sizeof(up->genbuf), "%d", s);
			devdir(c, q, up->genbuf, 0, nm, DMDIR|0555, dp);
			return 1;
		}
		// Après les dossiers, affiche 'clone'
		if(s == dshiwat){
			q.path = QID(0, Qclonus);
			devdir(c, q, "clone", 0, eve, 0660, dp);
			return 1;
		}
		return -1;

	case Qclonus:
		// Si on demande explicitement clone
		q.path = QID(0, Qclonus);
		devdir(c, q, "clone", 0, eve, 0666, dp);
		return 1;

	case Qconvdir:
		// Contenu d'un dossier de connexion (ex: /dev/tls/3/)
		ds = dstate[CONV(c->qid)];
		if(ds != 0)
			nm = ds->user;
		else
			nm = eve;

		switch(s) {
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

static Chan*
tlsattach(char *spec)
{
	// Allocation initiale sécurisée du tableau d'état
	if(dstate == nil){
		dstate = mallocz(sizeof(Dstate*) * maxdstate, 1);
		if(dstate == nil) error(Enomem);
		tlsinit();
	}
	Chan *c = devattach('a', spec);
	c->qid.path = QID(0, Qtopdir);
	c->qid.type = QTDIR;
	c->qid.vers = 0;
	return c;
}

static Walkqid*
tlswalk(Chan *c, Chan *nc, char **name, int nname)
{
	return devwalk(c, nc, name, nname, 0, 0, tlsgen);
}

static int
tlsstat(Chan *c, uchar *db, int n)
{
	return devstat(c, db, n, 0, 0, tlsgen);
}

static Chan*
tlsopen(Chan *c, int omode)
{
	Dstate *s, **pp;
	int perm = 0;

	omode &= 3;
	switch(omode) {
	case OREAD: perm = 4; break;
	case OWRITE: perm = 2; break;
	case ORDWR: perm = 6; break;
	}

	switch(TYPE(c->qid)) {
	default:
		error(Eperm);
	case Qtopdir:
	case Qconvdir:
		if(omode != OREAD) error(Eperm);
		break;
	case Qclonus:
		dsclone(c); // C'est ici que la magie opère pour créer le dossier
		break;
	case Qctl:
	case Qdata:
		lock(&dslock);
		if(waserror()){ unlock(&dslock); nexterror(); }
		int idx=CONV(c->qid);
	    	print("DEBUG: tlsopen path=%lux idx=%d\n", c->qid.path, idx); // AJOUTE ÇA
		s = dstate[CONV(c->qid)];
		if(s == 0) {
		 print("DEBUG: dstate[%d] is NULL! Hungup.\n", idx);
		error(Ehungup);}
		
		if(strcmp(up->env->user, s->user) != 0 && strcmp(eve, up->env->user) != 0)
			error(Eperm);
			
		s->ref++;
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

	if((c->flag & COPEN) == 0) return;

	switch(TYPE(c->qid)) {
	case Qctl:
	case Qdata:
		s = dstate[CONV(c->qid)];
		if(s == 0) break;
		
		lock(&dslock);
		if(--s->ref > 0) {
			unlock(&dslock);
			break;
		}
		// Dernier utilisateur ferme, on nettoie
		dstate[CONV(c->qid)] = 0;
		unlock(&dslock);
		
		tlshangup(s);
		free(s->user);
		free_tls_session(s->tls);
		if(s->c) cclose(s->c);
		free(s);
	}
}

// --- I/O Operations ---

static long
tlsread(Chan *c, void *a, long n, vlong offset)
{
    // (Checks initiaux...)
    if(c->qid.type & QTDIR)
        return devdirread(c, a, n, 0, 0, tlsgen);

    Dstate *s = dstate[CONV(c->qid)];

    /* --- gérer le fichier clone --- */
    int t = TYPE(c->qid);
    if(t == Qclonus){
        // Un clone read doit renvoyer le numéro de connexion
        // Exemple exact du device /dev/ssl
        char buf[16];
        snprint(buf, sizeof buf, "%d", CONV(c->qid));

        return readstr(offset, a, n, buf);
    }

    if(s == 0)
        error(Ehungup);

    //if(TYPE(c->qid) != Qdata)
//	print("yoyo");
	  //      error(Ebadusefd);
	if(TYPE(c->qid) == Qctl){
		print("yoy");
	    return ctlspecific_read(c, a, n);
	}

	if(TYPE(c->qid) == Qdata){
	    return tls_data_read(c, a, n);
	}

    if(s->tls == nil)
        error("TLS not configured");

    char *ua = a;
    while(1){
        int ret = SSL_read(s->tls->ssl, ua, n);
        if(ret > 0){
            flush_wbio_to_network(s);
            return ret;
        }

        int err = SSL_get_error(s->tls->ssl, ret);

        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
            flush_wbio_to_network(s);

            if(err == SSL_ERROR_WANT_WRITE)
                continue;

            Block *b = devtab[s->c->type]->bread(s->c, BIO_BUF_SIZE, 0);
            if(b == nil) return 0;

            BIO_write(s->tls->rbio, b->rp, BLEN(b));
            freeb(b);
            continue;
        }

        if(err == SSL_ERROR_ZERO_RETURN)
            return 0;

        error("SSL read error");
    }
}
//----- fonction pour differencier la lecture ctl et la lecture data---
static long
ctlspecific_read(Chan *c, void *a, long n)
{
    Dstate *s = dstate[CONV(c->qid)];
    if(s == nil) 
        error(Ehungup);

    char buf[256];
    int m = 0;

    // Exemple de contenu du ctl
    m = snprint(buf, sizeof(buf),
        "state %s\n"
        "cipher %s\n"
        "version %s\n",
        (s->tls != nil ? "ready" : "init"),
        (s->tls != nil ? SSL_get_cipher_name(s->tls->ssl) : "none"),
        (s->tls != nil ? SSL_get_version(s->tls->ssl) : "unknown")
    );

    if(n > m) n = m;
    memmove(a, buf, n);

    return n;
}

static long
tls_data_read(Chan *c, void *a, long n)
{
    Dstate *s = dstate[CONV(c->qid)];
    if(s == nil)
        error(Ehungup);

    if(s->tls == nil)
        error("TLS not configured");

    char *ua = a;

    for(;;){
        int ret = SSL_read(s->tls->ssl, ua, n);

        // Lecture OK → on renvoie les données
        if(ret > 0){
            flush_wbio_to_network(s);
            return ret;
        }

        int err = SSL_get_error(s->tls->ssl, ret);

        // WANT_READ / WANT_WRITE : handshake en cours
        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
            // Toujours flush d'abord
            flush_wbio_to_network(s);

            if(err == SSL_ERROR_WANT_WRITE){
                // OpenSSL veut juste envoyer → retente
                continue;
            }

            // WANT_READ → on doit alimenter rbio avec les données réseau
            Block *b = devtab[s->c->type]->bread(s->c, BIO_BUF_SIZE, 0);
            if(b == nil){
                // Fin du flux réseau
                return 0;
            }

            BIO_write(s->tls->rbio, b->rp, BLEN(b));
            freeb(b);
            continue; // On retente SSL_read après avoir nourri rbio
        }

        if(err == SSL_ERROR_ZERO_RETURN){
            // Fermeture TLS propre (close_notify)
            return 0;
        }

        error("SSL read error");
    }
}


static long
tlswrite(Chan *c, void *a, long n, vlong offset)
{
    Dstate *s = dstate[CONV(c->qid)];
    if(s == 0) error(Ehungup);
    
    // --- Gestion du fichier CTL ---
    if(TYPE(c->qid) == Qctl){
        char buf[128];
        char *p;
        if(n >= sizeof(buf)) error(Ebadarg);
        strncpy(buf, a, n);
        buf[n] = 0;
        p = strchr(buf, '\n'); if(p) *p=0;

        if(strncmp(buf, "fd", 2) == 0){
            p = strchr(buf, ' ');
            if(p == 0) error(Ebadarg);
            s->c = buftochan(p+1);
            if(s->tls == nil) s->tls = new_tls_session(0); 
            return n;
        }
        if(strncmp(buf, "server", 6) == 0){
            if(s->tls) free_tls_session(s->tls);
            s->tls = new_tls_session(1);
            return n;
        }
        if(strncmp(buf, "client", 6) == 0){
            if(s->tls) free_tls_session(s->tls);
            s->tls = new_tls_session(0);
            return n;
        }
        error(Ebadarg);
    }

    // --- Gestion des données DATA ---
    if(TYPE(c->qid) != Qdata) error(Ebadusefd);
    if(s->tls == nil) error("TLS session not initialized");

    // BOUCLE DE POMPAGE POUR LE HANDSHAKE
    while(1){
        // On tente d'écrire les données claires
        int ret = SSL_write(s->tls->ssl, a, n);
        // 1. Succès : on pousse ce qui a été produit (données chiffrées) et on sort
        if(ret > 0){
            flush_wbio_to_network(s);
            return ret;
        }
        // 2. Gestion des états intermédiaires (Handshake en cours)
        int err = SSL_get_error(s->tls->ssl, ret);
        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
            // OpenSSL a généré des données (ex: ClientHello) qu'il faut envoyer
            flush_wbio_to_network(s);
            // Et il attend probablement une réponse du serveur (ServerHello)
            // On va lire sur le réseau pour débloquer la situation
            Block *b = devtab[s->c->type]->bread(s->c, BIO_BUF_SIZE, 0);
            if(b == nil) error("TLS connection closed during handshake");
            BIO_write(s->tls->rbio, b->rp, BLEN(b));
            freeb(b);
            // On boucle pour retenter le SSL_write maintenant qu'on a nourri OpenSSL
            continue;
        }
        // 3. Vraie erreur fatale
        // print("devtls: write error %d\n", err);
        error("SSL write error");
    }
}
// --- Helpers internes ---

static void
tlshangup(Dstate *s)
{
	// Nettoyage spécifique si besoin (buffers pending etc)
	USED(s);
}

// Helper pour convertir un string "fd" en channel Inferno
static Chan*
buftochan(char *p)
{
	Chan *c;
	int fd;

	if(p == 0) error(Ebadarg);
	fd = strtoul(p, 0, 0);
	if(fd < 0) error(Ebadarg);
	c = fdtochan(up->env->fgrp, fd, -1, 0, 1);
	return c;
}

// Cloner : Trouve un slot vide ou agrandit le tableau
// Copié/Adapté de devssl.c
static void
dsclone(Chan *ch)
{
	Dstate **pp, **ep, **np;
	int newmax;

	lock(&dslock);
	if(waserror()) {
		unlock(&dslock);
		nexterror();
	}
	
	// Cherche un slot vide
	ep = &dstate[maxdstate];
	for(pp = dstate; pp < ep; pp++) {
		if(*pp == 0) {
			dsnew(ch, pp);
			break;
		}
	}
	
	// Si tableau plein, on agrandit
	if(pp >= ep) {
		if(maxdstate >= Maxdstate)
			error(Enodev);
			
		newmax = 2 * maxdstate;
		if(newmax > Maxdstate) newmax = Maxdstate;

		np = realloc(dstate, sizeof(Dstate*) * newmax);
		if(np == 0) error(Enomem);
		
		dstate = np;
		pp = &dstate[maxdstate];
		// Mise à zéro de la nouvelle zone
		memset(pp, 0, sizeof(Dstate*)*(newmax - maxdstate));

		maxdstate = newmax;
		dsnew(ch, pp);
	}
	poperror();
	unlock(&dslock);
}

static void
dsnew(Chan *ch, Dstate **pp)
{
	Dstate *s;
	int t;
	int idx;

	// 1. Calcul et vérification de l'index AVANT allocation
	idx = pp - dstate;

	// Sécurité : si le pointeur n'est pas dans le tableau, on panique ou on error
	if(idx < 0 || idx >= maxdstate){
		print("devtls: dsnew called with invalid pointer pp=%p dstate=%p\n", pp, dstate);
		error(Egreg); // "Egregious error" (interne)
	}

	// 2. Allocation de la structure
	*pp = s = mallocz(sizeof(Dstate), 1);
	if(s == nil)
		error(Enomem);

	// 3. Mise à jour du "High Water Mark" (index max utilisé)
	if(idx >= dshiwat)
		dshiwat = idx + 1;

	// 4. Initialisation des champs
	s->ref = 1;
	kstrdup(&s->user, up->env->user);
	s->perm = 0660;
	s->state = S_Handshaking; // État initial important

	// Init stats à 0 (mallocz le fait déjà, mais pour être clair)
	s->datain = 0; s->dataout = 0;
	s->handin = 0; s->handout = 0;

	// 5. Configuration du QID
	// Si on vient de cloner (Qclonus), le fichier ouvert devient le 'ctl' du nouveau dossier
	t = TYPE(ch->qid);
	if(t == Qclonus)
		t = Qctl;

	ch->qid.path = QID(idx, t);
	ch->qid.vers = 0;
	ch->qid.type = QTFILE;
}
Dev tlsdevtab = {
	'a',            // Lettre du device (ex: #a)
	"tls",
	devinit,
	tlsattach,
	tlswalk,
	tlsstat,
	tlsopen,
	devcreate,
	tlsclose,
	tlsread,
	devbread,       // On utilise le bread standard, pas de bread spécifique requis ici
	tlswrite,
	devbwrite,      // Idem
	devremove,
	devwstat,
};
