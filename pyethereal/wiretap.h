struct eth_phdr {
        gint fcs_len;
};



struct x25_phdr {
        guint8 flags;
};




struct isdn_phdr {
        gboolean uton;
        guint8 channel;
};
struct atm_phdr {
        guint32 flags;
        guint8 aal;
        guint8 type;
        guint8 subtype;
        guint16 vpi;
        guint16 vci;
        guint16 channel;
        guint16 cells;
        guint16 aal5t_u2u;
        guint16 aal5t_len;
        guint32 aal5t_chksum;
};
struct ascend_phdr {
        guint16 type;
        char user[64];
        guint32 sess;
        char call_num[64];
        guint32 chunk;
        guint32 task;
};


struct p2p_phdr {
        gboolean sent;
};



struct ieee_802_11_phdr {
        gint fcs_len;
        guint8 channel;
        guint8 data_rate;
        guint8 signal_level;
};
struct cosine_phdr {
        guint8 encap;
        guint8 direction;
        char if_name[128];
        guint16 pro;
        guint16 off;
        guint16 pri;
        guint16 rm;
        guint16 err;
};
struct irda_phdr {
        guint16 pkttype;
};



struct nettl_phdr {
        guint16 subsys;
        guint32 devid;
        guint32 kind;
        gint32 pid;
        gint16 uid;
};



struct mtp2_phdr {
        guint8 sent;
        guint8 annex_a_used;
        guint16 link_number;
};

union wtap_pseudo_header {
        struct eth_phdr eth;
        struct x25_phdr x25;
        struct isdn_phdr isdn;
        struct atm_phdr atm;
        struct ascend_phdr ascend;
        struct p2p_phdr p2p;
        struct ieee_802_11_phdr ieee_802_11;
        struct cosine_phdr cosine;
        struct irda_phdr irda;
        struct nettl_phdr nettl;
        struct mtp2_phdr mtp2;
};

struct wtap_pkthdr {
        struct timeval ts;
        guint32 caplen;
        guint32 len;
        int pkt_encap;
};

struct wtap;
struct Buffer;
struct wtap_dumper;

typedef struct wtap wtap;
typedef struct wtap_dumper wtap_dumper;
struct wtap* wtap_open_offline(const char *filename, int *err,
    gchar **err_info, gboolean do_random);




gboolean wtap_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset);

struct wtap_pkthdr *wtap_phdr(wtap *wth);
union wtap_pseudo_header *wtap_pseudoheader(wtap *wth);
guint8 *wtap_buf_ptr(wtap *wth);

int wtap_fd(wtap *wth);
int wtap_snapshot_length(wtap *wth);
int wtap_file_type(wtap *wth);
int wtap_file_encap(wtap *wth);

const char *wtap_file_type_string(int filetype);
const char *wtap_file_type_short_string(int filetype);
int wtap_short_string_to_file_type(const char *short_name);

const char *wtap_encap_string(int encap);
const char *wtap_encap_short_string(int encap);
int wtap_short_string_to_encap(const char *short_name);

const char *wtap_strerror(int err);
void wtap_sequential_close(wtap *wth);
void wtap_close(wtap *wth);
gboolean wtap_seek_read (wtap *wth, long seek_off,
        union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
        int *err, gchar **err_info);

gboolean wtap_dump_can_open(int filetype);
gboolean wtap_dump_can_write_encap(int filetype, int encap);
wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
        int snaplen, int *err);
wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
        int *err);
gboolean wtap_dump(wtap_dumper *, const struct wtap_pkthdr *,
        const union wtap_pseudo_header *pseudo_header, const guchar *, int *err);
FILE* wtap_dump_file(wtap_dumper *);
gboolean wtap_dump_close(wtap_dumper *, int *);
long wtap_get_bytes_dumped(wtap_dumper *);
void wtap_set_bytes_dumped(wtap_dumper *wdh, long bytes_dumped);
typedef struct {
        unsigned char *buf;
        size_t nbytes;
        int nextout;
        long comp_offset;
        long uncomp_offset;
} ngsniffer_comp_stream_t;

typedef struct {
        guint maj_vers;
        guint min_vers;
        double timeunit;
        time_t start;
        gboolean is_atm;
        ngsniffer_comp_stream_t seq;
        ngsniffer_comp_stream_t rand;
        GList *first_blob;
        GList *last_blob;
        GList *current_blob;
} ngsniffer_t;

typedef struct {
        gboolean byte_swapped;
} i4btrace_t;

typedef struct {
        gboolean is_hpux_11;
} nettl_t;

typedef struct {
        time_t start;
} lanalyzer_t;

typedef enum {
        NOT_SWAPPED,
        SWAPPED,
        MAYBE_SWAPPED
} swapped_type_t;

typedef struct {
        gboolean byte_swapped;
        swapped_type_t lengths_swapped;
        guint16 version_major;
        guint16 version_minor;
} libpcap_t;

typedef struct {
        time_t start_secs;
        guint32 start_usecs;
        guint8 version_major;
        guint32 *frame_table;
        guint32 frame_table_size;
        guint current_frame;
} netmon_t;

typedef struct {
        time_t start_time;
        double timeunit;
        double start_timestamp;
        gboolean wrapped;
        int end_offset;
        int version_major;
        gboolean fcs_valid;
        guint isdn_type;
} netxray_t;

typedef struct {
        time_t inittime;
        int adjusted;
        long next_packet_seek_start;
} ascend_t;

typedef struct {
        gboolean byteswapped;
} csids_t;

typedef struct {
        struct timeval reference_time;
} etherpeek_t;

typedef struct {
        gboolean has_fcs;
} airopeek9_t;

typedef struct {
        guint32 atm_encap;
        gboolean is_rawatm;
        gboolean is_ppp;
} erf_t;

typedef gboolean (*subtype_read_func)(struct wtap*, int*, char**, long*);
typedef gboolean (*subtype_seek_read_func)(struct wtap*, long, union wtap_pseudo_header*,
                                        guint8*, int, int *, char **);
struct wtap {
        FILE * fh;
        int fd;
        FILE * random_fh;
        int file_type;
        int snapshot_length;
        struct Buffer *frame_buffer;
        struct wtap_pkthdr phdr;
        union wtap_pseudo_header pseudo_header;

        long data_offset;

        union {
                libpcap_t *pcap;
                lanalyzer_t *lanalyzer;
                ngsniffer_t *ngsniffer;
                i4btrace_t *i4btrace;
                nettl_t *nettl;
                netmon_t *netmon;
                netxray_t *netxray;
                ascend_t *ascend;
                csids_t *csids;
                etherpeek_t *etherpeek;
                airopeek9_t *airopeek9;
                erf_t *erf;
                void *generic;
        } capture;

        subtype_read_func subtype_read;
        subtype_seek_read_func subtype_seek_read;
        void (*subtype_sequential_close)(struct wtap*);
        void (*subtype_close)(struct wtap*);
        int file_encap;



};

struct wtap_dumper;

typedef gboolean (*subtype_write_func)(struct wtap_dumper*,
                const struct wtap_pkthdr*, const union wtap_pseudo_header*,
                const guchar*, int*);
typedef gboolean (*subtype_close_func)(struct wtap_dumper*, int*);

typedef struct {
        gboolean first_frame;
        time_t start;
} ngsniffer_dump_t;

typedef struct {
        gboolean first_frame;
        struct timeval start;
        guint32 nframes;
} netxray_dump_t;

typedef struct {
        gboolean got_first_record_time;
        struct timeval first_record_time;
        guint32 frame_table_offset;
        guint32 *frame_table;
        guint frame_table_index;
        guint frame_table_size;
} netmon_dump_t;

typedef struct {
        guint32 nframes;
} _5views_dump_t;

typedef struct {
        guint64 packet_count;
        guint8 network_type;
} niobserver_dump_t;

struct wtap_dumper {
        FILE* fh;
        int file_type;
        int snaplen;
        int encap;
        long bytes_dumped;

        union {
                void *opaque;
                ngsniffer_dump_t *ngsniffer;
                netmon_dump_t *netmon;
                netxray_dump_t *netxray;
                _5views_dump_t *_5views;
                niobserver_dump_t *niobserver;
        } dump;

        subtype_write_func subtype_write;
        subtype_close_func subtype_close;
};
