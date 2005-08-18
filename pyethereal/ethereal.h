extern void register_all_protocols(void);
extern void register_all_protocol_handoffs(void);
extern void register_all_tap_listeners(void);
enum { except_no_call, except_call };
typedef struct {
    unsigned long except_group;
    unsigned long except_code;
} except_id_t;
typedef struct {
    except_id_t volatile except_id;
    const char *volatile except_message;
    void *volatile except_dyndata;
} except_t;
struct except_cleanup {
    void (*except_func)(void *);
    void *except_context;
};
struct except_catch {
    const except_id_t *except_id;
    size_t except_size;
    except_t except_obj;
    jmp_buf except_jmp;
};
enum except_stacktype {
    XCEPT_CLEANUP, XCEPT_CATCHER
};
struct except_stacknode {
    struct except_stacknode *except_down;
    enum except_stacktype except_type;
    union {
 struct except_catch *except_catcher;
 struct except_cleanup *except_cleanup;
    } except_info;
};
extern void except_setup_clean(struct except_stacknode *,
 struct except_cleanup *, void (*)(void *), void *);
extern void except_setup_try(struct except_stacknode *,
 struct except_catch *, const except_id_t [], size_t);
extern struct except_stacknode *except_pop(void);
extern int except_init(void);
extern void except_deinit(void);
extern void except_rethrow(except_t *);
extern void except_throw(long, long, const char *);
extern void except_throwd(long, long, const char *, void *);
extern void except_throwf(long, long, const char *, ...);
extern void (*except_unhandled_catcher(void (*)(except_t *)))(except_t *);
extern unsigned long except_code(except_t *);
extern unsigned long except_group(except_t *);
extern const char *except_message(except_t *);
extern void *except_data(except_t *);
extern void *except_take_data(except_t *);
extern void except_set_allocator(void *(*)(size_t), void (*)(void *));
extern void *except_alloc(size_t);
extern void except_free(void *);
typedef enum {
 TVBUFF_REAL_DATA,
 TVBUFF_SUBSET,
 TVBUFF_COMPOSITE
} tvbuff_type;

typedef struct {

 struct tvbuff *tvb;


 guint offset;
 guint length;

} tvb_backing_t;

typedef struct {
 GSList *tvbs;




 guint *start_offsets;
 guint *end_offsets;

} tvb_comp_t;

typedef void (*tvbuff_free_cb_t)(void*);

typedef struct tvbuff {

 tvbuff_type type;
 gboolean initialized;
 guint usage_count;
 struct tvbuff *ds_tvb;




 GSList *used_in;



 union {
  tvb_backing_t subset;
  tvb_comp_t composite;
 } tvbuffs;







 const guint8 *real_data;


 guint length;


 guint reported_length;


 gint raw_offset;


 tvbuff_free_cb_t free_cb;
} tvbuff_t;
extern void tvbuff_init(void);
extern void tvbuff_cleanup(void);
extern tvbuff_t* tvb_new(tvbuff_type);
extern void tvb_free(tvbuff_t*);
extern void tvb_free_chain(tvbuff_t*);
extern guint tvb_increment_usage_count(tvbuff_t*, guint count);
extern guint tvb_decrement_usage_count(tvbuff_t*, guint count);
extern void tvb_set_free_cb(tvbuff_t*, tvbuff_free_cb_t);
extern void tvb_set_child_real_data_tvbuff(tvbuff_t* parent, tvbuff_t* child);
extern void tvb_set_real_data(tvbuff_t*, const guint8* data, guint length,
    gint reported_length);
extern tvbuff_t* tvb_new_real_data(const guint8* data, guint length,
    gint reported_length);
extern void tvb_set_subset(tvbuff_t* tvb, tvbuff_t* backing,
  gint backing_offset, gint backing_length, gint reported_length);
extern tvbuff_t* tvb_new_subset(tvbuff_t* backing,
  gint backing_offset, gint backing_length, gint reported_length);
extern void tvb_composite_append(tvbuff_t* tvb, tvbuff_t* member);
extern void tvb_composite_prepend(tvbuff_t* tvb, tvbuff_t* member);
extern tvbuff_t* tvb_new_composite(void);
extern void tvb_composite_finalize(tvbuff_t* tvb);
extern guint tvb_length(tvbuff_t*);
extern gint tvb_length_remaining(tvbuff_t*, gint offset);
extern guint tvb_ensure_length_remaining(tvbuff_t*, gint offset);
extern gboolean tvb_bytes_exist(tvbuff_t*, gint offset, gint length);
extern void tvb_ensure_bytes_exist(tvbuff_t *tvb, gint offset, gint length);
extern gboolean tvb_offset_exists(tvbuff_t*, gint offset);
extern guint tvb_reported_length(tvbuff_t*);
extern gint tvb_reported_length_remaining(tvbuff_t *tvb, gint offset);
extern void tvb_set_reported_length(tvbuff_t*, guint);
extern int offset_from_real_beginning(tvbuff_t *tvb, int counter);
extern guint8 tvb_get_guint8(tvbuff_t*, gint offset);
extern guint16 tvb_get_ntohs(tvbuff_t*, gint offset);
extern guint32 tvb_get_ntoh24(tvbuff_t*, gint offset);
extern guint32 tvb_get_ntohl(tvbuff_t*, gint offset);
extern guint64 tvb_get_ntoh64(tvbuff_t*, gint offset);
extern gfloat tvb_get_ntohieee_float(tvbuff_t*, gint offset);
extern gdouble tvb_get_ntohieee_double(tvbuff_t*, gint offset);
extern guint16 tvb_get_letohs(tvbuff_t*, gint offset);
extern guint32 tvb_get_letoh24(tvbuff_t*, gint offset);
extern guint32 tvb_get_letohl(tvbuff_t*, gint offset);
extern guint64 tvb_get_letoh64(tvbuff_t*, gint offset);
extern gfloat tvb_get_letohieee_float(tvbuff_t*, gint offset);
extern gdouble tvb_get_letohieee_double(tvbuff_t*, gint offset);
extern guint8* tvb_memcpy(tvbuff_t*, guint8* target, gint offset, gint length);
extern guint8* tvb_memdup(tvbuff_t*, gint offset, gint length);
extern guint8* ep_tvb_memdup(tvbuff_t *tvb, gint offset, gint length);
extern const guint8* tvb_get_ptr(tvbuff_t*, gint offset, gint length);
extern gint tvb_find_guint8(tvbuff_t*, gint offset, gint maxlength,
    guint8 needle);
extern gint tvb_pbrk_guint8(tvbuff_t *, gint offset, gint maxlength,
    guint8 *needles);
extern guint tvb_strsize(tvbuff_t *tvb, gint offset);
extern gint tvb_strnlen(tvbuff_t*, gint offset, guint maxlength);
extern char *tvb_fake_unicode(tvbuff_t *tvb, int offset, int len,
                              gboolean little_endian);
extern gchar * tvb_format_text(tvbuff_t *tvb, gint offset, gint size);
extern gchar *tvb_format_stringzpad(tvbuff_t *tvb, gint offset, gint size);
extern guint8 *tvb_get_string(tvbuff_t *tvb, gint offset, gint length);
extern guint8 *ep_tvb_get_string(tvbuff_t *tvb, gint offset, gint length);
extern guint8 *tvb_get_stringz(tvbuff_t *tvb, gint offset, gint *lengthp);
extern gint tvb_get_nstringz(tvbuff_t *tvb, gint offset, guint bufsize,
    guint8* buffer);
extern gint tvb_get_nstringz0(tvbuff_t *tvb, gint offset, guint bufsize,
    guint8* buffer);
extern gint tvb_find_line_end(tvbuff_t *tvb, gint offset, int len,
    gint *next_offset, gboolean desegment);
extern gint tvb_find_line_end_unquoted(tvbuff_t *tvb, gint offset, int len,
    gint *next_offset);
extern gint tvb_strneql(tvbuff_t *tvb, gint offset, const gchar *str,
    gint size);
extern gint tvb_strncaseeql(tvbuff_t *tvb, gint offset, const gchar *str,
    gint size);
extern gint tvb_memeql(tvbuff_t *tvb, gint offset, const guint8 *str,
    gint size);
extern gchar *tvb_bytes_to_str_punct(tvbuff_t *tvb, gint offset, gint len,
    gchar punct);
extern gchar *tvb_bytes_to_str(tvbuff_t *tvb, gint offset, gint len);
extern gint tvb_find_tvb(tvbuff_t *haystack_tvb, tvbuff_t *needle_tvb,
 gint haystack_offset);
extern tvbuff_t* tvb_uncompress(tvbuff_t *tvb, int offset, int comprlen);
typedef struct {
 guint32 addr;
 guint32 nmask;
} ipv4_addr;
ipv4_addr* ipv4_addr_new(void);
void ipv4_addr_free(ipv4_addr *ipv4);
void ipv4_addr_set_host_order_addr(ipv4_addr *ipv4, guint32 new_addr);
void ipv4_addr_set_net_order_addr(ipv4_addr *ipv4, guint32 new_addr);
void ipv4_addr_set_netmask_bits(ipv4_addr *ipv4, guint new_nmask_bits);
guint32 ipv4_get_net_order_addr(ipv4_addr *ipv4);
guint32 ipv4_get_host_order_addr(ipv4_addr *ipv4);
void ipv4_addr_str_buf(const ipv4_addr *ipv4, gchar *buf);
gboolean ipv4_addr_eq(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_gt(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_ge(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_lt(ipv4_addr *a, ipv4_addr *b);
gboolean ipv4_addr_le(ipv4_addr *a, ipv4_addr *b);
typedef struct {
 time_t secs;
 int nsecs;
} nstime_t;
enum ftenum {
 FT_NONE,
 FT_PROTOCOL,
 FT_BOOLEAN,
 FT_UINT8,
 FT_UINT16,
 FT_UINT24,
 FT_UINT32,
 FT_UINT64,
 FT_INT8,
 FT_INT16,
 FT_INT24,
 FT_INT32,
 FT_INT64,
 FT_FLOAT,
 FT_DOUBLE,
 FT_ABSOLUTE_TIME,
 FT_RELATIVE_TIME,
 FT_STRING,
 FT_STRINGZ,
 FT_UINT_STRING,
 FT_ETHER,
 FT_BYTES,
 FT_UINT_BYTES,
 FT_IPv4,
 FT_IPv6,
 FT_IPXNET,
 FT_FRAMENUM,
 FT_PCRE,
 FT_GUID,
 FT_NUM_TYPES
};
typedef enum ftenum ftenum_t;
typedef struct _ftype_t ftype_t;
enum ftrepr {
    FTREPR_DISPLAY,
    FTREPR_DFILTER
};
typedef enum ftrepr ftrepr_t;
typedef struct _pcre_tuple_t pcre_tuple_t;
void
ftypes_initialize(void);
const char*
ftype_name(ftenum_t ftype);
const char*
ftype_pretty_name(ftenum_t ftype);
int
ftype_length(ftenum_t ftype);
gboolean
ftype_can_slice(enum ftenum ftype);
gboolean
ftype_can_eq(enum ftenum ftype);
gboolean
ftype_can_ne(enum ftenum ftype);
gboolean
ftype_can_gt(enum ftenum ftype);
gboolean
ftype_can_ge(enum ftenum ftype);
gboolean
ftype_can_lt(enum ftenum ftype);
gboolean
ftype_can_le(enum ftenum ftype);
gboolean
ftype_can_bitwise_and(enum ftenum ftype);
gboolean
ftype_can_contains(enum ftenum ftype);
gboolean
ftype_can_matches(enum ftenum ftype);
typedef enum {
 UNINITIALIZED,
 LENGTH,
 OFFSET,
 TO_THE_END
} drange_node_end_t;
typedef struct _drange_node {
  gint start_offset;
  gint length;
  gint end_offset;
  drange_node_end_t ending;
} drange_node;
typedef struct _drange {
  GSList* range_list;
  gboolean has_total_length;
  gint total_length;
  gint min_start_offset;
  gint max_start_offset;
} drange;
drange_node* drange_node_new(void);
void drange_node_free(drange_node* drnode);
void drange_node_free_list(GSList* list);
gint drange_node_get_start_offset(drange_node* drnode);
gint drange_node_get_length(drange_node* drnode);
gint drange_node_get_end_offset(drange_node* drnode);
drange_node_end_t drange_node_get_ending(drange_node* drnode);
void drange_node_set_start_offset(drange_node* drnode, gint offset);
void drange_node_set_length(drange_node* drnode, gint length);
void drange_node_set_end_offset(drange_node* drnode, gint offset);
void drange_node_set_to_the_end(drange_node* drnode);
drange* drange_new(void);
drange* drange_new_from_list(GSList *list);
void drange_free(drange* dr);
gboolean drange_has_total_length(drange* dr);
gint drange_get_total_length(drange* dr);
gint drange_get_min_start_offset(drange* dr);
gint drange_get_max_start_offset(drange* dr);
void drange_append_drange_node(drange* dr, drange_node* drnode);
void drange_prepend_drange_node(drange* dr, drange_node* drnode);
void drange_foreach_drange_node(drange* dr, GFunc func, gpointer funcdata);
typedef struct _fvalue_t {
 ftype_t *ftype;
 union {
  gpointer pointer;
  guint32 integer;
  guint64 integer64;
  gdouble floating;
  gchar *string;
  guchar *ustring;
  GByteArray *bytes;
  GString *gstring;
  ipv4_addr ipv4;
  nstime_t time;
  tvbuff_t *tvb;
  pcre_tuple_t *re;
 } value;
 gboolean fvalue_gboolean1;
} fvalue_t;
typedef void (*FvalueNewFunc)(fvalue_t*);
typedef void (*FvalueFreeFunc)(fvalue_t*);
typedef void (*LogFunc)(const char*,...);
typedef gboolean (*FvalueFromUnparsed)(fvalue_t*, char*, gboolean, LogFunc);
typedef gboolean (*FvalueFromString)(fvalue_t*, char*, LogFunc);
typedef void (*FvalueToStringRepr)(fvalue_t*, ftrepr_t, char*);
typedef int (*FvalueStringReprLen)(fvalue_t*, ftrepr_t);
typedef void (*FvalueSetFunc)(fvalue_t*, gpointer, gboolean);
typedef void (*FvalueSetIntegerFunc)(fvalue_t*, guint32);
typedef void (*FvalueSetInteger64Func)(fvalue_t*, guint64);
typedef void (*FvalueSetFloatingFunc)(fvalue_t*, gdouble);
typedef gpointer (*FvalueGetFunc)(fvalue_t*);
typedef guint32 (*FvalueGetIntegerFunc)(fvalue_t*);
typedef guint64 (*FvalueGetInteger64Func)(fvalue_t*);
typedef double (*FvalueGetFloatingFunc)(fvalue_t*);
typedef gboolean (*FvalueCmp)(fvalue_t*, fvalue_t*);
typedef guint (*FvalueLen)(fvalue_t*);
typedef void (*FvalueSlice)(fvalue_t*, GByteArray *, guint offset, guint length);
struct _ftype_t {
 const char *name;
 const char *pretty_name;
 int wire_size;
 FvalueNewFunc new_value;
 FvalueFreeFunc free_value;
 FvalueFromUnparsed val_from_unparsed;
 FvalueFromString val_from_string;
 FvalueToStringRepr val_to_string_repr;
 FvalueStringReprLen len_string_repr;
 FvalueSetFunc set_value;
 FvalueSetIntegerFunc set_value_integer;
 FvalueSetInteger64Func set_value_integer64;
 FvalueSetFloatingFunc set_value_floating;
 FvalueGetFunc get_value;
 FvalueGetIntegerFunc get_value_integer;
 FvalueGetInteger64Func get_value_integer64;
 FvalueGetFloatingFunc get_value_floating;
 FvalueCmp cmp_eq;
 FvalueCmp cmp_ne;
 FvalueCmp cmp_gt;
 FvalueCmp cmp_ge;
 FvalueCmp cmp_lt;
 FvalueCmp cmp_le;
 FvalueCmp cmp_bitwise_and;
 FvalueCmp cmp_contains;
 FvalueCmp cmp_matches;
 FvalueLen len;
 FvalueSlice slice;
};
fvalue_t*
fvalue_new(ftenum_t ftype);
void
fvalue_init(fvalue_t *fv, ftenum_t ftype);
union fvalue_tslab_item { fvalue_t slab_item; union fvalue_tslab_item *next_free; };
extern union fvalue_tslab_item *fvalue_t_free_list;
fvalue_t*
fvalue_from_unparsed(ftenum_t ftype, char *s, gboolean allow_partial_value, LogFunc logfunc);
fvalue_t*
fvalue_from_string(ftenum_t ftype, char *s, LogFunc logfunc);
int
fvalue_string_repr_len(fvalue_t *fv, ftrepr_t rtype);
extern char *
fvalue_to_string_repr(fvalue_t *fv, ftrepr_t rtype, char *buf);
const char*
fvalue_type_name(fvalue_t *fv);
void
fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied);
void
fvalue_set_integer(fvalue_t *fv, guint32 value);
void
fvalue_set_integer64(fvalue_t *fv, guint64 value);
void
fvalue_set_floating(fvalue_t *fv, gdouble value);
gpointer
fvalue_get(fvalue_t *fv);
extern guint32
fvalue_get_integer(fvalue_t *fv);
guint64
fvalue_get_integer64(fvalue_t *fv);
extern double
fvalue_get_floating(fvalue_t *fv);
gboolean
fvalue_eq(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_ne(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_gt(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_ge(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_lt(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_le(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_bitwise_and(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_contains(fvalue_t *a, fvalue_t *b);
gboolean
fvalue_matches(fvalue_t *a, fvalue_t *b);
guint
fvalue_length(fvalue_t *fv);
fvalue_t*
fvalue_slice(fvalue_t *fv, drange *dr);
extern int hf_text_only;
struct _value_string;
struct _protocol;
typedef struct _protocol protocol_t;
typedef enum {
 BASE_NONE,
 BASE_DEC,
 BASE_HEX,
 BASE_OCT
} base_display_e;
typedef struct _header_field_info header_field_info;
struct _header_field_info {
 const char *name;
 const char *abbrev;
 enum ftenum type;
 int display;
 const void *strings;
 guint32 bitmask;
 const char *blurb;
 int id;
 int parent;
 int ref_count;
 int bitshift;
 header_field_info *same_name_next;
 header_field_info *same_name_prev;
};
typedef struct hf_register_info {
 int *p_id;
 header_field_info hfinfo;
} hf_register_info;
typedef struct _item_label_t {
 char representation[240];
} item_label_t;
typedef struct field_info {
 header_field_info *hfinfo;
 gint start;
 gint length;
 gint tree_type;
 item_label_t *rep;
 int flags;
 tvbuff_t *ds_tvb;
 fvalue_t value;
} field_info;
typedef struct {
    GHashTable *interesting_hfids;
    gboolean visible;
} tree_data_t;
typedef struct _proto_node {
 struct _proto_node *first_child;
 struct _proto_node *last_child;
 struct _proto_node *next;
 struct _proto_node *parent;
 field_info *finfo;
 tree_data_t *tree_data;
} proto_node;
typedef proto_node proto_tree;
typedef proto_node proto_item;
typedef void (*proto_tree_foreach_func)(proto_node *, gpointer);
extern void proto_tree_children_foreach(proto_tree *tree,
    proto_tree_foreach_func func, gpointer data);
extern void proto_init(const char *plugin_dir,
    void (register_all_protocols)(void), void (register_all_handoffs)(void));
extern void proto_cleanup(void);
extern gboolean proto_field_is_referenced(proto_tree *tree, int proto_id);
extern proto_tree* proto_item_add_subtree(proto_item *ti, gint idx);
extern proto_tree* proto_item_get_subtree(proto_item *ti);
extern proto_item* proto_item_get_parent(proto_item *ti);
extern proto_item* proto_item_get_parent_nth(proto_item *ti, int gen);
extern void proto_item_set_text(proto_item *ti, const char *format, ...)
 __attribute__((format (printf, 2, 3)));
extern void proto_item_append_text(proto_item *ti, const char *format, ...)
 __attribute__((format (printf, 2, 3)));
extern void proto_item_set_len(proto_item *ti, gint length);
extern void proto_item_set_end(proto_item *ti, tvbuff_t *tvb, gint end);
extern int proto_item_get_len(proto_item *ti);
extern proto_tree* proto_tree_create_root(void);
extern void proto_tree_free(proto_tree *tree);
extern void
proto_tree_set_visible(proto_tree *tree, gboolean visible);
extern void
proto_tree_prime_hfid(proto_tree *tree, int hfid);
extern proto_item* proto_tree_get_parent(proto_tree *tree);
extern void proto_tree_move_item(proto_tree *tree, proto_item *fixed_item, proto_item *item_to_move);
extern proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian);
extern proto_item *
proto_tree_add_item_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian);
extern proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char *format,
 ...) __attribute__((format (printf, 5, 6)));
extern proto_item *
proto_tree_add_text_valist(proto_tree *tree, tvbuff_t *tvb, gint start,
 gint length, const char *format, va_list ap);
extern proto_item *
proto_tree_add_none_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const char *format, ...) __attribute__((format (printf, 6, 7)));
extern proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const char *format, ...) __attribute__((format (printf, 6, 7)));
extern proto_item *
proto_tree_add_bytes(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* start_ptr);
extern proto_item *
proto_tree_add_bytes_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* start_ptr);
extern proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* start_ptr, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, nstime_t* value_ptr);
extern proto_item *
proto_tree_add_time_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, nstime_t* value_ptr);
extern proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, nstime_t* value_ptr, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);
extern proto_item *
proto_tree_add_ipxnet_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);
extern proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);
extern proto_item *
proto_tree_add_ipv4_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);

extern proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value_ptr);
extern proto_item *
proto_tree_add_ipv6_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value_ptr);
extern proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value_ptr, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value);
extern proto_item *
proto_tree_add_ether_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value);
extern proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_guid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value_ptr);
extern proto_item *
proto_tree_add_guid_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value_ptr);
extern proto_item *
proto_tree_add_guid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const guint8* value_ptr, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const char* value);
extern proto_item *
proto_tree_add_string_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const char* value);
extern proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, const char* value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);
extern proto_item *
proto_tree_add_boolean_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);
extern proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_float(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, float value);
extern proto_item *
proto_tree_add_float_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, float value);
extern proto_item *
proto_tree_add_float_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, float value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_double(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, double value);
extern proto_item *
proto_tree_add_double_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, double value);
extern proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, double value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);
extern proto_item *
proto_tree_add_uint_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value);
extern proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint32 value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint64 value);
extern proto_item *
proto_tree_add_uint64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, guint64 value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, gint32 value);
extern proto_item *
proto_tree_add_int_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, gint32 value);
extern proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, gint32 value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, gint64 value);
extern proto_item *
proto_tree_add_int64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
 gint length, gint64 value, const char *format, ...) __attribute__((format (printf, 7, 8)));
extern proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format,
 ...) __attribute__((format (printf, 2, 3)));
extern void
proto_item_append_string(proto_item *pi, const char *str);
extern void
proto_item_fill_label(field_info *fi, gchar *label_str);
extern int
proto_register_protocol(const char *name, const char *short_name, const char *filter_name);
extern void
proto_register_field_array(int parent, hf_register_info *hf, int num_records);
extern void
proto_register_subtree_array(gint *const *indices, int num_indices);
extern int proto_registrar_n(void);
extern const char* proto_registrar_get_name(int n);
extern const char* proto_registrar_get_abbrev(int n);
extern header_field_info* proto_registrar_get_nth(guint hfindex);
extern header_field_info* proto_registrar_get_byname(const char *field_name);
extern int proto_registrar_get_ftype(int n);
extern int proto_registrar_get_parent(int n);
extern gboolean proto_registrar_is_protocol(int n);
extern gint proto_registrar_get_length(int n);
extern int proto_get_first_protocol(void **cookie);
extern int proto_get_next_protocol(void **cookie);
extern header_field_info *proto_get_first_protocol_field(int proto_id, void **cookle);
extern header_field_info *proto_get_next_protocol_field(void **cookle);
extern int proto_get_id_by_filter_name(const gchar* filter_name);
extern gboolean proto_can_toggle_protocol(int proto_id);
extern protocol_t *find_protocol_by_id(int proto_id);
extern const char *proto_get_protocol_name(int proto_id);
extern int proto_get_id(protocol_t *protocol);
extern const char *proto_get_protocol_short_name(protocol_t *protocol);
extern gboolean proto_is_protocol_enabled(protocol_t *protocol);
extern const char *proto_get_protocol_filter_name(int proto_id);
extern void proto_set_decoding(int proto_id, gboolean enabled);
extern void proto_set_cant_toggle(int proto_id);
extern gboolean proto_check_for_protocol_or_field(proto_tree* tree, int id);
extern GPtrArray* proto_get_finfo_ptr_array(proto_tree *tree, int hfindex);
extern GPtrArray* proto_find_finfo(proto_tree *tree, int hfindex);
extern void proto_registrar_dump_protocols(void);
extern void proto_registrar_dump_values(void);
extern void proto_registrar_dump_fields(int format);
extern gboolean *tree_is_expanded;
extern int num_tree_types;
extern int
hfinfo_bitwidth(header_field_info *hfinfo);
typedef struct _column_info {
  gint num_cols;
  gint *col_fmt;
  gboolean **fmt_matx;
  gint *col_first;
  gint *col_last;
  gchar **col_title;
  const gchar **col_data;
  gchar **col_buf;
  int *col_fence;
  gchar **col_expr;
  gchar **col_expr_val;
  gboolean writable;
} column_info;
enum {
  COL_NUMBER,
  COL_CLS_TIME,
  COL_REL_TIME,
  COL_ABS_TIME,
  COL_ABS_DATE_TIME,
  COL_DELTA_TIME,
  COL_DEF_SRC,
  COL_RES_SRC,
  COL_UNRES_SRC,
  COL_DEF_DL_SRC,
  COL_RES_DL_SRC,
  COL_UNRES_DL_SRC,
  COL_DEF_NET_SRC,
  COL_RES_NET_SRC,
  COL_UNRES_NET_SRC,
  COL_DEF_DST,
  COL_RES_DST,
  COL_UNRES_DST,
  COL_DEF_DL_DST,
  COL_RES_DL_DST,
  COL_UNRES_DL_DST,
  COL_DEF_NET_DST,
  COL_RES_NET_DST,
  COL_UNRES_NET_DST,
  COL_DEF_SRC_PORT,
  COL_RES_SRC_PORT,
  COL_UNRES_SRC_PORT,
  COL_DEF_DST_PORT,
  COL_RES_DST_PORT,
  COL_UNRES_DST_PORT,
  COL_PROTOCOL,
  COL_INFO,
  COL_PACKET_LENGTH,
  COL_CUMULATIVE_BYTES,
  COL_OXID,
  COL_RXID,
  COL_IF_DIR,
  COL_CIRCUIT_ID,
  COL_SRCIDX,
  COL_DSTIDX,
  COL_VSAN,
  COL_TX_RATE,
  COL_RSSI,
  COL_HPUX_SUBSYS,
  COL_HPUX_DEVID,
  COL_DCE_CALL,
  NUM_COL_FMTS
};
typedef struct _frame_data {
  struct _frame_data *next;
  struct _frame_data *prev;
  GSList *pfd;
  guint32 num;
  guint32 pkt_len;
  guint32 cap_len;
  guint32 cum_bytes;
  gint32 rel_secs;
  gint32 rel_usecs;
  guint32 abs_secs;
  guint32 abs_usecs;
  gint32 del_secs;
  gint32 del_usecs;
  long file_off;
  int lnk_t;
  struct {
 unsigned int passed_dfilter : 1;
   unsigned int encoding : 2;
 unsigned int visited : 1;
 unsigned int marked : 1;
 unsigned int ref_time : 1;
  } flags;
  void *color_filter;
} frame_data;
typedef struct {
  tvbuff_t *tvb;
  char *name;
} data_source;
extern void p_add_proto_data(frame_data *, int, void *);
extern void *p_get_proto_data(frame_data *, int);
extern void p_rem_proto_data(frame_data *fd, int proto);
extern void frame_data_init(void);
extern void frame_data_cleanup(void);
typedef struct _epan_dissect_t epan_dissect_t;
typedef struct _dfilter_t dfilter_t;
void
dfilter_init(void);
void
dfilter_cleanup(void);
gboolean
dfilter_compile(const gchar *text, dfilter_t **dfp);
void
dfilter_free(dfilter_t *df);
extern gchar *dfilter_error_msg;
gboolean
dfilter_apply_edt(dfilter_t *df, epan_dissect_t* edt);
gboolean
dfilter_apply(dfilter_t *df, proto_tree *tree);
void
dfilter_prime_proto_tree(const dfilter_t *df, proto_tree *tree);
void
dfilter_dump(dfilter_t *df);
void epan_init(const char * plugindir, void (*register_all_protocols)(void),
        void (*register_all_handoffs)(void),
        void (*report_failure)(const char *, va_list),
        void (*report_open_failure)(const char *, int, gboolean),
        void (*report_read_failure)(const char *, int));
void epan_cleanup(void);
void epan_conversation_init(void);
void epan_circuit_init(void);
typedef struct epan_session epan_t;
epan_t*
epan_new(void);
void
epan_free(epan_t*);
epan_dissect_t*
epan_dissect_new(gboolean create_proto_tree, gboolean proto_tree_visible);
void
epan_dissect_run(epan_dissect_t *edt, void* pseudo_header,
        const guint8* data, frame_data *fd, column_info *cinfo);
void
epan_dissect_prime_dfilter(epan_dissect_t *edt, const dfilter_t*);
void
epan_dissect_fill_in_columns(epan_dissect_t *edt);
void
epan_dissect_free(epan_dissect_t* edt);
extern gboolean
proto_can_match_selected(field_info *finfo, epan_dissect_t *edt);
extern char*
proto_construct_dfilter_string(field_info *finfo, epan_dissect_t *edt);
extern field_info*
proto_find_field_from_offset(proto_tree *tree, guint offset, tvbuff_t *tvb);
typedef enum {
  AT_NONE,
  AT_ETHER,
  AT_IPv4,
  AT_IPv6,
  AT_IPX,
  AT_SNA,
  AT_ATALK,
  AT_VINES,
  AT_OSI,
  AT_ARCNET,
  AT_FC,
  AT_SS7PC,
  AT_STRINGZ,
  AT_EUI64,
  AT_URI
} address_type;
typedef struct _address {
  address_type type;
  int len;
  const guint8 *data;
} address;
typedef enum {
  PT_NONE,
  PT_SCTP,
  PT_TCP,
  PT_UDP,
  PT_IPX,
  PT_NCP,
  PT_EXCHG,
  PT_DDP,
  PT_SBCCS,
  PT_IDP
} port_type;
typedef enum {
  CT_NONE,
  CT_DLCI,
  CT_ISDN,
  CT_X25,
  CT_ISUP,
  CT_IAX2
} circuit_type;
typedef struct _packet_info {
  const char *current_proto;
  column_info *cinfo;
  frame_data *fd;
  union wtap_pseudo_header *pseudo_header;
  GSList *data_src;
  address dl_src;
  address dl_dst;
  address net_src;
  address net_dst;
  address src;
  address dst;
  guint32 ethertype;
  guint32 ipproto;
  guint32 ipxptype;
  circuit_type ctype;
  guint32 circuit_id;
  const char *noreassembly_reason;
  gboolean fragmented;
  gboolean in_error_pkt;
  port_type ptype;
  guint32 srcport;
  guint32 destport;
  guint32 match_port;
  const char *match_string;
  guint16 can_desegment;
  guint16 saved_can_desegment;
  int desegment_offset;
  guint32 desegment_len;
  guint16 want_pdu_tracking;
  guint32 bytes_until_next_pdu;
  int iplen;
  int iphdrlen;
  int p2p_dir;
  guint16 oxid;
  guint16 rxid;
  guint8 r_ctl;
  guint8 sof_eof;
  guint16 src_idx;
  guint16 dst_idx;
  guint16 vsan;
  guint16 dcectxid;
  int dcetransporttype;
  guint16 dcetransportsalt;
  guint16 decrypt_gssapi_tvb;
  tvbuff_t *gssapi_wrap_tvb;
  tvbuff_t *gssapi_encrypted_tvb;
  tvbuff_t *gssapi_decrypted_tvb;
  gboolean gssapi_data_encrypted;
  guint32 ppid[2];
  void *private_data;
  GString *layer_names;
  guint16 link_number;
  gchar annex_a_used;
} packet_info;
struct _epan_dissect_t {
 tvbuff_t *tvb;
 proto_tree *tree;
 packet_info pi;
};
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
typedef union {
 struct {
  guint16 vp;
  guint16 vc;
 } atm;
 guint32 ds0mask;
} k12_input_info_t;
struct k12_phdr {
 guint32 input;
 const gchar* input_name;
 const gchar* stack_file;
 guint32 input_type;
 k12_input_info_t input_info;
 void* stuff;
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
 struct k12_phdr k12;
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
typedef enum {
 MSECS,
 USECS,
 NSECS
} time_res_t;
struct e_in6_addr;
extern gchar* address_to_str(const address *);
extern void address_to_str_buf(const address *, gchar *);
extern gchar* ether_to_str(const guint8 *);
extern gchar* ip_to_str(const guint8 *);
extern void ip_to_str_buf(const guint8 *, gchar *);
extern gchar* fc_to_str(const guint8 *);
extern gchar* fcwwn_to_str (const guint8 *);
extern gchar* ip6_to_str(const struct e_in6_addr *);
extern void ip6_to_str_buf(const struct e_in6_addr *, gchar *);
extern gchar* ipx_addr_to_str(guint32, const guint8 *);
extern gchar* ipxnet_to_string(const guint8 *ad);
extern gchar* ipxnet_to_str_punct(const guint32 ad, char punct);
extern gchar* vines_addr_to_str(const guint8 *addrp);
extern void vines_addr_to_str_buf(const guint8 *addrp, gchar *buf);
extern gchar* time_secs_to_str(gint32);
extern gchar* time_msecs_to_str(gint32);
extern gchar* abs_time_to_str(nstime_t*);
extern gchar* abs_time_secs_to_str(time_t);
extern void display_signed_time(gchar *, int, gint32, gint32, time_res_t);
extern gchar* rel_time_to_str(nstime_t*);
extern gchar* rel_time_to_secs_str(nstime_t*);
extern gchar* oid_to_str(const guint8*, gint);
extern gchar* oid_to_str_buf(const guint8*, gint, gchar*);
extern gchar* guid_to_str(const guint8*);
extern gchar* guid_to_str_buf(const guint8*, gchar*);
extern char *other_decode_bitfield_value(char *buf, guint32 val, guint32 mask,
    int width);
extern char *decode_bitfield_value(char *buf, guint32 val, guint32 mask,
    int width);
extern const char *decode_boolean_bitfield(guint32 val, guint32 mask, int width,
  const char *truedesc, const char *falsedesc);
extern const char *decode_numeric_bitfield(guint32 val, guint32 mask, int width,
  const char *fmt);
typedef struct _value_string {
  guint32 value;
  const gchar *strptr;
} value_string;
extern const gchar* match_strval_idx(guint32 val, const value_string *vs, gint *idx);
extern const gchar* match_strval(guint32 val, const value_string *vs);
extern const gchar* val_to_str(guint32 val, const value_string *vs, const char *fmt);
extern const char *decode_enumerated_bitfield(guint32 val, guint32 mask,
  int width, const value_string *tab, const char *fmt);
extern const char *decode_enumerated_bitfield_shifted(guint32 val, guint32 mask,
  int width, const value_string *tab, const char *fmt);
extern void col_setup(column_info *, gint);
extern void col_init(column_info *);
extern gboolean col_get_writable(column_info *);
extern void col_set_writable(column_info *, gboolean);
extern gint check_col(column_info *, gint);
extern void col_set_fence(column_info *, gint);
extern void col_clear(column_info *, gint);
extern void col_set_str(column_info *, gint, const gchar *);
extern void col_add_fstr(column_info *, gint, const gchar *, ...)
    __attribute__((format (printf, 3, 4)));
extern void col_append_fstr(column_info *, gint, const gchar *, ...)
    __attribute__((format (printf, 3, 4)));
extern void col_append_sep_fstr(column_info *, gint, const gchar *sep,
  const gchar *fmt, ...)
    __attribute__((format (printf, 4, 5)));
extern void col_prepend_fstr(column_info *, gint, const gchar *, ...)
    __attribute__((format (printf, 3, 4)));
extern void col_add_str(column_info *, gint, const gchar *);
extern void col_append_str(column_info *, gint, const gchar *);
extern void col_append_sep_str(column_info *, gint, const gchar *sep,
  const gchar *str);
extern void col_set_cls_time(frame_data *, column_info *, int);
extern void fill_in_columns(packet_info *);
typedef struct _packet_counts {
  gint sctp;
  gint tcp;
  gint udp;
  gint icmp;
  gint ospf;
  gint gre;
  gint netbios;
  gint ipx;
  gint vines;
  gint other;
  gint total;
  gint arp;
} packet_counts;
typedef enum {
 CHAR_ASCII = 0,
 CHAR_EBCDIC = 1
} char_enc;
typedef struct true_false_string {
 const char *true_string;
 const char *false_string;
} true_false_string;
extern const true_false_string flags_set_truth;
extern void packet_init(void);
extern void packet_cleanup(void);
struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;
struct dissector_table;
typedef struct dissector_table *dissector_table_t;
typedef void (*dissector_t)(tvbuff_t *, packet_info *, proto_tree *);
typedef int (*new_dissector_t)(tvbuff_t *, packet_info *, proto_tree *);
typedef gboolean (*heur_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
 proto_tree *tree);
typedef void (*DATFunc) (gchar *table_name, ftenum_t selector_type,
    gpointer key, gpointer value, gpointer user_data);
typedef void (*DATFunc_handle) (gchar *table_name, gpointer value,
    gpointer user_data);
typedef void (*DATFunc_table) (gchar *table_name, const gchar *ui_name,
    gpointer user_data);
typedef struct dtbl_entry dtbl_entry_t;
extern dissector_handle_t dtbl_entry_get_handle (dtbl_entry_t *dtbl_entry);
extern dissector_handle_t dtbl_entry_get_initial_handle (dtbl_entry_t * entry);
extern void dissector_table_foreach_changed (char *name, DATFunc func,
    gpointer user_data);
extern void dissector_table_foreach (char *name, DATFunc func,
    gpointer user_data);
extern void dissector_all_tables_foreach_changed (DATFunc func,
    gpointer user_data);
extern void dissector_table_foreach_handle(char *name, DATFunc_handle func,
    gpointer user_data);
extern void dissector_all_tables_foreach_table (DATFunc_table func,
    gpointer user_data);
extern dissector_table_t register_dissector_table(const char *name,
    const char *ui_name, ftenum_t type, int base);
extern dissector_table_t find_dissector_table(const char *name);
extern const char *get_dissector_table_ui_name(const char *name);
extern ftenum_t get_dissector_table_selector_type(const char *name);
extern int get_dissector_table_base(const char *name);
extern void dissector_add(const char *abbrev, guint32 pattern,
    dissector_handle_t handle);
extern void dissector_delete(const char *name, guint32 pattern,
    dissector_handle_t handle);
extern void dissector_change(const char *abbrev, guint32 pattern,
    dissector_handle_t handle);
extern void dissector_reset(const char *name, guint32 pattern);
extern gboolean dissector_try_port(dissector_table_t sub_dissectors,
    guint32 port, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern dissector_handle_t dissector_get_port_handle(
    dissector_table_t sub_dissectors, guint32 port);
extern void dissector_add_string(const char *name, const gchar *pattern,
    dissector_handle_t handle);
extern void dissector_delete_string(const char *name, const gchar *pattern,
 dissector_handle_t handle);
extern void dissector_change_string(const char *name, gchar *pattern,
    dissector_handle_t handle);
extern void dissector_reset_string(const char *name, const gchar *pattern);
extern gboolean dissector_try_string(dissector_table_t sub_dissectors,
    const gchar *string, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern dissector_handle_t dissector_get_string_handle(
    dissector_table_t sub_dissectors, const gchar *string);
extern void dissector_add_handle(const char *name, dissector_handle_t handle);
typedef GSList *heur_dissector_list_t;
extern void register_heur_dissector_list(const char *name,
    heur_dissector_list_t *list);
extern gboolean dissector_try_heuristic(heur_dissector_list_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void heur_dissector_add(const char *name, heur_dissector_t dissector,
    int proto);
extern void register_dissector(const char *name, dissector_t dissector,
    int proto);
extern void new_register_dissector(const char *name, new_dissector_t dissector,
    int proto);
extern const char *dissector_handle_get_short_name(dissector_handle_t handle);
extern int dissector_handle_get_protocol_index(dissector_handle_t handle);
extern dissector_handle_t find_dissector(const char *name);
extern dissector_handle_t create_dissector_handle(dissector_t dissector,
    int proto);
extern dissector_handle_t new_create_dissector_handle(new_dissector_t dissector,
    int proto);
extern int call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree);
extern int call_dissector_only(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree);
extern void dissect_init(void);
extern void dissect_cleanup(void);
extern void set_actual_length(tvbuff_t *tvb, guint specified_len);
extern void register_init_routine(void (*func)(void));
extern void init_dissection(void);
extern void cleanup_dissection(void);
extern void register_postseq_cleanup_routine(void (*func)(void));
extern void postseq_cleanup_all_protocols(void);
extern void
register_final_registration_routine(void (*func)(void));
extern void
final_registration_all_protocols(void);
extern void add_new_data_source(packet_info *pinfo, tvbuff_t *tvb,
    const char *name);
extern void free_data_sources(packet_info *pinfo);
extern void dissect_packet(epan_dissect_t *edt,
    union wtap_pseudo_header *pseudo_header, const guchar *pd,
    frame_data *fd, column_info *cinfo);
extern void capture_ethertype(guint16 etype, const guchar *pd, int offset,
  int len, packet_counts *ld);
extern void ethertype(guint16 etype, tvbuff_t *tvb, int offset_after_ethertype,
  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
  int etype_id, int trailer_id, int fcs_len);
extern void dissector_dump_decodes(void);
