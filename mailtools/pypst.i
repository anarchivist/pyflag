%module pypst

// rename due to name clashes
%rename(from_offset) from;
%rename(to_offset) to;

// declared but never defined
%ignore _pst_getItem;

%{
#include "libpst.h"
%}

// change to simple types which get mapped
typedef int int32_t;
typedef unsigned int u_int32_t;

//%include "libpst.h"

#define PST_TYPE_NOTE 1
#define PST_TYPE_APPOINTMENT 8
#define PST_TYPE_CONTACT 9
#define PST_TYPE_JOURNAL 10
#define PST_TYPE_STICKYNOTE 11
#define PST_TYPE_TASK 12
#define PST_TYPE_OTHER 13
#define PST_TYPE_REPORT 14

typedef struct _pst_item_contact {
  char *access_method;
  char *account_name;
  char *address1;
  char *address1_desc;
  char *address1_transport;
  char *address2;
  char *address2_desc;
  char *address2_transport;
  char *address3;
  char *address3_desc;
  char *address3_transport;
  char *assistant_name;
  char *assistant_phone;
  char *billing_information;
  FILETIME *birthday;
  char *business_address;
  char *business_city;
  char *business_country;
  char *business_fax;
  char *business_homepage;
  char *business_phone;
  char *business_phone2;
  char *business_po_box;
  char *business_postal_code;
  char *business_state;
  char *business_street;
  char *callback_phone;
  char *car_phone;
  char *company_main_phone;
  char *company_name;
  char *computer_name;
  char *customer_id;
  char *def_postal_address;
  char *department;
  char *display_name_prefix;
  char *first_name;
  char *followup;
  char *free_busy_address;
  char *ftp_site;
  char *fullname;
  int32_t  gender;
  char *gov_id;
  char *hobbies;
  char *home_address;
  char *home_city;
  char *home_country;
  char *home_fax;
  char *home_phone;
  char *home_phone2;
  char *home_po_box;
  char *home_postal_code;
  char *home_state;
  char *home_street;
  char *initials;
  char *isdn_phone;
  char *job_title;
  char *keyword;
  char *language;
  char *location;
  int32_t  mail_permission;
  char *manager_name;
  char *middle_name;
  char *mileage;
  char *mobile_phone;
  char *nickname;
  char *office_loc;
  char *org_id;
  char *other_address;
  char *other_city;
  char *other_country;
  char *other_phone;
  char *other_po_box;
  char *other_postal_code;
  char *other_state;
  char *other_street;
  char *pager_phone;
  char *personal_homepage;
  char *pref_name;
  char *primary_fax;
  char *primary_phone;
  char *profession;
  char *radio_phone;
  int32_t  rich_text;
  char *spouse_name;
  char *suffix;
  char *surname;
  char *telex;
  char *transmittable_display_name;
  char *ttytdd_phone;
  FILETIME *wedding_anniversary;
} pst_item_contact;

typedef struct _pst_desc_tree {
  u_int32_t id;
  pst_index_ll * list_index;
  pst_index_ll * desc;
  int32_t no_child;
  struct _pst_desc_tree * prev;
  struct _pst_desc_tree * next;
  struct _pst_desc_tree * parent;
  struct _pst_desc_tree * child;
  struct _pst_desc_tree * child_tail;
} pst_desc_ll;

typedef struct _pst_file {
  pst_index_ll *i_head, *i_tail;
  pst_index2_ll *i2_head;
  pst_desc_ll *d_head, *d_tail;
  pst_x_attrib_ll *x_head;
  int32_t index1;
  int32_t index1_count;
  int32_t index2;
  int32_t index2_count;
  FILE * fp;
  size_t size;
  unsigned char index1_depth;
  unsigned char index2_depth;
  unsigned char encryption;
  unsigned char id_depth_ok;
  unsigned char desc_depth_ok;
  unsigned char ind_type;
} pst_file;

typedef struct _pst_item {
  struct _pst_item_email *email; // data reffering to email
  struct _pst_item_folder *folder; // data reffering to folder
  struct _pst_item_contact *contact; // data reffering to contact
  struct _pst_item_attach *attach; // linked list of attachments
  struct _pst_item_attach *current_attach; // pointer to current attachment
  struct _pst_item_message_store * message_store; // data referring to the message store
  struct _pst_item_extra_field *extra_fields; // linked list of extra headers and such
  struct _pst_item_journal *journal; // data reffering to a journal entry
  struct _pst_item_appointment *appointment; // data reffering to a calendar entry
  int32_t type;
  char *ascii_type;
  char *file_as;
  char *comment;
  int32_t  message_size;
  char *outlook_version;
  char *record_key; // probably 16 bytes long.
  size_t record_key_size;
  int32_t  response_requested;
  FILETIME *create_date;
  FILETIME *modify_date;
  int32_t private;
} pst_item;


%extend pst_file {
	pst_file() {
		return (pst_file *) malloc(sizeof(pst_file));
	}
	~pst_file() {
		free(self);
	}
	int open(char *fname) {
		return pst_open(self, fname, "r");
	}
	int close() {
		return pst_close(self);
	}
	int load_index() {
		return pst_load_index(self);
	}
	int load_extended_attributes() {
		return pst_load_extended_attributes(self);
	}
	pst_item *get_item(pst_desc_ll *d_ptr) {
		return _pst_parse_item(self, d_ptr);
	}
	pst_desc_ll *getTopOfFolders(pst_item *item) {
		return pst_getTopOfFolders(self, item);
	}
	pst_desc_ll *get_ptr(u_int32_t id) {
		return _pst_getDptr(self, id);
	}
}

%extend pst_item {
	void free() {
		free(self);
	}
}
