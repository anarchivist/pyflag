/*
** fs_data
** The  Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
*/

/*
 * The FS_DATA structure is motivated by NTFS.  NTFS (and others) allow
 * one to have more than one data area per file.  Furthermore, there is
 * more than one way to store the data (resident in the MFT entry or
 * in the Data Area runs).  To handle this in 
 * a generic format, the FS_DATA structure was created.  
 *
 * FS_DATA structures have a type and id that describe it and then
 * a flag identifies it as a resident stream or a non-resident run
 * They form a linked list and are added to the FS_INODE structure
 */
#include "fs_tools.h"
#include "mymalloc.h"
#include "error.h"

/* 
 * Allocates and initializes a new structure.  
 * Specify which type (RES or NON_RES) for autmatic allocation, 
 * else if 0 is specified then a generic one is made
 */
FS_DATA *
fs_data_alloc(u_int8_t type)
{
	FS_DATA *data = (FS_DATA *) mymalloc(sizeof(FS_DATA));
	data->nsize = 128;
	data->name = (char *)mymalloc(data->nsize);

	data->size = 0;
	data->flags = 0;
	data->run = NULL;
	data->type = 0;
	data->next = NULL;

	if (type == FS_DATA_NONRES) {
		data->buflen = 0;
		data->buf = NULL;
		data->flags = (FS_DATA_NONRES | FS_DATA_INUSE);
	}
	else if (type == FS_DATA_RES) {
		data->buflen = 1024;
		data->buf = (u_int8_t *)mymalloc(data->buflen);
		data->flags = (FS_DATA_RES | FS_DATA_INUSE);
	}
	else {
		error ("fs_data_alloc: Invalid Type: %d\n", type);
	}

	return data;
}


FS_DATA_RUN *
fs_data_run_alloc ()
{
	FS_DATA_RUN *fs_data_run = 
	  (FS_DATA_RUN *)mymalloc(sizeof(FS_DATA_RUN));
	memset (fs_data_run, 0, sizeof(FS_DATA_RUN));	
	return fs_data_run;
}


/* Free a data_run list */
void
fs_data_run_free (FS_DATA_RUN *run)
{
	FS_DATA_RUN *run_prev;
	while (run) {
		run_prev = run;
		run = run->next;
		run_prev->next = NULL;
		free(run_prev);
	}
}

/* Free the FS_DATA structure */
void
fs_data_free (FS_DATA *fs_data)
{
	FS_DATA *tmp_data;

	while (fs_data) {
		tmp_data = fs_data->next;

		fs_data->next = NULL;

		if (fs_data->run) 
			fs_data_run_free(fs_data->run);
		fs_data->run = NULL;

		if (fs_data->buf)
			free(fs_data->buf);
		fs_data->buf = NULL;

		if (fs_data->name)
			free(fs_data->name);
		fs_data->name = NULL;

		free (fs_data);

		fs_data = tmp_data;
	}
}

/*
 * follow the linked list and clear the flag each time
 * to reset them
 */
void
fs_data_clear_list(FS_DATA *data)
{
	while (data) {
		data->flags = data->size = data->type = data->id = 0;
		if (data->run) {
			fs_data_run_free(data->run);
			data->run = NULL;
			data->runlen = 0;
		}
		data = data->next;
	}
}

/* 
 * Given the begining of the list, return either an empty element
 * in the list or a new one at the end
 *
 * Preference is given to finding one of the same type to prevent
 * excessive malloc's, but if one is not found then a different
 * type is used: type = [FS_DATA_NONRES | FS_DATA_RES]
 */
FS_DATA *
fs_data_getnew_attr(FS_DATA *begin, u_int8_t type)
{
	FS_DATA *temp = NULL, *data = begin;

	if ((type != FS_DATA_NONRES) && (type != FS_DATA_RES))
		error ("Invalid Type in fs_data_getnew_attr()");

	while (data) {
		if (data->flags == 0) {
			if (type == FS_DATA_NONRES) {
				if (data->run)
					break;
				else if (!temp)
					temp = data;
			}
			/* we want one with an allocated buf */
			else {
				if (data->buflen)
					break;
				else if (!temp)
					temp = data;
			}
		}
		data = data->next;
	}

	/* if we fell out then check temp */
	if (!data) {
		if (temp) 
			data = temp;
		else  {
			/* make a new one */
			data = fs_data_alloc(type);

			/* find the end of the list to add this to */
			temp = begin;
			while ((temp) && (temp->next)) 
				temp = temp->next;
			
			if (temp)
				temp->next = data;
		}
	}

	data->flags = (FS_DATA_INUSE | type);
	return data;
}


/*
 * Search the list of FS_DATA structures for an entry with the same
 * type and id.  If _id_ is 0, then the lowest id of the given type
 * is returned
 *
 * if the entry is not found, NULL is returned
 *
 */
FS_DATA *
fs_data_lookup(FS_DATA *data_head, u_int32_t type, u_int16_t id)
{
	FS_DATA *fs_data = data_head;

	if (!data_head)
		return NULL;

    if (id != 0) {
        while ((fs_data) && (fs_data->flags & FS_DATA_INUSE) &&
          ((fs_data->type != type) || (fs_data->id != id)))
            fs_data = fs_data->next;

        if ((!fs_data) || (fs_data->type != type) || (fs_data->id != id))
			return NULL;
    }
    else {
		/* If no id was given, then we will return the entry with the
		 * lowest id of the given type (if more than one exists) 
		 */
		FS_DATA *fs_data_ret = NULL;
	
        while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {
        	if (fs_data->type == type) {
				if ((!fs_data_ret) || (fs_data_ret->id > fs_data->id))
					fs_data_ret = fs_data;
			}
            fs_data = fs_data->next;
		}

		/* fs_data_ret is either NULL or the lowest id of the type */
		fs_data = fs_data_ret;
    }

	return fs_data;
}



/* Add _name_ to the FS_DATA structure 
 *
 * Handles the size reallocation if needed
 */
static void
fs_data_put_name(FS_DATA *data, char *name)
{
    if (data->nsize < (strlen(name) + 1)) {
        data->name = myrealloc(data->name, strlen(name)+1);
        data->nsize = strlen(name)+1;
    }   
    strncpy(data->name, name, data->nsize);
}

/*
 * put the resident data at "addr" which has size len into the
 * data_head list.  if _data_head_ is NULL, a new list will be started
 *
 * the head of the list is returned
 */
FS_DATA *
fs_data_put_str(FS_DATA *data_head, char *name, u_int32_t type, u_int16_t id,
  DADDR_T *addr, int len)
{

	FS_DATA *data;

	/* get a new attribute entry in the list */
	data = fs_data_getnew_attr(data_head, FS_DATA_RES);

	/* if the head of the list is null, then set it now */
	if (!data_head)
		data_head = data;


	data->flags = (FS_DATA_INUSE | FS_DATA_RES);
	data->type = type;
	data->id = id;

	fs_data_put_name(data, name);
    
    if (data->buflen < len) {
        data->buf = (u_int8_t *)myrealloc((char *)data->buf, len);
        data->buflen = len;
    }
	memset(data->buf, 0, data->buflen);
    memcpy(data->buf, addr, len);
	data->size = len;

	return data_head;
}


/*
 * Add a data_run of the specified type and id to the data_head list.
 * If a list head does not exist yet, a new one will be created.  The
 * list head is returned.
 *
 * This is complicated because we could get the runs out of order
 * so we use "filler" FS_DATA_RUN structures during the process
 *
 * start_vcn: The virtual cluster number of this run in the file
 * runlen: length of this run
 * run: the structure to add to the list
 * name: name of the attribute
 * type & id: The Type and id of the attribute
 * size: total size of the attribute
 */
FS_DATA *
fs_data_put_run(FS_DATA *data_head, 
    u_int64_t start_vcn, u_int64_t runlen, FS_DATA_RUN *run,
    char *name, u_int32_t type, u_int16_t id, u_int64_t size, u_int8_t flags)
{
	FS_DATA *data;
	FS_DATA_RUN *data_run, *data_run_prev;
	int cur_vcn = 0;

	/* First thing is to find the existing data attribute */
	data = fs_data_lookup(data_head, type, id);

	/* one does not already exist, so get a new one */
	if (!data) {
		/* get a new attribute entry in the list */
		data = fs_data_getnew_attr(data_head, FS_DATA_NONRES);


		/* if the head of the list is null, then set it now */
		if (!data_head)
			data_head = data;

		data->flags = (FS_DATA_INUSE | FS_DATA_NONRES | flags);
		data->type = type;
		data->id = id;
		data->size = size;

		fs_data_put_name(data, name);


		/* if this is not in the begining, then we need to make a filler 
		 * to account for the cluster numbers we haven't seen yet
		 *
		 * This commonly happens when we process an MFT entry tha
		 * is not a base entry and it is referenced in an $ATTR_LIST
		 *
		 * The $DATA attribute in the non-base have a non-zero
		 * start_vcn.  
		 */
		if (start_vcn != 0) {
			FS_DATA_RUN *fill = fs_data_run_alloc();
			fill->flags = FS_DATA_FILLER;
			fill->addr = 0;
			fill->len = start_vcn; 
			fill->next = run;
			run = fill;
		}

		data->runlen = runlen;
		data->run = run;

		return data_head;
	}

	/* 
	 * The data type and id already exist, so we will either add to 
	 * the end of it or replace a filler object with real data
	 */

	data_run = data->run;
	data_run_prev = NULL;

	while (data_run) {

		/* Do we replace this filler spot? */
		if (data_run->flags & FS_DATA_FILLER) {

			/* This should never happen because we always add 
			 * the filler to start from VCN 0
			 */
			if (cur_vcn > start_vcn) 
				error ("could not add data_run");

			/* The current filler ends after where we need to 
			 * start, so it will be added here 
			 */
			if (cur_vcn + data_run->len > start_vcn) {
				FS_DATA_RUN *endrun;

				/* if the new starts at the same as the filler, 
				 * replace the pointer */
				if (cur_vcn == start_vcn) {
					if (data_run_prev)
						data_run_prev->next = run;
					else 
						data->run = run;
				}
				/* The new run does not start at the begining of
				 * the filler, so make a new start filler
				 */
				else {
					FS_DATA_RUN *newfill = fs_data_run_alloc();
				
					if (data_run_prev)
						data_run_prev->next = newfill;
					else 
						data->run = newfill;

					newfill->next = run;
					newfill->len = start_vcn - cur_vcn;
					newfill->flags = FS_DATA_FILLER;

					data_run->len -= newfill->len;
				}

				/* get to the end of the run that we are trying
				 * to insert
				 */
				endrun = run;
				while (endrun->next) 
					endrun = endrun->next;

				/* if the filler is the same size as the
				 * new one, replace it 
				 */
				if (runlen == data_run->len) {
					endrun->next = data_run->next;
					free(data_run);
				}
				/* else adjust the last filler entry */
				else {
					endrun->next = data_run;
					data_run->len -= runlen;
				}
	
				return data_head;

			} /* end of replacing a filler */

		} /* end of if filler */

		cur_vcn += data_run->len;
		data_run_prev = data_run;
		data_run = data_run->next;

	} /* end of loop */



	/* 
	 * There is no filler holding the location of this run, so
	 * we will add it to the end of the list 
	 * 
	 * we got here because it did not fit in the current list or
	 * because the current list is NULL
	 *
	 * At this point cur_vcn is the end of the existing list of
	 * 0 if there is no list
	 */

	/* this is an error condition.  
	 * it means that we are currently at a greater VCN than
	 * what we are inserting, but we never found the filler
	 * for where we were to insert
	 */
	if (cur_vcn > start_vcn) {

		/* MAYBE this is because of a duplicate entry .. */
		if ((data_run_prev) && 
		  (data_run_prev->addr == run->addr) && 
		  (data_run_prev->len == run->len)) {
			fs_data_run_free (run);
			return data_head;
		}

		printf("Previous %d -> %d   Current %d -> %d\n",
		  (int)data_run_prev->addr, (int)data_run_prev->len, (int)run->addr, (int)run->len);
		error ("fs_data_put_run: error adding additional run: %d", start_vcn);
	}

	/* we should add it right here */
	else if (cur_vcn == start_vcn) {
		if (data_run_prev)
			data_run_prev->next = run;
		else
			data->run = run;
	}
	/* we need to make a filler before it */
	else  {
		FS_DATA_RUN *tmprun = fs_data_run_alloc();
		if (data_run_prev)
			data_run_prev->next = tmprun;
		else
			data->run = tmprun;
		tmprun->len = start_vcn - cur_vcn;
		tmprun->flags = FS_DATA_FILLER;
		tmprun->next = run;
	}

	/* Adjust the length of the FS_DATA structure to reflect the 
	 * new run
	 */
	data->runlen += runlen;

	/* return head of fs_data list */
	return data_head;
}

