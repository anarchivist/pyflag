/*
** fs_data
** The Sleuth Kit 
**
** $Date: 2007/12/20 20:32:38 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file fs_data.c
 * Functions to allocate and add structures to maintain generic file
 * system attributes and run lists.  Currently used only for NTFS, but
 * could be expanded to other file systems in the future.
 */

/*
 * The TSK_FS_DATA structure is motivated by NTFS.  NTFS (and others) allow
 * one to have more than one data area per file.  Furthermore, there is
 * more than one way to store the data (resident in the MFT entry or
 * in the Data Area runs).  To handle this in 
 * a generic format, the TSK_FS_DATA structure was created.  
 *
 * TSK_FS_DATA structures have a type and id that describe it and then
 * a flag identifies it as a resident stream or a non-resident run
 * They form a linked list and are added to the TSK_FS_INODE structure
 */
#include "tsk_fs_i.h"
#include "tsk_ntfs.h"

/** 
 * Allocates and initializes a new structure.  
 *
 * @param type The type of attribute to create (Resident or Non-resident)
 * @returns NULL on error
 */
TSK_FS_DATA *
tsk_fs_data_alloc(TSK_FS_DATA_FLAG_ENUM type)
{
    TSK_FS_DATA *fs_data = (TSK_FS_DATA *) tsk_malloc(sizeof(TSK_FS_DATA));
    if (fs_data == NULL) {
        return NULL;
    }
    fs_data->nsize = 128;
    if ((fs_data->name = (char *) tsk_malloc(fs_data->nsize)) == NULL) {
        free(fs_data);
        return NULL;
    }

    fs_data->size = 0;
    fs_data->flags = 0;
    fs_data->run = NULL;
    fs_data->run_end = NULL;
    fs_data->type = 0;
    fs_data->next = NULL;
    fs_data->compsize = 0;

    if (type == TSK_FS_DATA_NONRES) {
        fs_data->buflen = 0;
        fs_data->buf = NULL;
        fs_data->flags = (TSK_FS_DATA_NONRES | TSK_FS_DATA_INUSE);
    }
    else if (type == TSK_FS_DATA_RES) {
        fs_data->buflen = 1024;
        fs_data->buf = (uint8_t *) tsk_malloc(fs_data->buflen);
        if (fs_data->buf == NULL) {
            free(fs_data->name);
            return NULL;
        }
        fs_data->flags = (TSK_FS_DATA_RES | TSK_FS_DATA_INUSE);
    }
    else {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "tsk_fs_data_alloc: Invalid Type: %d\n", type);
        return NULL;
    }

    return fs_data;
}


/**
 * Allocate a run list entry.
 *
 * @returns NULL on error
 */
TSK_FS_DATA_RUN *
tsk_fs_data_run_alloc()
{
    TSK_FS_DATA_RUN *fs_data_run =
        (TSK_FS_DATA_RUN *) tsk_malloc(sizeof(TSK_FS_DATA_RUN));
    if (fs_data_run == NULL)
        return NULL;

    memset(fs_data_run, 0, sizeof(TSK_FS_DATA_RUN));
    return fs_data_run;
}


/**
 * Free a list of data_runs
 *
 * @param fs_data_run Head of list to free
 */
void
tsk_fs_data_run_free(TSK_FS_DATA_RUN * fs_data_run)
{
    TSK_FS_DATA_RUN *fs_data_run_prev;
    while (fs_data_run) {
        fs_data_run_prev = fs_data_run;
        fs_data_run = fs_data_run->next;
        fs_data_run_prev->next = NULL;
        free(fs_data_run_prev);
    }
}

/**
 * Free the list of TSK_FS_DATA structures and the runs that
 * they allocated.
 *
 * @param fs_data_head List of structures to free.
 */
void
tsk_fs_data_free(TSK_FS_DATA * fs_data_head)
{
    TSK_FS_DATA *fs_data_tmp;

    while (fs_data_head) {
        fs_data_tmp = fs_data_head->next;

        fs_data_head->next = NULL;

        if (fs_data_head->run)
            tsk_fs_data_run_free(fs_data_head->run);
        fs_data_head->run = NULL;

        if (fs_data_head->buf)
            free(fs_data_head->buf);
        fs_data_head->buf = NULL;

        if (fs_data_head->name)
            free(fs_data_head->name);
        fs_data_head->name = NULL;

        free(fs_data_head);

        fs_data_head = fs_data_tmp;
    }
}

/**
 * Clear the fields and run_lists in the FS_DATA list.
 *
 * @param fs_data_head List of attributes to clear
 */
void
tsk_fs_data_clear_list(TSK_FS_DATA * fs_data_head)
{
    while (fs_data_head) {
        fs_data_head->size = fs_data_head->type = fs_data_head->id =
            fs_data_head->flags = 0;
        if (fs_data_head->run) {
            tsk_fs_data_run_free(fs_data_head->run);
            fs_data_head->run = NULL;
            fs_data_head->run_end = NULL;
            fs_data_head->allocsize = 0;
        }
        fs_data_head = fs_data_head->next;
    }
}

/** 
 * Given the begining of the list, return either an empty element
 * in the list or a new one at the end
 *
 * Preference is given to finding one of the same type to prevent
 * excessive malloc's, but if one is not found then a different
 * type is used: type = [TSK_FS_DATA_NONRES | TSK_FS_DATA_RES]
 *
 * @param fs_data_head Head of attribute list to search
 * @param type Preference for attribute type to reuse
 * @return NULL on error or attribute in list to use
 */
TSK_FS_DATA *
tsk_fs_data_getnew_attr(TSK_FS_DATA * fs_data_head,
    TSK_FS_DATA_FLAG_ENUM type)
{
    TSK_FS_DATA *fs_data_tmp = NULL, *fs_data = fs_data_head;

    if ((type != TSK_FS_DATA_NONRES) && (type != TSK_FS_DATA_RES)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Invalid Type in tsk_fs_data_getnew_attr()");
        return NULL;
    }

    while (fs_data) {
        if (fs_data->flags == 0) {
            if (type == TSK_FS_DATA_NONRES) {
                if (fs_data->run)
                    break;
                else if (!fs_data_tmp)
                    fs_data_tmp = fs_data;
            }
            /* we want one with an allocated buf */
            else {
                if (fs_data->buflen)
                    break;
                else if (!fs_data_tmp)
                    fs_data_tmp = fs_data;
            }
        }
        fs_data = fs_data->next;
    }

    /* if we fell out then check fs_data_tmp */
    if (!fs_data) {
        if (fs_data_tmp)
            fs_data = fs_data_tmp;
        else {
            /* make a new one */
            if ((fs_data = tsk_fs_data_alloc(type)) == NULL)
                return NULL;

            /* find the end of the list to add this to */
            fs_data_tmp = fs_data_head;
            while ((fs_data_tmp) && (fs_data_tmp->next))
                fs_data_tmp = fs_data_tmp->next;

            if (fs_data_tmp)
                fs_data_tmp->next = fs_data;
        }
    }

    fs_data->flags = (TSK_FS_DATA_INUSE | type);
    return fs_data;
}

/**
 * Search the list of TSK_FS_DATA structures for an entry with a given 
 * type and id.  
 *
 * @param fs_data_head Head of fs_data list to search
 * @param type Type of attribute to find
 * @param id Id of attribute to find.  If 0, then the lowest id of the
 * given type is returned. 
 *
 * @return NULL is returned on error and if an entry could not be found.
 * tsk_errno will be set to 0 if entry could not be found and it will be
 * non-zero if an error occured.
 */
TSK_FS_DATA *
tsk_fs_data_lookup(TSK_FS_DATA * fs_data_head, uint32_t type, uint16_t id)
{
    TSK_FS_DATA *fs_data = fs_data_head;

    if (!fs_data_head) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "tsk_fs_data_lookup: Null head pointer");
        tsk_errstr2[0] = '\0';
        return NULL;
    }

    while (fs_data) {
        if ((fs_data->flags & TSK_FS_DATA_INUSE) &&
            (fs_data->type == type) && (fs_data->id == id))
            break;

        fs_data = fs_data->next;
    }

    if ((!fs_data) || (fs_data->type != type) || (fs_data->id != id)) {
        return NULL;
    }

    return fs_data;
}

/**
 * Search the list of TSK_FS_DATA structures for an entry with a given 
 * type (and ANY id).  The attribute with the lowest id (or the named
 * $Data attribute if that type is specified) is returned. 
 *
 * @param fs_data_head Head of fs_data list to search
 * @param type Type of attribute to find
 *
 * @return NULL is returned on error and if an entry could not be found.
 * tsk_errno will be set to 0 if entry could not be found and it will be
 * non-zero if an error occured.
 */
TSK_FS_DATA *
tsk_fs_data_lookup_noid(TSK_FS_DATA * fs_data_head, uint32_t type)
{
    TSK_FS_DATA *fs_data = fs_data_head;
    TSK_FS_DATA *fs_data_ret = NULL;

    if (!fs_data_head) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "tsk_fs_data_lookup_noid: NULL head pointer");
        return NULL;
    }

    /* If no id was given, then we will return the entry with the
     * lowest id of the given type (if more than one exists) 
     */

    while (fs_data) {
        if ((fs_data->flags & TSK_FS_DATA_INUSE)
            && (fs_data->type == type)) {

            /* replace existing if new is lower */
            if ((!fs_data_ret) || (fs_data_ret->id > fs_data->id))
                fs_data_ret = fs_data;

            /* If we are looking for NTFS $Data, 
             * then return default when we see it */
            if ((fs_data->type == NTFS_ATYPE_DATA) &&
                (fs_data->nsize > 5) &&
                (strncmp(fs_data->name, "$Data", 5) == 0)) {
                fs_data_ret = fs_data;
                break;
            }
        }
        fs_data = fs_data->next;
    }
    return fs_data_ret;
}



/**
 * Add a name to an existing FS_DATA structure.  Will reallocate
 * space for the name if needed.
 *
 * @param fs_data Structure to add name to
 * @param name UTF-8 name to add
 *
 * @return 1 on error and 0 on success
 */
static uint8_t
fs_data_put_name(TSK_FS_DATA * fs_data, const char *name)
{
    if (fs_data->nsize < (strlen(name) + 1)) {
        fs_data->name = tsk_realloc(fs_data->name, strlen(name) + 1);
        if (fs_data->name == NULL)
            return 1;
        fs_data->nsize = strlen(name) + 1;
    }
    strncpy(fs_data->name, name, fs_data->nsize);
    return 0;
}

/**
 * Copy resident data to an attribute in the list. If no attributes
 * exist yet, one will be created and the head of the resulting list 
 * will be returned. 
 *
 * @param fs_data_head Head of the attribute list (or NULL if empty)
 * @param name Name of the attribute to add
 * @param type Type of the attribute to add
 * @param id Id of the attribute to add
 * @param res_data Pointer to where resident data is located (data will
 * be copied from here into FS_DATA)
 * @param len Length of resident data
 * @return NULL on error or head of attribute list
 */
TSK_FS_DATA *
tsk_fs_data_put_str(TSK_FS_DATA * fs_data_head, const char *name, uint32_t type,
    uint16_t id, void *res_data, unsigned int len)
{
    TSK_FS_DATA *fs_data;

    /* get a new attribute entry in the list */
    if ((fs_data =
            tsk_fs_data_getnew_attr(fs_data_head,
                TSK_FS_DATA_RES)) == NULL)
        return NULL;

    /* if the head of the list is null, then set it now */
    if (!fs_data_head)
        fs_data_head = fs_data;


    fs_data->flags = (TSK_FS_DATA_INUSE | TSK_FS_DATA_RES);
    fs_data->type = type;
    fs_data->id = id;
    fs_data->compsize = 0;

    if (fs_data_put_name(fs_data, name)) {
        return NULL;
    }

    if (fs_data->buflen < len) {
        fs_data->buf = (uint8_t *) tsk_realloc((char *) fs_data->buf, len);
        if (fs_data->buf == NULL)
            return NULL;
        fs_data->buflen = len;
    }

    memset(fs_data->buf, 0, fs_data->buflen);
    memcpy(fs_data->buf, res_data, len);
    fs_data->size = len;

    return fs_data_head;
}


/**
 * Add a set of consecutive runs of an attribute of a specified type 
 * and id.
 * This function first determines if the attribute exists and then
 * either creates the attribute or adds to it. 
 * This is complicated because we could get the runs out of order
 * so we use "filler" TSK_FS_DATA_RUN structures during the process
 *
 * @param fs_data_head The head of the list of attributes (or NULL if list is empty)
 * @param runlen The total number of clusters in this set of runs.
 * @param data_run_new The set of runs to add.   This can be NULL only if it is the only run in the attribute.  We use this special case for $Bad, but it should change.
 * @param name Name of the attribute (in case it needs to be created)
 * @param type Type of attribute to add run to
 * @param id Id of attribute to add run to
 * @param size Total size of the attribute (in case it needs to be created)
 * @param flags Flags about compression, sparse etc. of data
 * @param compsize Compression unit size (in case it needs to be created)
 *
 * @returns The head of the list or NULL on error
 */
TSK_FS_DATA *
tsk_fs_data_put_run(TSK_FS_DATA * fs_data_head,
    TSK_OFF_T runlen, TSK_FS_DATA_RUN * data_run_new,
    const char *name, uint32_t type, uint16_t id, TSK_OFF_T size,
    TSK_FS_DATA_FLAG_ENUM flags, uint32_t compsize)
{
    TSK_FS_DATA *fs_data = NULL;
    TSK_FS_DATA_RUN *data_run_cur, *data_run_prev;

    tsk_error_reset();

    /* First thing is to find the existing data attribute */
    fs_data = NULL;
    if (fs_data_head)
        fs_data = tsk_fs_data_lookup(fs_data_head, type, id);

    /* one does not already exist, so get a new one */
    if (fs_data == NULL) {

        /* tsk_fs_data_lookup returns NULL both on error and if it can't find 
         * the attribute, so check errno */
        if (tsk_errno != 0)
            return NULL;

        /* get a new attribute entry in the list */
        if ((fs_data =
                tsk_fs_data_getnew_attr(fs_data_head,
                    TSK_FS_DATA_NONRES)) == NULL)
            return NULL;


        /* if the head of the list is null, then set it now */
        if (!fs_data_head)
            fs_data_head = fs_data;

        fs_data->flags = (TSK_FS_DATA_INUSE | TSK_FS_DATA_NONRES | flags);
        fs_data->type = type;
        fs_data->id = id;
        fs_data->size = size;
        fs_data->compsize = compsize;

        if (fs_data_put_name(fs_data, name)) {
            return NULL;
        }


        /* Add the data_run_new to the attribute. */

        /* We support the ODD case where the run is NULL.  In this case, 
         * we set the attribute size info, but set everything else to NULL.
         */
        if (data_run_new == NULL) {
            fs_data->allocsize = runlen;
            fs_data->run = NULL;
            fs_data->run_end = NULL;
            return fs_data_head;
        }

        /*
         * If this is not in the begining, then we need to make a filler 
         * to account for the cluster numbers we haven't seen yet
         *
         * This commonly happens when we process an MFT entry that
         * is not a base entry and it is referenced in an $ATTR_LIST
         *
         * The $DATA attribute in the non-base have a non-zero
         * data_run_new->offset.  
         */
        if (data_run_new->offset != 0) {
            TSK_FS_DATA_RUN *fill_run = tsk_fs_data_run_alloc();
            fill_run->flags = TSK_FS_DATA_RUN_FLAG_FILLER;
            fill_run->offset = 0;
            fill_run->addr = 0;
            fill_run->len = data_run_new->offset;
            fill_run->next = data_run_new;
            data_run_new = fill_run;
        }

        fs_data->allocsize = runlen;
        fs_data->run = data_run_new;

        // update the pointer to the end of the list
        fs_data->run_end = data_run_new;
        while (fs_data->run_end->next)
            fs_data->run_end = fs_data->run_end->next;

        return fs_data_head;
    }

    // we only support the case of a null run if it is the only run...
    if (data_run_new == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "tsk_fs_data_put_run: Error, NULL run added to existing attribute");
        return NULL;
    }

    /* 
     * An attribute of this type and id already exist, 
     * so we will either add to 
     * the end of it or replace a filler object with real data
     */

    /* First thing, is to check if we can just add it to the end */
    if ((fs_data->run_end)
        && (fs_data->run_end->offset + fs_data->run_end->len ==
            data_run_new->offset)) {
        fs_data->run_end->next = data_run_new;
        fs_data->allocsize += runlen;

        // update the pointer to the end of the list
        while (fs_data->run_end->next)
            fs_data->run_end = fs_data->run_end->next;

        /* return head of fs_data list */
        return fs_data_head;
    }

    data_run_cur = fs_data->run;
    data_run_prev = NULL;
    while (data_run_cur) {

        /* Do we replace this filler spot? */
        if (data_run_cur->flags & TSK_FS_DATA_RUN_FLAG_FILLER) {

            /* This should never happen because we always add 
             * the filler to start from VCN 0 */
            if (data_run_cur->offset > data_run_new->offset) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_ARG;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "tsk_fs_data_put_run: could not add data_run");
                return NULL;
            }

            /* Check if the new run starts inside of this filler. */
            if (data_run_cur->offset + data_run_cur->len >
                data_run_new->offset) {
                TSK_FS_DATA_RUN *endrun;

                /* if the new starts at the same as the filler, 
                 * replace the pointer */
                if (data_run_cur->offset == data_run_new->offset) {
                    if (data_run_prev)
                        data_run_prev->next = data_run_new;
                    else
                        fs_data->run = data_run_new;
                }

                /* The new run does not start at the begining of
                 * the filler, so make a new start filler
                 */
                else {
                    TSK_FS_DATA_RUN *newfill = tsk_fs_data_run_alloc();
                    if (newfill == NULL)
                        return NULL;

                    if (data_run_prev)
                        data_run_prev->next = newfill;
                    else
                        fs_data->run = newfill;

                    newfill->next = data_run_new;
                    newfill->len =
                        data_run_new->offset - data_run_cur->offset;
                    newfill->offset = data_run_cur->offset;
                    newfill->flags = TSK_FS_DATA_RUN_FLAG_FILLER;

                    data_run_cur->len -= newfill->len;
                }

                /* get to the end of the run that we are trying to add */
                endrun = data_run_new;
                while (endrun->next)
                    endrun = endrun->next;

                /* if the filler is the same size as the
                 * new one, replace it 
                 */
                if (runlen == data_run_cur->len) {
                    endrun->next = data_run_cur->next;

                    // update the pointer to the end of the list
                    if (endrun->next == NULL)
                        fs_data->run_end = endrun;

                    free(data_run_cur);
                }
                /* else adjust the last filler entry */
                else {
                    endrun->next = data_run_cur;
                    data_run_cur->len -= runlen;
                }

                return fs_data_head;
            }
        }

        data_run_prev = data_run_cur;
        data_run_cur = data_run_cur->next;
    }


    /* 
     * There is no filler holding the location of this run, so
     * we will add it to the end of the list 
     * 
     * we got here because it did not fit in the current list or
     * because the current list is NULL
     *
     * At this point data_run_prev is the end of the existing list or
     * 0 if there is no list
     */

    /* this is an error condition.  
     * it means that we are currently at a greater VCN than
     * what we are inserting, but we never found the filler
     * for where we were to insert
     */
    if ((data_run_prev)
        && (data_run_prev->offset + data_run_prev->len >
            data_run_new->offset)) {

        /* MAYBE this is because of a duplicate entry .. */
        if ((data_run_prev->addr == data_run_new->addr) &&
            (data_run_prev->len == data_run_new->len)) {
            tsk_fs_data_run_free(data_run_new);
            return fs_data_head;
        }

        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fs_data_run: error adding aditional run: %" PRIuDADDR
            ", Previous %" PRIuDADDR " -> %" PRIuDADDR "   Current %"
            PRIuDADDR " -> %" PRIuDADDR "\n", data_run_new->offset,
            data_run_prev->addr, data_run_prev->len, data_run_new->addr,
            data_run_new->len);
        return NULL;
    }

    /* we should add it right here */
    else if (((data_run_prev)
            && (data_run_prev->offset + data_run_prev->len ==
                data_run_new->offset)) || (data_run_new->offset == 0)) {
        if (data_run_prev)
            data_run_prev->next = data_run_new;
        else
            fs_data->run = data_run_new;
    }
    /* we need to make a filler before it */
    else {
        TSK_FS_DATA_RUN *tmprun = tsk_fs_data_run_alloc();
        if (tmprun == NULL)
            return NULL;

        if (data_run_prev) {
            data_run_prev->next = tmprun;
            tmprun->offset = data_run_prev->offset + data_run_prev->len;
        }
        else {
            fs_data->run = tmprun;
        }

        tmprun->len = data_run_new->offset - tmprun->offset;
        tmprun->flags = TSK_FS_DATA_RUN_FLAG_FILLER;
        tmprun->next = data_run_new;
    }

    /* Adjust the length of the TSK_FS_DATA structure to reflect the 
     * new run
     */
    fs_data->allocsize += runlen;

    // update the pointer to the end of the list
    fs_data->run_end = data_run_new;
    while (fs_data->run_end->next)
        fs_data->run_end = fs_data->run_end->next;

    /* return head of fs_data list */
    return fs_data_head;
}
