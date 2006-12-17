/*
 * The Sleuth Kit
 *
 * $Date: 2006/12/05 21:39:52 $
 */
#include <stdlib.h>
#include <stdio.h>
#include "aux_tools.h"

/*
 * tsk_lists are a linked list of buckets that store a key in 
 * REVERSE sorted order
 */

/* 
 * does not add duplicates
 *
 * returns 1 on error
 * result is in REVERSE sorted order
 */

static TSK_LIST *
tsk_list_create(uint64_t key)
{
    TSK_LIST *ent;
    if ((ent = (TSK_LIST *) mymalloc(sizeof(TSK_LIST))) == NULL) {
	return NULL;
    }

    ent->key = key;
    ent->next = NULL;
    ent->len = 1;

    return ent;
}

uint8_t
tsk_list_add(TSK_LIST ** list, uint64_t key)
{
    TSK_LIST *tmp;

    /* If the head is NULL, then create an entry */
    if (*list == NULL) {
	TSK_LIST *ent;
	if (verbose)
	    fprintf(stderr, "entry %" PRIu64 " is first on list\n", key);
	if ((ent = tsk_list_create(key)) == NULL)
	    return 1;

	*list = ent;
	return 0;
    }

    /* If the new key is larger than the head, make it the head */
    if (key > (*list)->key) {
	if (verbose)
	    fprintf(stderr,
		"entry %" PRIu64 " added to head before %" PRIu64 "\n",
		key, (*list)->key);

	// If we can, update the length of the existing list entry
	if (key == (*list)->key + 1) {
	    (*list)->key++;
	    (*list)->len++;
	}
	else {
	    TSK_LIST *ent;
	    if ((ent = tsk_list_create(key)) == NULL)
		return 1;
	    ent->next = *list;
	    *list = ent;
	}
	return 0;
    }
    // get rid of duplicates
    else if (key == (*list)->key) {
	return 0;
    }

    /* At the start of this loop each time, we know that the key to add 
     * is smaller than the entry being considered (tmp) */
    tmp = *list;
    while (tmp != NULL) {

	/* First check if this is a duplicate and contained in tmp */
	if (key > (tmp->key - tmp->len)) {
	    return 0;
	}
	/* Can we append it to the end of tmp? */
	else if (key == (tmp->key - tmp->len)) {
	    // do a sanity check on the next entry
	    if ((tmp->next) && (tmp->next->key == key)) {
		// @@@ We could fix this situation and remove the next entry...
		return 0;
	    }
	    tmp->len++;
	    return 0;
	}

	/* The key is less than the current bucket and can't be added to it.
	 * check if we are at the end of the list yet */
	else if (tmp->next == NULL) {
	    TSK_LIST *ent;

	    if (verbose)
		fprintf(stderr, "entry %" PRIu64 " added to tail\n", key);

	    if ((ent = tsk_list_create(key)) == NULL)
		return 1;
	    tmp->next = ent;

	    return 0;
	}
	// can we prepend it to the next bucket?
	else if (key == tmp->next->key + 1) {
	    tmp->next->key++;
	    tmp->next->len++;
	}
	// do we need a new bucket in between?
	else if (key > tmp->next->key) {
	    TSK_LIST *ent;

	    if (verbose)
		fprintf(stderr,
		    "entry %" PRIu64 " added before %" PRIu64 "\n",
		    key, tmp->next->key);

	    if ((ent = tsk_list_create(key)) == NULL)
		return 1;

	    ent->next = tmp->next;
	    tmp->next = ent;
	    return 0;
	}
	else if (key == tmp->next->key) {
	    return 0;
	}
	tmp = tmp->next;
    }
    return 0;
}


/* return 1 if key is in list and 0 if not */
uint8_t
tsk_list_find(TSK_LIST * list, uint64_t key)
{
    TSK_LIST *tmp;

    tmp = list;
    while (tmp != NULL) {
	// check this bucket
	if ((key <= tmp->key) && (key > tmp->key - tmp->len))
	    return 1;

	// Have we passed any potential buckets?
	else if (key > tmp->key)
	    return 0;

	tmp = tmp->next;
    }
    return 0;
}

void
tsk_list_free(TSK_LIST * list)
{
    TSK_LIST *tmp;

    while (list) {
	tmp = list->next;
	free(list);
	list = tmp;
    }
}
