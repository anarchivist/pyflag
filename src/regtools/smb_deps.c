/*
 * This file contains miscellaneous pieces of code which regfio.c
 * depends upon, from the Samba Subversion tree.  See:
 *   http://websvn.samba.org/cgi-bin/viewcvs.cgi/trunk/source/
 *
 * Copyright (C) 2005-2006 Timothy D. Morgan
 * Copyright (C) 1992-2005 Samba development team 
 *               (see individual files under Subversion for details.)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: smb_deps.c 111 2008-05-01 04:06:22Z tim $
 */

#include "smb_deps.h"
#include "talloc.h"

/* From lib/time.c */

/****************************************************************************
 Put a 8 byte filetime from a time_t
 This takes real GMT as input and converts to kludge-GMT
****************************************************************************/
void unix_to_nt_time(NTTIME *nt, time_t t)
{
  double d;
  
  if (t==0) 
  {
    nt->low = 0;
    nt->high = 0;
    return;
  }
  
  if (t == TIME_T_MAX) 
  {
    nt->low = 0xffffffff;
    nt->high = 0x7fffffff;
    return;
  }		
  
  if (t == -1) 
  {
    nt->low = 0xffffffff;
    nt->high = 0xffffffff;
    return;
  }		
  
  /* this converts GMT to kludge-GMT */
  /* XXX: This was removed due to difficult dependency requirements.  
   *      So far, times appear to be correct without this adjustment, but 
   *      that may be proven wrong with adequate testing. 
   */
  /* t -= TimeDiff(t) - get_serverzone(); */
  
  d = (double)(t);
  d += TIME_FIXUP_CONSTANT;
  d *= 1.0e7;
  
  nt->high = (uint32)(d * (1.0/(4.0*(double)(1<<30))));
  nt->low  = (uint32)(d - ((double)nt->high)*4.0*(double)(1<<30));
}


/****************************************************************************
 Interpret an 8 byte "filetime" structure to a time_t
 It's originally in "100ns units since jan 1st 1601"

 An 8 byte value of 0xffffffffffffffff will be returned as (time_t)0.

 It appears to be kludge-GMT (at least for file listings). This means
 its the GMT you get by taking a localtime and adding the
 serverzone. This is NOT the same as GMT in some cases. This routine
 converts this to real GMT.
****************************************************************************/
time_t nt_time_to_unix(const NTTIME* nt)
{
  double d;
  time_t ret;
  /* The next two lines are a fix needed for the 
     broken SCO compiler. JRA. */
  time_t l_time_min = TIME_T_MIN;
  time_t l_time_max = TIME_T_MAX;
  
  if (nt->high == 0 || (nt->high == 0xffffffff && nt->low == 0xffffffff))
    return(0);
  
  d = ((double)nt->high)*4.0*(double)(1<<30);
  d += (nt->low&0xFFF00000);
  d *= 1.0e-7;
  
  /* now adjust by 369 years to make the secs since 1970 */
  d -= TIME_FIXUP_CONSTANT;
  
  if (d <= l_time_min)
    return (l_time_min);
  
  if (d >= l_time_max)
    return (l_time_max);
  
  ret = (time_t)(d+0.5);
  
  /* this takes us from kludge-GMT to real GMT */
  /* XXX: This was removed due to difficult dependency requirements.  
   *      So far, times appear to be correct without this adjustment, but 
   *      that may be proven wrong with adequate testing. 
   */
  /*
    ret -= get_serverzone();
    ret += LocTimeDiff(ret);
  */

  return(ret);
}

/* End of stuff from lib/time.c */

/* From parse_prs.c */

/*******************************************************************
 Attempt, if needed, to grow a data buffer.
 Also depends on the data stream mode (io).
 ********************************************************************/
bool prs_grow(prs_struct *ps, uint32 extra_space)
{
  uint32 new_size;
  char *new_data;
  
  ps->grow_size = MAX(ps->grow_size, ps->data_offset + extra_space);
  
  if(ps->data_offset + extra_space <= ps->buffer_size)
    return true;
  
  /*
   * We cannot grow the buffer if we're not reading
   * into the prs_struct, or if we don't own the memory.
   */
  
  if(ps->io || !ps->is_dynamic)
    return false;
  
  /*
   * Decide how much extra space we really need.
   */
  extra_space -= (ps->buffer_size - ps->data_offset);
  if(ps->buffer_size == 0) 
  {
    /*
     * Ensure we have at least a PDU's length, or extra_space, 
     * whichever is greater.
     */  
    new_size = MAX(MAX_PDU_FRAG_LEN,extra_space);
    
    if((new_data = talloc_size(ps, new_size)) == NULL)
      return false;
  } 
  else 
  {
    /*
     * If the current buffer size is bigger than the space needed, just 
     * double it, else add extra_space.
     */
    new_size = MAX(ps->buffer_size*2, ps->buffer_size + extra_space);		
    
    if ((new_data = talloc_realloc(ps, ps->data_p, char, new_size)) == NULL)
      return false;
    
    memset(&new_data[ps->buffer_size], '\0', 
	   (size_t)(new_size - ps->buffer_size));
  }
  ps->buffer_size = new_size;
  ps->data_p = new_data;
  
  return true;
}


/*******************************************************************
 Align a the data_len to a multiple of align bytes - filling with
 zeros.
 ********************************************************************/
bool prs_align(prs_struct *ps)
{
  uint32 mod = ps->data_offset & (ps->align-1);
  
  if (ps->align != 0 && mod != 0) 
  {
    uint32 extra_space = (ps->align - mod);
    if(!prs_grow(ps, extra_space))
      return false;
    memset(&ps->data_p[ps->data_offset], '\0', (size_t)extra_space);
    ps->data_offset += extra_space;
  }
  
  return true;
}


/**
 * Initialise an expandable parse structure.
 *
 * @param size Initial buffer size.  If >0, a new buffer will be
 * created with malloc().
 *
 * @return false if allocation fails, otherwise true.
 **/

prs_struct *prs_init(void *ctx, uint32 size, bool io)
{
  prs_struct *ps = talloc(ctx, prs_struct);
  if(ps == NULL)
    return NULL;

  ps->io = io;
  ps->bigendian_data = RPC_LITTLE_ENDIAN;
  ps->align = RPC_PARSE_ALIGN;
  ps->is_dynamic = false;
  ps->data_offset = 0;
  ps->buffer_size = 0;
  ps->data_p = NULL;
  
  if (size != 0) 
  {
    ps->buffer_size = size;
    if((ps->data_p = talloc_array(ps, char,size)) == NULL) {
      talloc_free(ps);
      return NULL;
    };

    ps->is_dynamic = true; /* We own this memory. */
  }
  
  return ps;
}


char *prs_mem_get(prs_struct *ps, uint32 extra_size)
{
  if(ps->io) 
  {
    /*
     * If reading, ensure that we can read the requested size item.
     */
    if (ps->data_offset + extra_size > ps->buffer_size)
      return NULL;
  } 
  else 
  {
    /*
     * Writing - grow the buffer if needed.
     */
    if(!prs_grow(ps, extra_size))
      return NULL;
  }

  return &ps->data_p[ps->data_offset];
}


/*******************************************************************
 Stream a uint32.
 ********************************************************************/
bool prs_uint32(const char *name, prs_struct *ps, int depth, uint32 *data32)
{
  char *q = prs_mem_get(ps, sizeof(uint32));
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    if (ps->bigendian_data)
      *data32 = RIVAL(q,0);
    else
      *data32 = IVAL(q,0);
  } 
  else 
  {
    if (ps->bigendian_data)
      RSIVAL(q,0,*data32);
    else
      SIVAL(q,0,*data32);
  }
  ps->data_offset += sizeof(uint32);
  
  return true;
}


/******************************************************************
 Stream an array of uint32s. Length is number of uint32s.
 ********************************************************************/
bool prs_uint32s(const char *name, prs_struct *ps, 
		 int depth, uint32 *data32s, int len)
{
  int i;
  char *q = prs_mem_get(ps, len * sizeof(uint32));
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    if (ps->bigendian_data) 
    {
      for (i = 0; i < len; i++)
	data32s[i] = RIVAL(q, 4*i);
    } 
    else 
    {
      for (i = 0; i < len; i++)
	data32s[i] = IVAL(q, 4*i);
    }
  } 
  else 
  {
    if (ps->bigendian_data) 
    {
      for (i = 0; i < len; i++)
	RSIVAL(q, 4*i, data32s[i]);
    } 
    else 
    {
      for (i = 0; i < len; i++)
	SIVAL(q, 4*i, data32s[i]);
    }
  }
  ps->data_offset += (len * sizeof(uint32));
  
  return true;
}


/*******************************************************************
 Stream a uint16.
 ********************************************************************/
bool prs_uint16(const char *name, prs_struct *ps, int depth, uint16 *data16)
{
  char *q = prs_mem_get(ps, sizeof(uint16));
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    if (ps->bigendian_data)
      *data16 = RSVAL(q,0);
    else
      *data16 = SVAL(q,0);
  } 
  else 
  {
    if (ps->bigendian_data)
      RSSVAL(q,0,*data16);
    else
      SSVAL(q,0,*data16);
  }
  ps->data_offset += sizeof(uint16);
  
  return true;
}


/*******************************************************************
 prs_uint16 wrapper. Call this and it sets up a pointer to where the
 uint16 should be stored, or gets the size if reading.
 ********************************************************************/
bool prs_uint16_pre(const char *name, prs_struct *ps, int depth, 
		    uint16 *data16, uint32 *offset)
{
  *offset = ps->data_offset;
  if (ps->io) 
  {
    /* reading. */
    return prs_uint16(name, ps, depth, data16);
  } 
  else 
  {
    char *q = prs_mem_get(ps, sizeof(uint16));
    if(q ==NULL)
      return false;
    ps->data_offset += sizeof(uint16);
  }
  return true;
}


/*******************************************************************
 prs_uint16 wrapper.  call this and it retrospectively stores the size.
 does nothing on reading, as that is already handled by ...._pre()
 ********************************************************************/
bool prs_uint16_post(const char *name, prs_struct *ps, int depth, 
		     uint16 *data16, uint32 ptr_uint16, uint32 start_offset)
{
  if (!ps->io) 
  {
    /* 
     * Writing - temporarily move the offset pointer.
     */
    uint16 data_size = ps->data_offset - start_offset;
    uint32 old_offset = ps->data_offset;
    
    ps->data_offset = ptr_uint16;
    if(!prs_uint16(name, ps, depth, &data_size)) 
    {
      ps->data_offset = old_offset;
      return false;
    }
    ps->data_offset = old_offset;
  } 
  else 
    ps->data_offset = start_offset + (uint32)(*data16);

  return true;
}


/*******************************************************************
 Stream a uint8.
 ********************************************************************/
bool prs_uint8(const char *name, prs_struct *ps, int depth, uint8 *data8)
{
  char *q = prs_mem_get(ps, 1);
  if (q == NULL)
    return false;
  
  if (ps->io)
    *data8 = CVAL(q,0);
  else
    SCVAL(q,0,*data8);
  
  ps->data_offset += 1;
  
  return true;
}


/******************************************************************
 Stream an array of uint8s. Length is number of uint8s.
 ********************************************************************/
bool prs_uint8s(const char *name, prs_struct *ps, int depth, 
		uint8* data8s, int len)
{
  int i;
  char *q = prs_mem_get(ps, len);
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    for (i = 0; i < len; i++)
      data8s[i] = CVAL(q,i);
  } 
  else 
  {
    for (i = 0; i < len; i++)
      SCVAL(q, i, data8s[i]);
  }
  
  ps->data_offset += len;
  
  return true;
}


/*******************************************************************
 Set the current offset (external interface).
 ********************************************************************/
bool prs_set_offset(prs_struct *ps, uint32 offset)
{
  if(offset <= ps->data_offset) 
  {
    ps->data_offset = offset;
    return true;
  }
  
  if(!prs_grow(ps, offset - ps->data_offset))
    return false;
  
  ps->data_offset = offset;
  return true;
}

/* End of stuff from parse_prs.c */

/* From rpc_parse/parse_misc.c */

/*******************************************************************
 Reads or writes a struct uuid
********************************************************************/
bool smb_io_uuid(const char *desc, struct uuid *uuid, 
		 prs_struct *ps, int depth)
{
  if (uuid == NULL)
    return false;
  depth++;
  
  if(!prs_uint32 ("data   ", ps, depth, &uuid->time_low))
    return false;
  if(!prs_uint16 ("data   ", ps, depth, &uuid->time_mid))
    return false;
  if(!prs_uint16 ("data   ", ps, depth, &uuid->time_hi_and_version))
    return false;
  
  if(!prs_uint8s ("data   ", ps, depth, 
		  uuid->clock_seq, sizeof(uuid->clock_seq)))
    return false;

  if(!prs_uint8s ("data   ", ps, depth, uuid->node, sizeof(uuid->node)))
    return false;
  
  return true;
}


/*******************************************************************
 Reads or writes an NTTIME structure.
********************************************************************/
bool smb_io_time(const char *desc, NTTIME *nttime, prs_struct *ps, int depth)
{
  if (nttime == NULL)
    return false;
  depth++;

  if(!prs_align(ps))
    return false;
	
  if(!prs_uint32("low ", ps, depth, &nttime->low)) /* low part */
    return false;
  if(!prs_uint32("high", ps, depth, &nttime->high)) /* high part */
    return false;

  return true;
}


/*******************************************************************
 Reads or writes a DOM_SID structure.
********************************************************************/
bool smb_io_dom_sid(const char *desc, DOM_SID *sid, prs_struct *ps, int depth)
{
  int i;

  if (sid == NULL)
    return false;
  depth++;

  if(!prs_uint8 ("sid_rev_num", ps, depth, &sid->sid_rev_num))
    return false;

  if(!prs_uint8 ("num_auths  ", ps, depth, &sid->num_auths))
    return false;

  for (i = 0; i < 6; i++)
  {
    fstring tmp;
    snprintf(tmp, sizeof(tmp) - 1, "id_auth[%d] ", i);
    if(!prs_uint8 (tmp, ps, depth, &sid->id_auth[i]))
      return false;
  }

  /* oops! XXXX should really issue a warning here... */
  if (sid->num_auths > MAXSUBAUTHS)
    sid->num_auths = MAXSUBAUTHS;

  if(!prs_uint32s("sub_auths ", ps, depth, 
		  sid->sub_auths, sid->num_auths))
  { return false; }

  return true;
}

/* End of stuff from rpc_parse/parse_misc.c */

/* From lib/util_sid.c */

/*****************************************************************
 Calculates size of a sid.
*****************************************************************/  
size_t sid_size(const DOM_SID *sid)
{
  if (sid == NULL)
    return 0;

  return sid->num_auths * sizeof(uint32) + 8;
}


/*****************************************************************
 Compare the auth portion of two sids.
*****************************************************************/  
int sid_compare_auth(const DOM_SID *sid1, const DOM_SID *sid2)
{
  int i;

  if (sid1 == sid2)
    return 0;
  if (!sid1)
    return -1;
  if (!sid2)
    return 1;

  if (sid1->sid_rev_num != sid2->sid_rev_num)
    return sid1->sid_rev_num - sid2->sid_rev_num;

  for (i = 0; i < 6; i++)
    if (sid1->id_auth[i] != sid2->id_auth[i])
      return sid1->id_auth[i] - sid2->id_auth[i];

  return 0;
}


/*****************************************************************
 Compare two sids.
*****************************************************************/  
int sid_compare(const DOM_SID *sid1, const DOM_SID *sid2)
{
  int i;

  if (sid1 == sid2)
    return 0;
  if (!sid1)
    return -1;
  if (!sid2)
    return 1;

  /* Compare most likely different rids, first: i.e start at end */
  if (sid1->num_auths != sid2->num_auths)
    return sid1->num_auths - sid2->num_auths;

  for (i = sid1->num_auths-1; i >= 0; --i)
    if (sid1->sub_auths[i] != sid2->sub_auths[i])
      return sid1->sub_auths[i] - sid2->sub_auths[i];

  return sid_compare_auth(sid1, sid2);
}


/*****************************************************************
 Compare two sids.
*****************************************************************/  
bool sid_equal(const DOM_SID *sid1, const DOM_SID *sid2)
{
  return sid_compare(sid1, sid2) == 0;
}

/* End of stuff from lib/util_sid.c */

/* From lib/secace.c */

/*******************************************************************
 Check if ACE has OBJECT type.
********************************************************************/

bool sec_ace_object(uint8 type)
{
  if (type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT ||
      type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT ||
      type == SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT ||
      type == SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT) {
    return true;
  }
  return false;
}

/* End of stuff from lib/secace.c */

/* From rpc_parse/parse_sec.c */

/*******************************************************************
 Reads or writes a SEC_ACCESS structure.
********************************************************************/
bool sec_io_access(const char *desc, SEC_ACCESS *t, prs_struct *ps, int depth)
{
  if (t == NULL)
    return false;

  depth++;
	
  if(!prs_uint32("mask", ps, depth, &t->mask))
    return false;

  return true;
}


/*******************************************************************
 Reads or writes a SEC_ACE structure.
********************************************************************/
bool sec_io_ace(const char *desc, SEC_ACE *psa, prs_struct *ps, int depth)
{
  uint32 old_offset;
  uint32 offset_ace_size;

  if (psa == NULL)
    return false;

  depth++;
	
  old_offset = ps->data_offset;

  if(!prs_uint8("type ", ps, depth, &psa->type))
    return false;

  if(!prs_uint8("flags", ps, depth, &psa->flags))
    return false;

  if(!prs_uint16_pre("size ", ps, depth, &psa->size, &offset_ace_size))
    return false;

  if(!sec_io_access("info ", &psa->info, ps, depth))
    return false;

  /* check whether object access is present */
  if (!sec_ace_object(psa->type)) 
  {
    if (!smb_io_dom_sid("trustee  ", &psa->trustee , ps, depth))
      return false;
  } 
  else 
  {
    if (!prs_uint32("obj_flags", ps, depth, &psa->obj_flags))
      return false;

    if (psa->obj_flags & SEC_ACE_OBJECT_PRESENT)
      if (!smb_io_uuid("obj_guid", &psa->obj_guid, ps,depth))
	return false;

    if (psa->obj_flags & SEC_ACE_OBJECT_INHERITED_PRESENT)
      if (!smb_io_uuid("inh_guid", &psa->inh_guid, ps,depth))
	return false;

    if(!smb_io_dom_sid("trustee  ", &psa->trustee , ps, depth))
      return false;
  }

  /* Theorectically an ACE can have a size greater than the
   * sum of its components. When marshalling, pad with extra null bytes 
   * up to the
   * correct size. 
   */
  if (!ps->io && (psa->size > ps->data_offset - old_offset)) 
  {
    uint32 extra_len = psa->size - (ps->data_offset - old_offset);
    uint32 i;
    uint8 c = 0;

    for (i = 0; i < extra_len; i++) 
    {
      if (!prs_uint8("ace extra space", ps, depth, &c))
	return false;
    }
  }

  if(!prs_uint16_post("size ", ps, depth, &psa->size, 
		      offset_ace_size, old_offset))
  { return false; }

  return true;
}


/*******************************************************************
 Reads or writes a SEC_ACL structure.  

 First of the xx_io_xx functions that allocates its data structures
 for you as it reads them.
********************************************************************/
bool sec_io_acl(const char *desc, SEC_ACL **ppsa, prs_struct *ps, int depth)
{
  unsigned int i;
  uint32 old_offset;
  uint32 offset_acl_size;
  SEC_ACL* psa;

  /*
   * Note that the size is always a multiple of 4 bytes due to the
   * nature of the data structure.  Therefore the prs_align() calls
   * have been removed as they through us off when doing two-layer
   * marshalling such as in the printing code (RPC_BUFFER).  --jerry
   */

  if (ppsa == NULL || ps == NULL)
    return false;

  psa = *ppsa;

  if(ps->io && psa == NULL) 
  {
    /*
     * This is a read and we must allocate the stuct to read into.
     */
    if((psa = talloc(ps, SEC_ACL)) == NULL)
      return false;
    *ppsa = psa;
  }

  depth++;	
  old_offset = ps->data_offset;

  if(!prs_uint16("revision", ps, depth, &psa->revision)
     || !prs_uint16_pre("size     ", ps, depth, &psa->size, &offset_acl_size)
     || !prs_uint32("num_aces ", ps, depth, &psa->num_aces))
    goto error;

  if (ps->io) 
  {
    /*
     * Even if the num_aces is zero, allocate memory as there's a difference
     * between a non-present DACL (allow all access) and a DACL with no ACE's
     * (allow no access).
     */
    if((psa->ace = talloc_array(psa, SEC_ACE, psa->num_aces+1)) == NULL)
      goto error;
  }

  for (i = 0; i < psa->num_aces; i++) 
  {
    fstring tmp;
    snprintf(tmp, sizeof(tmp)-1, "ace_list[%02d]: ", i);
    if(!sec_io_ace(tmp, &psa->ace[i], ps, depth))
      goto error;
  }

  /* Theoretically an ACL can have a size greater than the
   *  sum of its components. When marshalling, pad with extra null 
   *  bytes up to the
   *  correct size. 
   */
  if (!ps->io && (psa->size > ps->data_offset - old_offset)) 
  {
    uint32 extra_len = psa->size - (ps->data_offset - old_offset);
    uint8 c = 0;

    for (i = 0; i < extra_len; i++) 
    {
      if (!prs_uint8("acl extra space", ps, depth, &c))
	goto error;
    }
  }

  if(!prs_uint16_post("size     ", ps, depth, &psa->size, 
		      offset_acl_size, old_offset))
    goto error; 

  return true;
 error:
  talloc_free(psa);
  *ppsa = NULL;
  return false;
}

/*******************************************************************
 Reads or writes a SEC_DESC structure.
 If reading and the *ppsd = NULL, allocates the structure.
********************************************************************/
bool sec_io_desc(const char *desc, SEC_DESC **ppsd, prs_struct *ps, int depth)
{
  uint32 old_offset;
  uint32 max_offset = 0; /* after we're done, move offset to end */
  uint32 tmp_offset = 0;

  SEC_DESC *psd;

  if (ppsd == NULL || ps == NULL)
    return false;

  psd = *ppsd;
  if (psd == NULL) 
  {
    if(ps->io) 
    {
      if((psd = talloc(ps, SEC_DESC)) == NULL)
	return false;
      *ppsd = psd;
    } 
    else 
    {
      /* Marshalling - just ignore. */
      return true;
    }
  }

  depth++;

  /* start of security descriptor stored for back-calc offset purposes */
  old_offset = ps->data_offset;

  if(!prs_uint16("revision ", ps, depth, &psd->revision)
     || !prs_uint16("type     ", ps, depth, &psd->type))
    goto error;

  if (!ps->io)
  {
    uint32 offset = SEC_DESC_HEADER_SIZE;

    /*
     * Work out the offsets here, as we write it out.
     */

    if (psd->sacl != NULL) 
    {
      psd->off_sacl = offset;
      offset += psd->sacl->size;
    } 
    else
      psd->off_sacl = 0;

    if (psd->dacl != NULL) 
    {
      psd->off_dacl = offset;
      offset += psd->dacl->size;
    } 
    else 
      psd->off_dacl = 0;

    if (psd->owner_sid != NULL) 
    {
      psd->off_owner_sid = offset;
      offset += sid_size(psd->owner_sid);
    } 
    else
      psd->off_owner_sid = 0;

    if (psd->grp_sid != NULL) 
    {
      psd->off_grp_sid = offset;
      offset += sid_size(psd->grp_sid);
    } 
    else
      psd->off_grp_sid = 0;
  }

  if(!prs_uint32("off_owner_sid", ps, depth, &psd->off_owner_sid)
     || !prs_uint32("off_grp_sid  ", ps, depth, &psd->off_grp_sid)
     || !prs_uint32("off_sacl     ", ps, depth, &psd->off_sacl)
     || !prs_uint32("off_dacl     ", ps, depth, &psd->off_dacl))
    goto error;

  max_offset = MAX(max_offset, ps->data_offset);

  if (psd->off_owner_sid != 0) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_owner_sid))
      goto error;

    if (ps->io) 
    {
      /* reading */
      if((psd->owner_sid = talloc(psd, DOM_SID)) == NULL)
	goto error;
    
    }

    if(!smb_io_dom_sid("owner_sid ", psd->owner_sid , ps, depth))
      goto error;

    max_offset = MAX(max_offset, ps->data_offset);

    if (!prs_set_offset(ps,tmp_offset))
      goto error;
  }

  if (psd->off_grp_sid != 0) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_grp_sid))
      goto error;

    if (ps->io) 
      {
	/* reading */
	if((psd->grp_sid = talloc(psd, DOM_SID)) == NULL)
	  goto error;
      }

    if(!smb_io_dom_sid("grp_sid", psd->grp_sid, ps, depth))
      goto error;
    
    max_offset = MAX(max_offset, ps->data_offset);

    if (!prs_set_offset(ps,tmp_offset))
      goto error;
  }

  if ((psd->type & SEC_DESC_SACL_PRESENT) && psd->off_sacl) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_sacl)
       || !sec_io_acl("sacl", &psd->sacl, ps, depth))
      goto error;
    
    max_offset = MAX(max_offset, ps->data_offset);
    if (!prs_set_offset(ps,tmp_offset))
      goto error;
  }

  if ((psd->type & SEC_DESC_DACL_PRESENT) && psd->off_dacl != 0) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_dacl)
       || !sec_io_acl("dacl", &psd->dacl, ps, depth))
      goto error;
    
    max_offset = MAX(max_offset, ps->data_offset);
    if (!prs_set_offset(ps,tmp_offset))
      goto error;
  }

  if(!prs_set_offset(ps, max_offset))
    goto error;
  
  return true;

 error:
    talloc_free(psd);
    *ppsd = NULL;
    return false;
}

/* End of stuff from rpc_parse/parse_sec.c */

/* From lib/secace.c */

/*******************************************************************
 Compares two SEC_ACE structures
********************************************************************/
bool sec_ace_equal(SEC_ACE *s1, SEC_ACE *s2)
{
  /* Trivial cases */
  if (!s1 && !s2) 
    return true;
  if (!s1 || !s2) 
    return false;

  /* Check top level stuff */
  if (s1->type != s2->type || s1->flags != s2->flags ||
      s1->info.mask != s2->info.mask) 
  { return false; }

  /* Check SID */
  if (!sid_equal(&s1->trustee, &s2->trustee))
    return false;

  return true;
}

/* End of stuff from lib/secace.c */

/* From lib/secacl.c */

/*******************************************************************
 Compares two SEC_ACL structures
********************************************************************/

bool sec_acl_equal(SEC_ACL *s1, SEC_ACL *s2)
{
  unsigned int i, j;

  /* Trivial cases */
  if (!s1 && !s2) 
    return true;
  if (!s1 || !s2) 
    return false;

  /* Check top level stuff */
  if (s1->revision != s2->revision)
    return false;

  if (s1->num_aces != s2->num_aces)
    return false;

  /* The ACEs could be in any order so check each ACE in s1 against 
     each ACE in s2. */

  for (i = 0; i < s1->num_aces; i++) 
  {
    bool found = false;

    for (j = 0; j < s2->num_aces; j++) 
    {
      if (sec_ace_equal(&s1->ace[i], &s2->ace[j])) 
      {
	found = true;
	break;
      }
    }

    if (!found)
      return false;
  }

  return true;
}

/* End of stuff from lib/secacl.c */

/* From lib/secdesc.c */

/*******************************************************************
 Compares two SEC_DESC structures
********************************************************************/
bool sec_desc_equal(SEC_DESC *s1, SEC_DESC *s2)
{
  /* Trivial cases */
  if (!s1 && !s2)
    return true;
  if (!s1 || !s2)
    return false;

  /* Check top level stuff */
  if (s1->revision != s2->revision)
    return false;

  if (s1->type!= s2->type)
    return false;

  /* Check owner and group */
  if (!sid_equal(s1->owner_sid, s2->owner_sid))
    return false;

  if (!sid_equal(s1->grp_sid, s2->grp_sid)) 
    return false;

  /* Check ACLs present in one but not the other */
  if ((s1->dacl && !s2->dacl) || (!s1->dacl && s2->dacl) ||
      (s1->sacl && !s2->sacl) || (!s1->sacl && s2->sacl)) 
  { return false; }

  /* Sigh - we have to do it the hard way by iterating over all
     the ACEs in the ACLs */
  if(!sec_acl_equal(s1->dacl, s2->dacl) || !sec_acl_equal(s1->sacl, s2->sacl)) 
    return false;

  return true;
}

/* End of stuff from lib/secdesc.c */
