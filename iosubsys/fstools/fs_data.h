#ifndef _FS_DATA_H
#define _FS_DATA_H

extern FS_DATA *fs_data_alloc(u_int8_t);
extern FS_DATA_RUN *fs_data_run_alloc();
extern FS_DATA *fs_data_getnew_attr(FS_DATA *, u_int8_t);
extern void fs_data_clear_list(FS_DATA *);

extern FS_DATA *fs_data_put_str(FS_DATA *, char *, u_int32_t, u_int16_t, 
  DADDR_T *, int);

extern FS_DATA *fs_data_put_run(FS_DATA *, u_int64_t, u_int64_t,
  FS_DATA_RUN *, char *, u_int32_t, u_int16_t, u_int64_t, u_int8_t);

extern FS_DATA *fs_data_lookup(FS_DATA *, u_int32_t, u_int16_t);

extern void fs_data_run_free (FS_DATA_RUN *);
extern void fs_data_free (FS_DATA *);
#endif
