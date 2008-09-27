profile_members = { \
  'task_struct' : [ 1360, { \
    'state' : [ 0, ['long']], \
    'thread_info' : [ 4, ['pointer', ['thread_info']]], \
    'usage' : [ 8, ['__anonstruct_atomic_t_14']], \
    'flags' : [ 12, ['unsigned long']], \
    'lock_depth' : [ 16, ['int']], \
    'load_weight' : [ 20, ['int']], \
    'prio' : [ 24, ['int']], \
    'static_prio' : [ 28, ['int']], \
    'normal_prio' : [ 32, ['int']], \
    'run_list' : [ 36, ['list_head']], \
    'array' : [ 44, ['pointer', ['prio_array']]], \
    'ioprio' : [ 48, ['unsigned short']], \
    'btrace_seq' : [ 52, ['unsigned int']], \
    'sleep_avg' : [ 56, ['unsigned long']], \
    'timestamp' : [ 60, ['unsigned long long']], \
    'last_ran' : [ 68, ['unsigned long long']], \
    'sched_time' : [ 76, ['unsigned long long']], \
    'sleep_type' : [ 84, ['enum', 'sleep_type', ]], \
    'policy' : [ 88, ['unsigned long']], \
    'cpus_allowed' : [ 92, ['__anonstruct_cpumask_t_8']], \
    'time_slice' : [ 96, ['unsigned int']], \
    'first_time_slice' : [ 100, ['unsigned int']], \
    'sched_info' : [ 104, ['sched_info']], \
    'tasks' : [ 124, ['list_head']], \
    'mm' : [ 132, ['pointer', ['mm_struct']]], \
    'active_mm' : [ 136, ['pointer', ['mm_struct']]], \
    'binfmt' : [ 140, ['pointer', ['linux_binfmt']]], \
    'exit_state' : [ 144, ['long']], \
    'exit_code' : [ 148, ['int']], \
    'exit_signal' : [ 152, ['int']], \
    'pdeath_signal' : [ 156, ['int']], \
    'personality' : [ 160, ['unsigned long']], \
    'pid' : [ 168, ['int']], \
    'tgid' : [ 172, ['int']], \
    'parent' : [ 176, ['pointer', ['task_struct']]], \
    'children' : [ 180, ['list_head']], \
    'sibling' : [ 188, ['list_head']], \
    'group_leader' : [ 196, ['pointer', ['task_struct']]], \
    'pids' : [ 200, ['array', 3, ['pid_link']]], \
    'thread_group' : [ 236, ['list_head']], \
    'vfork_done' : [ 244, ['pointer', ['completion']]], \
    'set_child_tid' : [ 248, ['pointer', ['int']]], \
    'clear_child_tid' : [ 252, ['pointer', ['int']]], \
    'rt_priority' : [ 256, ['unsigned long']], \
    'utime' : [ 260, ['unsigned long']], \
    'stime' : [ 264, ['unsigned long']], \
    'nvcsw' : [ 268, ['unsigned long']], \
    'nivcsw' : [ 272, ['unsigned long']], \
    'start_time' : [ 276, ['timespec']], \
    'min_flt' : [ 284, ['unsigned long']], \
    'maj_flt' : [ 288, ['unsigned long']], \
    'it_prof_expires' : [ 292, ['unsigned long']], \
    'it_virt_expires' : [ 296, ['unsigned long']], \
    'it_sched_expires' : [ 300, ['unsigned long long']], \
    'cpu_timers' : [ 308, ['array', 3, ['list_head']]], \
    'uid' : [ 332, ['unsigned int']], \
    'euid' : [ 336, ['unsigned int']], \
    'suid' : [ 340, ['unsigned int']], \
    'fsuid' : [ 344, ['unsigned int']], \
    'gid' : [ 348, ['unsigned int']], \
    'egid' : [ 352, ['unsigned int']], \
    'sgid' : [ 356, ['unsigned int']], \
    'fsgid' : [ 360, ['unsigned int']], \
    'group_info' : [ 364, ['pointer', ['group_info']]], \
    'cap_effective' : [ 368, ['unsigned int']], \
    'cap_inheritable' : [ 372, ['unsigned int']], \
    'cap_permitted' : [ 376, ['unsigned int']], \
    'user' : [ 384, ['pointer', ['user_struct']]], \
    'request_key_auth' : [ 388, ['pointer', ['key']]], \
    'thread_keyring' : [ 392, ['pointer', ['key']]], \
    'jit_keyring' : [ 396, ['unsigned char']], \
    'oomkilladj' : [ 400, ['int']], \
    'comm' : [ 404, ['array', 16, ['char']]], \
    'link_count' : [ 420, ['int']], \
    'total_link_count' : [ 424, ['int']], \
    'sysvsem' : [ 428, ['sysv_sem']], \
    'thread' : [ 432, ['thread_struct']], \
    'fs' : [ 1088, ['pointer', ['fs_struct']]], \
    'files' : [ 1092, ['pointer', ['files_struct']]], \
    'namespace' : [ 1096, ['pointer', ['namespace']]], \
    'signal' : [ 1100, ['pointer', ['signal_struct']]], \
    'sighand' : [ 1104, ['pointer', ['sighand_struct']]], \
    'blocked' : [ 1108, ['__anonstruct_sigset_t_72']], \
    'real_blocked' : [ 1116, ['__anonstruct_sigset_t_72']], \
    'saved_sigmask' : [ 1124, ['__anonstruct_sigset_t_72']], \
    'pending' : [ 1132, ['sigpending']], \
    'sas_ss_sp' : [ 1148, ['unsigned long']], \
    'sas_ss_size' : [ 1152, ['unsigned int']], \
    'notifier' : [ 1156, ['pointer', ['function']]], \
    'notifier_data' : [ 1160, ['pointer', ['void']]], \
    'notifier_mask' : [ 1164, ['pointer', ['__anonstruct_sigset_t_72']]], \
    'tux_info' : [ 1168, ['pointer', ['void']]], \
    'tux_exit' : [ 1172, ['pointer', ['function']]], \
    'security' : [ 1176, ['pointer', ['void']]], \
    'audit_context' : [ 1180, ['pointer', ['audit_context']]], \
    'seccomp' : [ 1184, ['__anonstruct_seccomp_t_82']], \
    'utrace' : [ 1184, ['pointer', ['utrace']]], \
    'utrace_flags' : [ 1188, ['unsigned long']], \
    'parent_exec_id' : [ 1192, ['unsigned int']], \
    'self_exec_id' : [ 1196, ['unsigned int']], \
    'alloc_lock' : [ 1200, ['__anonstruct_spinlock_t_12']], \
    'pi_lock' : [ 1204, ['__anonstruct_spinlock_t_12']], \
    'pi_waiters' : [ 1208, ['plist_head']], \
    'pi_blocked_on' : [ 1224, ['pointer', ['rt_mutex_waiter']]], \
    'journal_info' : [ 1228, ['pointer', ['void']]], \
    'reclaim_state' : [ 1232, ['pointer', ['reclaim_state']]], \
    'backing_dev_info' : [ 1236, ['pointer', ['backing_dev_info']]], \
    'io_context' : [ 1240, ['pointer', ['io_context']]], \
    'io_wait' : [ 1244, ['pointer', ['__wait_queue']]], \
    'rchar' : [ 1248, ['unsigned long long']], \
    'wchar' : [ 1256, ['unsigned long long']], \
    'syscr' : [ 1264, ['unsigned long long']], \
    'syscw' : [ 1272, ['unsigned long long']], \
    'acct_rss_mem1' : [ 1280, ['unsigned long long']], \
    'acct_vm_mem1' : [ 1288, ['unsigned long long']], \
    'acct_stimexpd' : [ 1296, ['long']], \
    'cpuset' : [ 1300, ['pointer', ['cpuset']]], \
    'mems_allowed' : [ 1304, ['__anonstruct_nodemask_t_16']], \
    'cpuset_mems_generation' : [ 1308, ['int']], \
    'cpuset_mem_spread_rotor' : [ 1312, ['int']], \
    'robust_list' : [ 1316, ['pointer', ['robust_list_head']]], \
    'pi_state_list' : [ 1320, ['list_head']], \
    'pi_state_cache' : [ 1328, ['pointer', ['futex_pi_state']]], \
    'fs_excl' : [ 1332, ['__anonstruct_atomic_t_14']], \
    'rcu' : [ 1336, ['rcu_head']], \
    'ptracees' : [ 1344, ['list_head']], \
    'splice_pipe' : [ 1352, ['pointer', ['pipe_inode_info']]], \
    'delays' : [ 1356, ['pointer', ['task_delay_info']]], \
  } ], \
  'dentry' : [ 136, { \
    'd_count' : [ 0, ['__anonstruct_atomic_t_14']], \
    'd_flags' : [ 4, ['unsigned int']], \
    'd_lock' : [ 8, ['__anonstruct_spinlock_t_12']], \
    'd_inode' : [ 12, ['pointer', ['inode']]], \
    'd_hash' : [ 16, ['hlist_node']], \
    'd_parent' : [ 24, ['pointer', ['dentry']]], \
    'd_name' : [ 28, ['qstr']], \
    'd_lru' : [ 40, ['list_head']], \
    'd_u' : [ 48, ['__anonunion_d_u_92']], \
    'd_subdirs' : [ 56, ['list_head']], \
    'd_alias' : [ 64, ['list_head']], \
    'd_time' : [ 72, ['unsigned long']], \
    'd_op' : [ 76, ['pointer', ['dentry_operations']]], \
    'd_sb' : [ 80, ['pointer', ['super_block']]], \
    'd_fsdata' : [ 84, ['pointer', ['void']]], \
    'd_extra_attributes' : [ 88, ['pointer', ['void']]], \
    'd_cookie' : [ 92, ['pointer', ['dcookie_struct']]], \
    'd_mounted' : [ 96, ['int']], \
    'd_iname' : [ 100, ['array', 36, ['unsigned char']]], \
  } ], \
  'inode' : [ 340, { \
    'i_hash' : [ 0, ['hlist_node']], \
    'i_list' : [ 8, ['list_head']], \
    'i_sb_list' : [ 16, ['list_head']], \
    'i_dentry' : [ 24, ['list_head']], \
    'i_ino' : [ 32, ['unsigned long']], \
    'i_count' : [ 36, ['__anonstruct_atomic_t_14']], \
    'i_mode' : [ 40, ['unsigned short']], \
    'i_nlink' : [ 44, ['unsigned int']], \
    'i_uid' : [ 48, ['unsigned int']], \
    'i_gid' : [ 52, ['unsigned int']], \
    'i_rdev' : [ 56, ['unsigned int']], \
    'i_size' : [ 60, ['long long']], \
    'i_atime' : [ 68, ['timespec']], \
    'i_mtime' : [ 76, ['timespec']], \
    'i_ctime' : [ 84, ['timespec']], \
    'i_blkbits' : [ 92, ['unsigned int']], \
    'i_version' : [ 96, ['unsigned long']], \
    'i_blocks' : [ 100, ['unsigned long long']], \
    'i_bytes' : [ 108, ['unsigned short']], \
    'i_lock' : [ 112, ['__anonstruct_spinlock_t_12']], \
    'i_mutex' : [ 116, ['mutex']], \
    'i_alloc_sem' : [ 132, ['rw_semaphore']], \
    'i_op' : [ 148, ['pointer', ['inode_operations']]], \
    'i_fop' : [ 152, ['pointer', ['file_operations']]], \
    'i_sb' : [ 156, ['pointer', ['super_block']]], \
    'i_flock' : [ 160, ['pointer', ['file_lock']]], \
    'i_mapping' : [ 164, ['pointer', ['address_space']]], \
    'i_data' : [ 168, ['address_space']], \
    'i_dquot' : [ 252, ['array', 2, ['pointer', ['dquot']]]], \
    'i_devices' : [ 260, ['list_head']], \
    '__annonCompField1' : [ 268, ['__anonunion____missing_field_name_94']], \
    'i_cindex' : [ 272, ['int']], \
    'i_generation' : [ 276, ['unsigned int']], \
    'i_dnotify_mask' : [ 280, ['unsigned long']], \
    'i_dnotify' : [ 284, ['pointer', ['dnotify_struct']]], \
    'inotify_watches' : [ 288, ['list_head']], \
    'inotify_mutex' : [ 296, ['mutex']], \
    'i_state' : [ 312, ['unsigned long']], \
    'dirtied_when' : [ 316, ['unsigned long']], \
    'i_flags' : [ 320, ['unsigned int']], \
    'i_writecount' : [ 324, ['__anonstruct_atomic_t_14']], \
    'i_security' : [ 328, ['pointer', ['void']]], \
    'i_private' : [ 332, ['pointer', ['void']]], \
    'i_size_seqcount' : [ 336, ['seqcount']], \
  } ], \
  'file' : [ 140, { \
    'f_u' : [ 0, ['__anonunion_f_u_95']], \
    'f_dentry' : [ 8, ['pointer', ['dentry']]], \
    'f_vfsmnt' : [ 12, ['pointer', ['vfsmount']]], \
    'f_op' : [ 16, ['pointer', ['file_operations']]], \
    'f_count' : [ 20, ['__anonstruct_atomic_t_14']], \
    'f_flags' : [ 24, ['unsigned int']], \
    'f_mode' : [ 28, ['unsigned short']], \
    'f_pos' : [ 32, ['long long']], \
    'f_owner' : [ 40, ['fown_struct']], \
    'f_uid' : [ 64, ['unsigned int']], \
    'f_gid' : [ 68, ['unsigned int']], \
    'f_ra' : [ 72, ['file_ra_state']], \
    'f_version' : [ 112, ['unsigned long']], \
    'f_security' : [ 116, ['pointer', ['void']]], \
    'private_data' : [ 120, ['pointer', ['void']]], \
    'f_ep_links' : [ 124, ['list_head']], \
    'f_ep_lock' : [ 132, ['__anonstruct_spinlock_t_12']], \
    'f_mapping' : [ 136, ['pointer', ['address_space']]], \
  } ], \
  'mm_struct' : [ 444, { \
    'mmap' : [ 0, ['pointer', ['vm_area_struct']]], \
    'mm_rb' : [ 4, ['rb_root']], \
    'mmap_cache' : [ 8, ['pointer', ['vm_area_struct']]], \
    'get_unmapped_area' : [ 12, ['pointer', ['function']]], \
    'get_unmapped_exec_area' : [ 16, ['pointer', ['function']]], \
    'unmap_area' : [ 20, ['pointer', ['function']]], \
    'mmap_base' : [ 24, ['unsigned long']], \
    'task_size' : [ 28, ['unsigned long']], \
    'cached_hole_size' : [ 32, ['unsigned long']], \
    'free_area_cache' : [ 36, ['unsigned long']], \
    'pgd' : [ 40, ['pointer', ['__anonstruct_pgd_t_6']]], \
    'mm_users' : [ 44, ['__anonstruct_atomic_t_14']], \
    'mm_count' : [ 48, ['__anonstruct_atomic_t_14']], \
    'map_count' : [ 52, ['int']], \
    'mmap_sem' : [ 56, ['rw_semaphore']], \
    'page_table_lock' : [ 72, ['__anonstruct_spinlock_t_12']], \
    'mmlist' : [ 76, ['list_head']], \
    '_file_rss' : [ 84, ['unsigned long']], \
    '_anon_rss' : [ 88, ['unsigned long']], \
    'hiwater_rss' : [ 92, ['unsigned long']], \
    'hiwater_vm' : [ 96, ['unsigned long']], \
    'total_vm' : [ 100, ['unsigned long']], \
    'locked_vm' : [ 104, ['unsigned long']], \
    'shared_vm' : [ 108, ['unsigned long']], \
    'exec_vm' : [ 112, ['unsigned long']], \
    'stack_vm' : [ 116, ['unsigned long']], \
    'reserved_vm' : [ 120, ['unsigned long']], \
    'def_flags' : [ 124, ['unsigned long']], \
    'nr_ptes' : [ 128, ['unsigned long']], \
    'start_code' : [ 132, ['unsigned long']], \
    'end_code' : [ 136, ['unsigned long']], \
    'start_data' : [ 140, ['unsigned long']], \
    'end_data' : [ 144, ['unsigned long']], \
    'start_brk' : [ 148, ['unsigned long']], \
    'brk' : [ 152, ['unsigned long']], \
    'start_stack' : [ 156, ['unsigned long']], \
    'arg_start' : [ 160, ['unsigned long']], \
    'arg_end' : [ 164, ['unsigned long']], \
    'env_start' : [ 168, ['unsigned long']], \
    'env_end' : [ 172, ['unsigned long']], \
    'saved_auxv' : [ 176, ['array', 44, ['unsigned long']]], \
    'cpu_vm_mask' : [ 356, ['__anonstruct_cpumask_t_8']], \
    'context' : [ 360, ['__anonstruct_mm_context_t_17']], \
    'swap_token_time' : [ 404, ['unsigned long']], \
    'recent_pagein' : [ 408, ['char']], \
    'core_waiters' : [ 412, ['int']], \
    'core_startup_done' : [ 416, ['pointer', ['completion']]], \
    'core_done' : [ 420, ['completion']], \
    'ioctx_list_lock' : [ 436, ['__anonstruct_rwlock_t_13']], \
    'ioctx_list' : [ 440, ['pointer', ['kioctx']]], \
  } ], \
  'list_head' : [ 8, { \
    'next' : [ 0, ['pointer', ['list_head']]], \
    'prev' : [ 4, ['pointer', ['list_head']]], \
  } ], \
  'module' : [ 4608, { \
    'state' : [ 0, ['enum', 'module_state', ]], \
    'list' : [ 4, ['list_head']], \
    'name' : [ 12, ['array', 60, ['char']]], \
    'mkobj' : [ 72, ['module_kobject']], \
    'param_attrs' : [ 140, ['pointer', ['module_param_attrs']]], \
    'modinfo_attrs' : [ 144, ['pointer', ['module_attribute']]], \
    'version' : [ 148, ['pointer', ['char']]], \
    'srcversion' : [ 152, ['pointer', ['char']]], \
    'syms' : [ 156, ['pointer', ['kernel_symbol']]], \
    'num_syms' : [ 160, ['unsigned int']], \
    'crcs' : [ 164, ['pointer', ['unsigned long']]], \
    'gpl_syms' : [ 168, ['pointer', ['kernel_symbol']]], \
    'num_gpl_syms' : [ 172, ['unsigned int']], \
    'gpl_crcs' : [ 176, ['pointer', ['unsigned long']]], \
    'unused_syms' : [ 180, ['pointer', ['kernel_symbol']]], \
    'num_unused_syms' : [ 184, ['unsigned int']], \
    'unused_crcs' : [ 188, ['pointer', ['unsigned long']]], \
    'unused_gpl_syms' : [ 192, ['pointer', ['kernel_symbol']]], \
    'num_unused_gpl_syms' : [ 196, ['unsigned int']], \
    'unused_gpl_crcs' : [ 200, ['pointer', ['unsigned long']]], \
    'gpl_future_syms' : [ 204, ['pointer', ['kernel_symbol']]], \
    'num_gpl_future_syms' : [ 208, ['unsigned int']], \
    'gpl_future_crcs' : [ 212, ['pointer', ['unsigned long']]], \
    'num_exentries' : [ 216, ['unsigned int']], \
    'extable' : [ 220, ['pointer', ['exception_table_entry']]], \
    'init' : [ 224, ['pointer', ['function']]], \
    'module_init' : [ 228, ['pointer', ['void']]], \
    'module_core' : [ 232, ['pointer', ['void']]], \
    'init_size' : [ 236, ['unsigned long']], \
    'core_size' : [ 240, ['unsigned long']], \
    'init_text_size' : [ 244, ['unsigned long']], \
    'core_text_size' : [ 248, ['unsigned long']], \
    'unwind_info' : [ 252, ['pointer', ['void']]], \
    'arch' : [ 256, ['mod_arch_specific']], \
    'unsafe' : [ 256, ['int']], \
    'license_gplok' : [ 260, ['int']], \
    'gpgsig_ok' : [ 264, ['int']], \
    'ref' : [ 384, ['array', 32, ['module_ref']]], \
    'modules_which_use_me' : [ 4480, ['list_head']], \
    'waiter' : [ 4488, ['pointer', ['task_struct']]], \
    'exit' : [ 4492, ['pointer', ['function']]], \
    'symtab' : [ 4496, ['pointer', ['elf32_sym']]], \
    'num_symtab' : [ 4500, ['unsigned long']], \
    'strtab' : [ 4504, ['pointer', ['char']]], \
    'sect_attrs' : [ 4508, ['pointer', ['module_sect_attrs']]], \
    'percpu' : [ 4512, ['pointer', ['void']]], \
    'args' : [ 4516, ['pointer', ['char']]], \
  } ], \
  'socket' : [ 40, { \
    'state' : [ 0, ['enum', '__anonenum_socket_state_119', ]], \
    'flags' : [ 4, ['unsigned long']], \
    'ops' : [ 8, ['pointer', ['proto_ops']]], \
    'fasync_list' : [ 12, ['pointer', ['fasync_struct']]], \
    'file' : [ 16, ['pointer', ['file']]], \
    'sk' : [ 20, ['pointer', ['sock']]], \
    'wait' : [ 24, ['__wait_queue_head']], \
    'type' : [ 36, ['short']], \
  } ], \
  'sock' : [ 344, { \
    '__sk_common' : [ 0, ['sock_common']], \
    'sk_protocol' : [ 37, ['unsigned char']], \
    'sk_type' : [ 38, ['unsigned short']], \
    'sk_rcvbuf' : [ 40, ['int']], \
    'sk_lock' : [ 44, ['__anonstruct_socket_lock_t_218']], \
    'sk_sleep' : [ 64, ['pointer', ['__wait_queue_head']]], \
    'sk_dst_cache' : [ 68, ['pointer', ['dst_entry']]], \
    'sk_policy' : [ 72, ['array', 2, ['pointer', ['xfrm_policy']]]], \
    'sk_dst_lock' : [ 80, ['__anonstruct_rwlock_t_13']], \
    'sk_rmem_alloc' : [ 84, ['__anonstruct_atomic_t_14']], \
    'sk_wmem_alloc' : [ 88, ['__anonstruct_atomic_t_14']], \
    'sk_omem_alloc' : [ 92, ['__anonstruct_atomic_t_14']], \
    'sk_receive_queue' : [ 96, ['sk_buff_head']], \
    'sk_write_queue' : [ 112, ['sk_buff_head']], \
    'sk_async_wait_queue' : [ 128, ['sk_buff_head']], \
    'sk_wmem_queued' : [ 144, ['int']], \
    'sk_forward_alloc' : [ 148, ['int']], \
    'sk_allocation' : [ 152, ['unsigned int']], \
    'sk_sndbuf' : [ 156, ['int']], \
    'sk_route_caps' : [ 160, ['int']], \
    'sk_gso_type' : [ 164, ['int']], \
    'sk_rcvlowat' : [ 168, ['int']], \
    'sk_flags' : [ 172, ['unsigned long']], \
    'sk_lingertime' : [ 176, ['unsigned long']], \
    'sk_backlog' : [ 180, ['__anonstruct_sk_backlog_219']], \
    'sk_error_queue' : [ 188, ['sk_buff_head']], \
    'sk_prot_creator' : [ 204, ['pointer', ['proto']]], \
    'sk_callback_lock' : [ 208, ['__anonstruct_rwlock_t_13']], \
    'sk_err' : [ 212, ['int']], \
    'sk_err_soft' : [ 216, ['int']], \
    'sk_ack_backlog' : [ 220, ['unsigned short']], \
    'sk_max_ack_backlog' : [ 222, ['unsigned short']], \
    'sk_priority' : [ 224, ['unsigned int']], \
    'sk_peercred' : [ 228, ['ucred']], \
    'sk_rcvtimeo' : [ 240, ['long']], \
    'sk_sndtimeo' : [ 244, ['long']], \
    'sk_filter' : [ 248, ['pointer', ['sk_filter']]], \
    'sk_protinfo' : [ 252, ['pointer', ['void']]], \
    'sk_timer' : [ 256, ['timer_list']], \
    'sk_stamp' : [ 280, ['timeval']], \
    'sk_socket' : [ 288, ['pointer', ['socket']]], \
    'sk_user_data' : [ 292, ['pointer', ['void']]], \
    'sk_sndmsg_page' : [ 296, ['pointer', ['page']]], \
    'sk_send_head' : [ 300, ['pointer', ['sk_buff']]], \
    'sk_sndmsg_off' : [ 304, ['unsigned int']], \
    'sk_write_pending' : [ 308, ['int']], \
    'sk_security' : [ 312, ['pointer', ['void']]], \
    'sk_state_change' : [ 316, ['pointer', ['function']]], \
    'sk_data_ready' : [ 320, ['pointer', ['function']]], \
    'sk_write_space' : [ 324, ['pointer', ['function']]], \
    'sk_error_report' : [ 328, ['pointer', ['function']]], \
    'sk_backlog_rcv' : [ 332, ['pointer', ['function']]], \
    'sk_create_child' : [ 336, ['pointer', ['function']]], \
    'sk_destruct' : [ 340, ['pointer', ['function']]], \
  } ], \
  'sock_common' : [ 36, { \
    'skc_family' : [ 0, ['unsigned short']], \
    'skc_state' : [ 2, ['unsigned char']], \
    'skc_reuse' : [ 3, ['unsigned char']], \
    'skc_bound_dev_if' : [ 4, ['int']], \
    'skc_node' : [ 8, ['hlist_node']], \
    'skc_bind_node' : [ 16, ['hlist_node']], \
    'skc_refcnt' : [ 24, ['__anonstruct_atomic_t_14']], \
    'skc_hash' : [ 28, ['unsigned int']], \
    'skc_prot' : [ 32, ['pointer', ['proto']]], \
  } ], \
  'inet_sock' : [ 496, { \
    'sk' : [ 0, ['sock']], \
    'pinet6' : [ 344, ['pointer', ['ipv6_pinfo']]], \
    'daddr' : [ 348, ['unsigned int']], \
    'rcv_saddr' : [ 352, ['unsigned int']], \
    'dport' : [ 356, ['unsigned short']], \
    'num' : [ 358, ['unsigned short']], \
    'saddr' : [ 360, ['unsigned int']], \
    'uc_ttl' : [ 364, ['short']], \
    'cmsg_flags' : [ 366, ['unsigned short']], \
    'opt' : [ 368, ['pointer', ['ip_options']]], \
    'sport' : [ 372, ['unsigned short']], \
    'id' : [ 374, ['unsigned short']], \
    'tos' : [ 376, ['unsigned char']], \
    'mc_ttl' : [ 377, ['unsigned char']], \
    'pmtudisc' : [ 378, ['unsigned char']], \
    'mc_index' : [ 380, ['int']], \
    'mc_addr' : [ 384, ['unsigned int']], \
    'mc_list' : [ 388, ['pointer', ['ip_mc_socklist']]], \
    'cork' : [ 392, ['__anonstruct_cork_226']], \
  } ], \
  'vm_area_struct' : [ 84, { \
    'vm_mm' : [ 0, ['pointer', ['mm_struct']]], \
    'vm_start' : [ 4, ['unsigned long']], \
    'vm_end' : [ 8, ['unsigned long']], \
    'vm_next' : [ 12, ['pointer', ['vm_area_struct']]], \
    'vm_page_prot' : [ 16, ['__anonstruct_pgprot_t_7']], \
    'vm_flags' : [ 20, ['unsigned long']], \
    'vm_rb' : [ 24, ['rb_node']], \
    'shared' : [ 36, ['__anonunion_shared_103']], \
    'anon_vma_node' : [ 52, ['list_head']], \
    'anon_vma' : [ 60, ['pointer', ['anon_vma']]], \
    'vm_ops' : [ 64, ['pointer', ['vm_operations_struct']]], \
    'vm_pgoff' : [ 68, ['unsigned long']], \
    'vm_file' : [ 72, ['pointer', ['file']]], \
    'vm_private_data' : [ 76, ['pointer', ['void']]], \
    'vm_truncate_count' : [ 80, ['unsigned long']], \
  } ], \
  'vfsmount' : [ 108, { \
    'mnt_hash' : [ 0, ['list_head']], \
    'mnt_parent' : [ 8, ['pointer', ['vfsmount']]], \
    'mnt_mountpoint' : [ 12, ['pointer', ['dentry']]], \
    'mnt_root' : [ 16, ['pointer', ['dentry']]], \
    'mnt_sb' : [ 20, ['pointer', ['super_block']]], \
    'mnt_mounts' : [ 24, ['list_head']], \
    'mnt_child' : [ 32, ['list_head']], \
    'mnt_count' : [ 40, ['__anonstruct_atomic_t_14']], \
    'mnt_flags' : [ 44, ['int']], \
    'mnt_expiry_mark' : [ 48, ['int']], \
    'mnt_devname' : [ 52, ['pointer', ['char']]], \
    'mnt_list' : [ 56, ['list_head']], \
    'mnt_expire' : [ 64, ['list_head']], \
    'mnt_share' : [ 72, ['list_head']], \
    'mnt_slave_list' : [ 80, ['list_head']], \
    'mnt_slave' : [ 88, ['list_head']], \
    'mnt_master' : [ 96, ['pointer', ['vfsmount']]], \
    'mnt_namespace' : [ 100, ['pointer', ['namespace']]], \
    'mnt_pinned' : [ 104, ['int']], \
  } ], \
  'timespec' : [ 8, { \
    'tv_sec' : [ 0, ['long']], \
    'tv_nsec' : [ 4, ['long']], \
  } ], \
  'timezone' : [ 8, { \
    'tz_minuteswest' : [ 0, ['int']], \
    'tz_dsttime' : [ 4, ['int']], \
  } ], \
  'new_utsname' : [ 390, { \
    'sysname' : [ 0, ['array', 65, ['char']]], \
    'nodename' : [ 65, ['array', 65, ['char']]], \
    'release' : [ 130, ['array', 65, ['char']]], \
    'version' : [ 195, ['array', 65, ['char']]], \
    'machine' : [ 260, ['array', 65, ['char']]], \
    'domainname' : [ 325, ['array', 65, ['char']]], \
  } ], \
  'files_struct' : [ 384, { \
    'count' : [ 0, ['__anonstruct_atomic_t_14']], \
    'fdt' : [ 4, ['pointer', ['fdtable']]], \
    'fdtab' : [ 8, ['fdtable']], \
    'file_lock' : [ 128, ['__anonstruct_spinlock_t_12']], \
    'next_fd' : [ 132, ['int']], \
    'close_on_exec_init' : [ 136, ['embedded_fd_set']], \
    'open_fds_init' : [ 140, ['embedded_fd_set']], \
    'fd_array' : [ 144, ['array', 32, ['pointer', ['file']]]], \
  } ], \
  'thread_info' : [ 56, { \
    'task' : [ 0, ['pointer', ['task_struct']]], \
    'exec_domain' : [ 4, ['pointer', ['exec_domain']]], \
    'flags' : [ 8, ['unsigned long']], \
    'status' : [ 12, ['unsigned long']], \
    'cpu' : [ 16, ['unsigned int']], \
    'preempt_count' : [ 20, ['int']], \
    'addr_limit' : [ 24, ['__anonstruct_mm_segment_t_9']], \
    'sysenter_return' : [ 28, ['pointer', ['void']]], \
    'restart_block' : [ 32, ['restart_block']], \
    'previous_esp' : [ 52, ['unsigned long']], \
    'supervisor_stack' : [ 56, ['array', 0, ['unsigned char']]], \
  } ], \
  'fdtable' : [ 36, { \
    'max_fds' : [ 0, ['unsigned int']], \
    'max_fdset' : [ 4, ['int']], \
    'fd' : [ 8, ['pointer', ['pointer', ['file']]]], \
    'close_on_exec' : [ 12, ['pointer', ['__anonstruct___kernel_fd_set_1']]], \
    'open_fds' : [ 16, ['pointer', ['__anonstruct___kernel_fd_set_1']]], \
    'rcu' : [ 20, ['rcu_head']], \
    'free_files' : [ 28, ['pointer', ['files_struct']]], \
    'next' : [ 32, ['pointer', ['fdtable']]], \
  } ], \
  'qstr' : [ 12, { \
    'hash' : [ 0, ['unsigned int']], \
    'len' : [ 4, ['unsigned int']], \
    'name' : [ 8, ['pointer', ['unsigned char']]], \
  } ], \
  'proto' : [ 4272, { \
    'close' : [ 0, ['pointer', ['function']]], \
    'connect' : [ 4, ['pointer', ['function']]], \
    'disconnect' : [ 8, ['pointer', ['function']]], \
    'accept' : [ 12, ['pointer', ['function']]], \
    'ioctl' : [ 16, ['pointer', ['function']]], \
    'init' : [ 20, ['pointer', ['function']]], \
    'destroy' : [ 24, ['pointer', ['function']]], \
    'shutdown' : [ 28, ['pointer', ['function']]], \
    'setsockopt' : [ 32, ['pointer', ['function']]], \
    'getsockopt' : [ 36, ['pointer', ['function']]], \
    'compat_setsockopt' : [ 40, ['pointer', ['function']]], \
    'compat_getsockopt' : [ 44, ['pointer', ['function']]], \
    'sendmsg' : [ 48, ['pointer', ['function']]], \
    'recvmsg' : [ 52, ['pointer', ['function']]], \
    'sendpage' : [ 56, ['pointer', ['function']]], \
    'bind' : [ 60, ['pointer', ['function']]], \
    'backlog_rcv' : [ 64, ['pointer', ['function']]], \
    'hash' : [ 68, ['pointer', ['function']]], \
    'unhash' : [ 72, ['pointer', ['function']]], \
    'get_port' : [ 76, ['pointer', ['function']]], \
    'enter_memory_pressure' : [ 80, ['pointer', ['function']]], \
    'memory_allocated' : [ 84, ['pointer', ['__anonstruct_atomic_t_14']]], \
    'sockets_allocated' : [ 88, ['pointer', ['__anonstruct_atomic_t_14']]], \
    'memory_pressure' : [ 92, ['pointer', ['int']]], \
    'sysctl_mem' : [ 96, ['pointer', ['int']]], \
    'sysctl_wmem' : [ 100, ['pointer', ['int']]], \
    'sysctl_rmem' : [ 104, ['pointer', ['int']]], \
    'max_header' : [ 108, ['int']], \
    'slab' : [ 112, ['pointer', ['kmem_cache']]], \
    'obj_size' : [ 116, ['unsigned int']], \
    'orphan_count' : [ 120, ['pointer', ['__anonstruct_atomic_t_14']]], \
    'rsk_prot' : [ 124, ['pointer', ['request_sock_ops']]], \
    'twsk_prot' : [ 128, ['pointer', ['timewait_sock_ops']]], \
    'owner' : [ 132, ['pointer', ['module']]], \
    'name' : [ 136, ['array', 32, ['char']]], \
    'node' : [ 168, ['list_head']], \
    'stats' : [ 176, ['array', 32, ['__anonstruct_stats_220']]], \
  } ], \
}