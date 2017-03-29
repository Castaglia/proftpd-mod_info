/*
 * ProFTPD: mod_info -- a module implementing informational SITE commands
 *
 * Copyright (c) 2003-2017 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_info, contrib software for proftpd 1.2 and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#ifndef MOD_INFO_H
#define MOD_INFO_H

#include "conf.h"
#include "privs.h"

#define MOD_INFO_VERSION	"mod_info/0.5"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030501
# error "ProFTPD 1.3.5rc1 or later required"
#endif

/* Statistics objects */
typedef enum {
  info_type_overall = 4,
  info_type_vhost
} info_stats_type_t;

typedef struct info_stat_obj {
  info_stats_type_t type;
  const char *name;

  unsigned long nsessions;
  unsigned long nbytes_downloaded;
  unsigned long nfiles_downloaded;
  unsigned long nbytes_uploaded;
  unsigned long nfiles_uploaded;

  struct info_stat_obj *next;
} info_stats_t;

/* Table source abstraction object */
typedef struct info_tab_obj {

  /* Memory pool for this object */
  pool *tab_pool;

  /* Table handle */
  int tab_handle;

  /* Arbitrary data pointer */
  void *tab_data;

  size_t tab_statslen;

  /* Table I/O routines */
  int (*tab_close)(struct info_tab_obj *);
  int (*tab_prep)(struct info_tab_obj *, const char **);
  int (*tab_read)(struct info_tab_obj *, info_stats_t *, info_stats_t *);
  int (*tab_write)(struct info_tab_obj *, info_stats_t *, info_stats_t *);

  /* Table locking routines.  There are two locks explicitly defined:
   * one for locking the "overall" portion of the table, and one for
   * locking the relevant server portion of the table.  The locking
   * routines use both internally.
   */
  struct flock tab_overall_lock, tab_vhost_lock;
  int (*tab_rlock)(struct info_tab_obj *, const char *);
  int (*tab_unlock)(struct info_tab_obj *);
  int (*tab_wlock)(struct info_tab_obj *, const char *);

} info_table_t;

/* Function prototypes necessary for info sub-modules */
int info_log(const char *, ...);
int info_register(const char *,
  info_table_t *(*tab_open)(pool *, const char *));

/* Function prototypes necessary for consumers of info data. */

/* Returns 0 on success, * -1 on failure (with errno set appropriately).
 */
int info_prep(const char **);

/* Returns 0 on success, * -1 on failure (with errno set appropriately).
 */
int info_read(info_stats_t *, info_stats_t *);

/* Returns 0 on success, -1 on failure (with errno set appropriately).
 */
int info_write(info_stats_t *, info_stats_t *);

#endif /* MOD_INFO_H */
