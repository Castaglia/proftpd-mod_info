/*
 * ProFTPD: mod_info -- a module implementing informational SITE commands
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
 * This is mod_info, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "mod_info.h"

#include <sys/resource.h>

typedef struct regtab_obj {
  struct regtab_obj *next;

  /* Table source type name */
  const char *regtab_name;

  /* Initialization function for this type of table source */
  info_table_t *(*regtab_open)(pool *, const char *);

} info_regtab_t;

extern module *static_modules[];
extern xaset_t *server_list;

module info_module;

/* Memory pool for this module. */
static pool *info_pool = NULL;

/* List of registered info tables */
static info_regtab_t *info_regtab_list = NULL;

/* Logging data */
static int info_logfd = -1;
static char *info_logname = NULL;

static unsigned char info_engine = FALSE;
static info_table_t *info_tab = NULL;

static info_stats_t info_overall_stats, info_vhost_stats;

/* Necessary prototypes */
MODRET info_post_retr(cmd_rec *);
MODRET info_post_stor(cmd_rec *);

static int info_rlock(const char *);
static int info_unlock(void);
static int info_wlock(const char *);

static char *info_get_uptime_str(time_t since) {
  static char buf[128] = {'\0'};
  time_t upsecs = time(NULL) - since;
  unsigned int upmins, uphours, updays;
  unsigned int pos = 0;

  if (!since)
    return "(N/A)";

  memset(buf, '\0', sizeof(buf));

  updays = (unsigned int) upsecs / (60 * 60 * 24);

  if (updays) {
    pos += sprintf(buf + pos, "%u day%s ", updays, (updays != 1) ? "s" : "");
    upsecs -= (updays * 60 * 60 * 24);
  }

  uphours = (unsigned int) upsecs / (60 * 60);

  if (uphours) {
    pos += sprintf(buf + pos, "%u hour%s ", uphours,
      (uphours != 1) ? "s" : "");
    upsecs -= (uphours * 60 * 60);
  }

  upmins = (unsigned int) upsecs / 60;

  if (upmins) {
    pos += sprintf(buf + pos, "%u minute%s ", upmins, (upmins != 1) ? "s" : "");
    upsecs -= (upmins * 60);
  }

  sprintf(buf + pos, "%lu second%s", (unsigned long) upsecs,
    (upsecs != 1) ? "s" : "");

  return buf;
}

/* Info logging routines */
static int info_closelog(void) {

  /* Sanity check */
  if (info_logfd != -1) {
    if (close(info_logfd) < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error closing '%s' file: %s", info_logname,
        strerror(errno));
    }

    info_logfd = -1;
    info_logname = NULL;
  }

  return 0;
}

int info_log(const char *fmt, ...) {
  va_list msg;
  int res;

  /* Sanity check */
  if (!info_logname)
    return 0;

  va_start(msg, fmt);
  res = pr_log_vwritefile(info_logfd, MOD_INFO_VERSION, fmt, msg);
  va_end(msg);

  return res;
}

static int info_openlog(void) {
  int res = 0;

  /* Sanity check */
  if ((info_logname = (char *) get_param_ptr(main_server->conf,
      "InfoLog", FALSE)) == NULL)
    return 0;

  /* Check for "none" */
  if (strcasecmp(info_logname, "none") == 0) {
    info_logname = NULL;
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile(info_logname, &info_logfd, 0640);
  PRIVS_RELINQUISH
  pr_signals_unblock();

  return res;
}

/* Table access routines */

static int info_closetab(void) {
  int res = 0;

  return res;
}

int info_prep(const char **vhosts) {

  if (!vhosts) {
    errno = EINVAL;
    return -1;
  }

  /* For each vhost (ServerName), check to see if the table contains an
   * entry.  If not, create one.
   *
   * Then, scan the table entries again, this time looking for table entries
   * that are not in the vhost list (ie that vhost has been removed from
   * the configuration.  Remove any such entries from the table.
   *
   * This will be something very much like the scoreboard; a module that
   * tracks its own statistics in a scoreboard table.
   */

  return 0;
}

int info_read(info_stats_t *overall_stats, info_stats_t *vhost_stats) {
  int bread = 0;

  if (!info_tab || !info_tab->tab_read) {
    errno = EPERM;
    return -1;
  }

  if (!overall_stats || !vhost_stats) {
    errno = EINVAL;
    return -1;
  }

  /* Obtain a read lock. */
  if (info_rlock(vhost_stats->name) < 0) {
    info_log("error: unable to obtain read lock: %s", strerror(errno));
    return -1;
  }

  /* Read in data to populate the stats objects. */
  if ((bread = info_tab->tab_read(info_tab, overall_stats, vhost_stats)) < 0) {
    info_unlock();
    return -1;
  }

  /* Release the lock. */
  if (info_unlock() < 0) {
    info_log("error: unable to release read lock: %s", strerror(errno));
    return -1;
  }

  return bread;
}

static int info_rlock(const char *name) {
  return info_tab->tab_rlock(info_tab, name);
}

static int info_unlock(void) {
  return info_tab->tab_unlock(info_tab);
}

static int info_wlock(const char *name) {
  return info_tab->tab_wlock(info_tab, name);
}

int info_write(info_stats_t *overall_stats, info_stats_t *vhost_stats) {
  int bwritten = 0;

  if (!info_tab || !info_tab->tab_write) {
    errno = EPERM;
    return -1;
  }

  if (!overall_stats || !vhost_stats) {
    errno = EINVAL;
    return -1;
  }

  /* Obtain a write lock. */
  if (info_wlock(vhost_stats->name) < 0) {
    info_log("error: unable to obtain write lock: %s", strerror(errno));
    return -1;
  }

  /* Write out the data in the stats objects. */
  if ((bwritten = info_tab->tab_write(info_tab, overall_stats,
      vhost_stats)) < 0) {
    info_unlock();
    return -1;
  }

  /* Release the lock. */
  if (info_unlock() < 0) {
    info_log("error: unable to release write lock: %s", strerror(errno));
    return -1;
  }

  return bwritten;
}

static int info_opentab(void) {
  register config_rec *c = NULL;
  register info_regtab_t *regtab = NULL;
  unsigned char have_type = FALSE;

  if ((c = find_config(main_server->conf, CONF_PARAM, "InfoTable",
      FALSE)) == NULL) {
    info_log("notice: no InfoTable configured");
    return -1;
  }

  /* Look up the table source open routine by name, and invoke it. */
  for (regtab = info_regtab_list; regtab; regtab = regtab->next) {
    if ((info_tab = regtab->regtab_open(info_pool, c->argv[1])) == NULL)
      return -1;

    else {
      have_type = TRUE;
      break;
    }
  }

  if (!have_type) {
    info_log("error: unsupported info table type: '%s'", c->argv[0]);
    return -1;
  }

  return 0;
}

int info_register(const char *srcname,
    info_table_t *(*srcopen)(pool *, const char *)) {

  /* Note: I know that use of permanent_pool is discouraged as much as
   * possible, but in this particular instance, I need a pool that
   * persists across rehashes.  The registration of a table type only
   * happens once, on module init when the server first starts up, so
   * this will not constitute a memory leak.
   */
  info_regtab_t *regtab = pcalloc(permanent_pool, sizeof(info_regtab_t));

  regtab->regtab_name = pstrdup(permanent_pool, srcname);
  regtab->regtab_open = srcopen;

  /* Add this object to the list. */
  regtab->next = info_regtab_list;
  info_regtab_list = regtab;

  return 0;
}

/* Configuration handlers
 */

/* usage: InfoEngine on|off */
MODRET set_infoengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: InfoLog path|"none" */
MODRET set_infolog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

#ifdef USE_INFO_TABLES
/* usage: InfoTable <source-type:source-info> */
MODRET set_infotable(cmd_rec *cmd) {
  register info_regtab_t *regtab = NULL;
  unsigned char have_registration = FALSE;
  char *ptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Separate the parameter into the components.  The parameter is
   * given as one string to enhance its similarity to URL syntax.
   */
  ptr = strchr(cmd->argv[1], ':');
  if (ptr == NULL) {
    CONF_ERROR(cmd, "badly formatted parameter");
  }

  *ptr++ = '\0';

  /* Verify that the requested source type has been registered. */
  for (regtab = info_regtab_list; regtab; regtab = regtab->next) {
    if (strcasecmp(regtab->regtab_name, cmd->argv[1]) == 0) {
      have_registration = TRUE;
      break;
    }
  }

  if (!have_registration) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported table source type: '",
      cmd->argv[1], "'", NULL));
  }

  add_config_param_str(cmd->argv[0], 2, cmd->argv[1], ptr);
  return PR_HANDLED(cmd);
}
#endif

/* Command handlers
 */

MODRET info_post_pass(cmd_rec *cmd) {
  if (info_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Update the session count. */
  info_overall_stats.nsessions++;
  info_vhost_stats.nsessions++;

  return PR_DECLINED(cmd);
}

MODRET info_post_retr(cmd_rec *cmd) {
  if (info_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Update the bytes/files downloaded count. */
  return PR_DECLINED(cmd);
}

MODRET info_post_stor(cmd_rec *cmd) {
  if (info_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Update the bytes/files uploaded count. */
  return PR_DECLINED(cmd);
}

MODRET info_site(cmd_rec *cmd) {
  unsigned char *authenticated = NULL;

  if (info_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 2) {
    return PR_DECLINED(cmd);
  }

  if (strcasecmp(cmd->argv[1], "HELP") == 0) {

    /* Add descriptions of this module's SITE commands. */
    pr_response_add(R_214, "STATUS");
    pr_response_add(R_214, "WHO");

    return PR_DECLINED(cmd);
  }

  /* The SITE commands all require that the client be authenticated first. */
  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);

  if (strcasecmp(cmd->argv[1], "STATUS") == 0) {
    time_t uptime = 0, now = time(NULL);
    char *cmd_name = NULL, *current_time_str = ctime(&now);
    register unsigned int i = 0;

    if (!authenticated || *authenticated == FALSE) {
      pr_response_send(R_530, "Please login with USER and PASS");
      return PR_ERROR(cmd);
    }

    cmd_name = cmd->argv[0];
    cmd->argv[0] = "SITE_STATUS";
    if (!dir_check(cmd->tmp_pool, cmd, "NONE", session.cwd, NULL)) {
      cmd->argv[0] = cmd_name;
      pr_response_add_err(R_550, "SITE %s: %s", cmd->arg, strerror(EACCES));
      return PR_ERROR(cmd);
    }
    cmd->argv[0] = cmd_name;

    pr_response_add(R_214, "Server Information");

    pr_response_add(R_DUP, "Server Version: ProFTPD " PROFTPD_VERSION_TEXT
      " " PR_STATUS);
    pr_response_add(R_DUP, "Server Built: " BUILD_STAMP);

    current_time_str[strlen(current_time_str)-1] = '\0';
    pr_response_add(R_DUP, "Current Time: %s", current_time_str);

    uptime = pr_scoreboard_get_daemon_uptime();
    pr_response_add(R_DUP, "Server Uptime: %s", info_get_uptime_str(uptime));

    pr_response_add(R_DUP, "\nModules:");
    for (i = 0; static_modules[i]; i++)
      pr_response_add(R_DUP, " mod_%s.c", (static_modules[i])->name);

    pr_response_add(R_DUP, "\nOverall Statistics:");
    if (info_tab) {

    } else
      pr_response_add(R_DUP, "(unavailable)");

    pr_response_add(R_DUP, "\nVirtual Server Statistics");
    if (info_tab == NULL) {
      pr_response_add(R_DUP, "(unavailable)\n");
    }

    pr_response_add(R_DUP, "Please contact %s for more information",
      cmd->server->ServerAdmin ? cmd->server->ServerAdmin : "ftp-admin");

    return PR_HANDLED(cmd);
 
  } else if (strcasecmp(cmd->argv[1], "WHO") == 0) {
    pr_scoreboard_entry_t *score = NULL;
    unsigned char have_sessions = FALSE;
    char *cmd_name = NULL;

    if (!authenticated || *authenticated == FALSE) {
      pr_response_send(R_530, "Please login with USER and PASS");
      return PR_ERROR(cmd);
    }

    cmd_name = cmd->argv[0];
    cmd->argv[0] = "SITE_WHO";
    if (!dir_check(cmd->tmp_pool, cmd, "NONE", session.cwd, NULL)) {
      cmd->argv[0] = cmd_name;
      pr_response_add_err(R_550, "SITE %s: %s", cmd->arg, strerror(EACCES));
      return PR_ERROR(cmd);
    }
    cmd->argv[0] = cmd_name;

    pr_response_add(R_214, "Current Sessions:");

    pr_rewind_scoreboard();
    while ((score = pr_scoreboard_read_entry()) != NULL) {
      have_sessions = TRUE;
      pr_response_add(R_DUP, "%s: (%s -> %s) \"%s %s\"", score->sce_user,
        score->sce_client_name, score->sce_server_addr, score->sce_cmd,
        score->sce_cmd_arg);
    }
    pr_restore_scoreboard();

    if (!have_sessions) {
      pr_response_add(R_DUP, "(none)");
    }

    pr_response_add(R_DUP, " ");
    pr_response_add(R_DUP, "Please contact %s for more information",
      cmd->server->ServerAdmin ? cmd->server->ServerAdmin : "ftp-admin");

    return PR_HANDLED(cmd);
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void info_exit_ev(const void *event_data, void *user_data) {
  if (info_engine == FALSE) {
    return;
  }

  if (info_tab) {
/* This code is currently unused; it will be used once tracking of usage
 * of system resources is supported by mod_info.
 */
#if 0
    struct rusage usage;
    long nsecs;

    if (getrusage(RUSAGE_SELF, &usage) < 0)
      info_log("error gathering resource usage numbers: %s", strerror(errno));

    info_daemon_stats.nsecs_user += usage.ru_utime.tv_sec;
    info_daemon_stats.nusecs_user += usage.ru_utime.tv_usec;

    /* Increment nsecs if appropriate; trying to keep nusecs from wrapping. */
    nsecs = info_daemon_stats.nusecs_user / 1000000;

    if (nsecs) {
      info_daemon_stats.nsecs_user += nsecs;
      info_daemon_stats.nusecs_user -= (nsecs * 1000000);
    }

    info_daemon_stats.nsecs_system += usage.ru_stime.tv_sec;
    info_daemon_stats.nusecs_system += usage.ru_stime.tv_usec;

    /* Increment nsecs if appropriate; trying to keep nusecs from wrapping. */
    nsecs = info_daemon_stats.nusecs_system / 1000000;

    if (nsecs) {
      info_daemon_stats.nsecs_system += nsecs;
      info_daemon_stats.nusecs_system -= (nsecs * 1000000);
    }

    info_vhost_stats.nsecs_user += usage.ru_utime.tv_sec;
    info_vhost_stats.nusecs_user += usage.ru_utime.tv_usec;

    /* Increment nsecs if appropriate; trying to keep nusecs from wrapping. */
    nsecs = info_vhost_stats.nusecs_user / 1000000;

    if (nsecs) {
      info_vhost_stats.nsecs_user += nsecs;
      info_vhost_stats.nusecs_user -= (nsecs * 1000000);
    }

    info_vhost_stats.nsecs_system += usage.ru_stime.tv_sec;
    info_vhost_stats.nusecs_system += usage.ru_stime.tv_usec;

    /* Increment nsecs if appropriate; trying to keep nusecs from wrapping. */
    nsecs = info_vhost_stats.nusecs_system / 1000000;

    if (nsecs) {
      info_vhost_stats.nsecs_system += nsecs;
      info_vhost_stats.nusecs_system -= (nsecs * 1000000);
    }
#endif

    if (info_write(&info_overall_stats, &info_vhost_stats) < 0)
      info_log("error writing statistics to InfoTable: %s", strerror(errno));

    if (info_closetab() < 0)
      info_log("error: unable to close InfoTable: %s", strerror(errno));
  }
 
  info_closelog();
  return;
}

#if defined(PR_SHARED_MODULE)
static void info_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_info.c", (const char *) event_data) == 0) {
    pr_event_unregister(&info_module, NULL, NULL);

    info_closelog();

    if (info_pool != NULL) {
      destroy_pool(info_pool);
      info_pool = NULL;
    }
  }
}
#endif /* PR_SHARED_MODULE */

static void info_postparse_ev(const void *event_data, void *user_data) {
  pool *tmp_pool = make_sub_pool(info_pool);
  array_header *vhost_list = make_array(tmp_pool, 0, sizeof(char *));
  server_rec *s = NULL;

  /* Prep the table. */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next)
    *((char **) push_array(vhost_list)) = pstrdup(tmp_pool, s->ServerName);

  if (info_prep((const char **) vhost_list->elts) < 0)
    info_log("error preparing InfoTable: %s", strerror(errno));

  destroy_pool(tmp_pool);
  return;
}

static void info_restart_ev(const void *event_data, void *user_data) {

  /* "Bounce" the log file descriptor. */
  info_closelog();
  info_openlog();

  /* Reset the module's memory pool. */
  destroy_pool(info_pool);
  info_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(info_pool, MOD_INFO_VERSION);

  return;
}

/* Initialization functions
 */

static int info_init(void) {

  /* Initialize the module's memory pool. */
  if (!info_pool) {
    info_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(info_pool, MOD_INFO_VERSION);
  }

#if defined(PR_SHARED_MODULE)
  pr_event_register(&info_module, "core.module-unload", info_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&info_module, "core.postparse", info_postparse_ev, NULL);
  pr_event_register(&info_module, "core.restart", info_restart_ev, NULL);

  return 0;
}

static int info_sess_init(void) {
  unsigned char *info_enabled = get_param_ptr(main_server->conf,
    "InfoEngine", FALSE);

  if (!info_enabled || *info_enabled == FALSE) {
    return 0;
  }

  info_engine = TRUE;

  info_openlog();

#ifdef USE_INFO_TABLES
  /* Open the info table. */
  PRIVS_ROOT
  if (info_opentab() < 0)
    info_log("error: unable to open InfoTable: %s", strerror(errno));
  PRIVS_RELINQUISH
#endif

  /* Make sure to close the tables when the child exits. */
  pr_event_register(&info_module, "core.exit", info_exit_ev, NULL);

  /* Initialize the overall stats, and the stats for this particular
   * vhost.
   */
  memset(&info_overall_stats, 0, sizeof(info_stats_t));
  memset(&info_vhost_stats, 0, sizeof(info_stats_t));
  info_vhost_stats.name = main_server->ServerName;

#ifdef USE_INFO_TABLES
  if (info_read(&info_overall_stats, &info_vhost_stats) < 0)
    info_log("error reading statistics from InfoTable: %s", strerror(errno));
#endif

  return 0;
}

/* Module API tables
 */

static conftable info_conftab[] = {
  { "InfoEngine",	set_infoengine,		NULL },
  { "InfoLog",		set_infolog,		NULL },
#ifdef USE_INFO_TABLES
  { "InfoTable",	set_infotable,		NULL },
#endif
  { NULL }
};

static cmdtable info_cmdtab[] = {
  { POST_CMD,	C_APPE,	G_NONE,	info_post_stor,	FALSE,	FALSE },
  { POST_CMD,	C_PASS,	G_NONE,	info_post_pass,	FALSE,	FALSE },
  { POST_CMD,	C_RETR,	G_NONE,	info_post_retr,	FALSE,	FALSE },
  { POST_CMD,	C_STOR,	G_NONE,	info_post_stor,	FALSE,	FALSE },
  { POST_CMD,	C_STOU,	G_NONE,	info_post_stor,	FALSE,	FALSE },
  { CMD,	C_SITE,	G_NONE,	info_site,	FALSE,	FALSE,	CL_MISC },
  { 0, NULL }
};

module info_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "info",

  /* Module configuration handler table */
  info_conftab,

  /* Module command handler table */
  info_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  info_init,

  /* Session initialization function */
  info_sess_init,

  /* Module version */
  MOD_INFO_VERSION
};
