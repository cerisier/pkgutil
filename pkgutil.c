#include <archive.h>
#include <archive_entry.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if (defined(_WIN32) || defined(__WIN32__))
#include <direct.h> /* _mkdir */
#define mkdir(x, y) _mkdir(x)
#endif

#define BSIZE (8 * 1024)

static const char *short_options = "EfhvX";

static const char *const nested_archive_names[] = {"Payload", "Scripts", NULL};

static const int disk_flags =
    ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
    ARCHIVE_EXTRACT_XATTR | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_OWNER |
    ARCHIVE_EXTRACT_SECURE_SYMLINKS | ARCHIVE_EXTRACT_SECURE_NODOTDOT |
    ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;

enum {
  opt_include = 256,
  opt_exclude,
  opt_strip_components,
};

static const struct option {
  const char *name;
  int required;
  int equivalent;
} pkg_longopts[] = {{"expand", 0, 'X'},
                    {"expand-full", 0, 'E'},
                    {"force", 0, 'f'},
                    {"help", 0, 'h'},
                    {"include", 1, opt_include},
                    {"exclude", 1, opt_exclude},
                    {"strip-components", 1, opt_strip_components},
                    {"verbose", 0, 'v'},
                    {NULL, 0, 0}};

static void fail_archive(struct archive *a, const char *ctx) {
  fprintf(stderr, "%s: %s\n", ctx,
          a ? archive_error_string(a) : "unknown error");
  exit(1);
}

static void fail_errno(const char *ctx) {
  fprintf(stderr, "%s: %s\n", ctx, strerror(errno));
  exit(1);
}

static void usage(FILE *out) {
  fprintf(out,
          "Usage: pkgutil [OPTIONS] [COMMANDS] ...\n\n"
          "Options:\n"
          "  --help                 Show this usage guide\n"
          "  --verbose, -v          Show contextual information and "
          "format for easy reading\n"
          "  --force, -f            Perform all operations without asking "
          "for confirmation\n"
          "  --include PATTERN      Only include paths matching PATTERN\n"
          "  --exclude PATTERN      Exclude paths matching PATTERN\n"
          "  --strip-components N   Strip N leading path components\n"
          "File Commands:\n"
          "  --expand PKG DIR       Write flat package entries to DIR\n"
          "  --expand-full PKG DIR  Fully expand package contents to DIR\n");
}

static char *strip_components_path(const char *path, int strip);
static int apply_strip_components(struct archive_entry *e, int strip);
static int path_component_count(const char *path);
static char *normalize_rel_path(const char *path);
struct pattern_list {
  char **items;
  size_t len;
  size_t cap;
};
static void pattern_list_add(struct pattern_list *list, const char *pattern);
static void pattern_list_free(struct pattern_list *list);
static int should_extract_path(struct archive *matching, const char *path);
static char *join_prefix_path(const char *prefix, const char *path);
static int has_include_descendant(const struct pattern_list *includes,
                                  const char *path);

static int pkg_getopt(int *argc, char ***argv, const char **arg) {
  enum { state_start = 0, state_next_word, state_short, state_long };
  static int state = state_start;
  static char *opt_word;
  const char *p;
  const struct option *popt, *match, *match2;
  size_t optlength;
  int opt;
  int required;

again:
  match = NULL;
  match2 = NULL;
  opt = '?';
  required = 0;
  *arg = NULL;

  if (state == state_start) {
    ++(*argv);
    --(*argc);
    state = state_next_word;
  }

  if (state == state_next_word) {
    if ((*argv)[0] == NULL) {
      return (-1);
    }
    if ((*argv)[0][0] != '-') {
      return (-1);
    }
    if (strcmp((*argv)[0], "--") == 0) {
      ++(*argv);
      --(*argc);
      return (-1);
    }
    opt_word = *(*argv)++;
    --(*argc);
    if (opt_word[1] == '-') {
      state = state_long;
      opt_word += 2;
    } else {
      state = state_short;
      opt_word += 1;
    }
  }

  if (state == state_short) {
    opt = *opt_word++;
    p = strchr(short_options, opt);
    if (p == NULL) {
      return ('?');
    }
    if (p[1] == ':') {
      required = 1;
    }
    if (*opt_word == '\0') {
      state = state_next_word;
    }
    if (required) {
      if (*opt_word != '\0') {
        *arg = opt_word;
        state = state_next_word;
      } else if ((*argv)[0] == NULL) {
        return ('?');
      } else {
        *arg = *(*argv)++;
        --(*argc);
        state = state_next_word;
      }
    }
    return (opt);
  }

  if (state == state_long) {
    optlength = strcspn(opt_word, "=");
    for (popt = pkg_longopts; popt->name != NULL; popt++) {
      if (strncmp(opt_word, popt->name, optlength) != 0) {
        continue;
      }
      if (strlen(popt->name) == optlength) {
        match = popt;
        break;
      }
      if (match == NULL) {
        match = popt;
      } else {
        match2 = popt;
      }
    }
    if (match == NULL) {
      return ('?');
    }
    if (match2 != NULL) {
      return ('?');
    }
    opt = match->equivalent;
    required = match->required;
    if (required) {
      if (opt_word[optlength] == '=') {
        *arg = opt_word + optlength + 1;
      } else if ((*argv)[0] == NULL) {
        return ('?');
      } else {
        *arg = *(*argv)++;
        --(*argc);
      }
    }
    state = state_next_word;
    return (opt);
  }

  goto again;
}

struct astream {
  struct archive *a;
  const unsigned char *blk;
  size_t blksz;
  size_t pos;
  la_int64_t off;
  int eof;
};

static int astream_fill(struct astream *s) {
  int r;

  if (s->eof) {
    return (ARCHIVE_EOF);
  }

  r = archive_read_data_block(s->a, (const void **)&s->blk, &s->blksz, &s->off);
  s->pos = 0;
  if (r == ARCHIVE_EOF) {
    s->eof = 1;
    return (ARCHIVE_EOF);
  }
  if (r != ARCHIVE_OK) {
    return (r);
  }

  return (ARCHIVE_OK);
}

static int astream_open_cb(struct archive *a, void *client_data) {
  (void)a;
  (void)client_data;
  return (ARCHIVE_OK);
}

static la_ssize_t astream_read_cb(struct archive *a, void *client_data,
                                  const void **buff) {
  struct astream *s = (struct astream *)client_data;
  if (s->eof) {
    return (0);
  }
  if (s->blk == NULL || s->pos == s->blksz) {
    int r = astream_fill(s);
    if (r == ARCHIVE_EOF) {
      return (0);
    }
    if (r != ARCHIVE_OK) {
      archive_set_error(a, archive_errno(s->a), "%s",
                        archive_error_string(s->a));
      return (-1);
    }
  }
  *buff = s->blk + s->pos;
  size_t avail = s->blksz - s->pos;
  s->pos = s->blksz;
  return ((la_ssize_t)avail);
}

static int astream_close_cb(struct archive *a, void *client_data) {
  (void)a;
  (void)client_data;
  return (ARCHIVE_OK);
}

static void extract_nested_archive_from_stream(struct astream *in,
                                               const char *outdir, int flags,
                                               struct archive *matching,
                                               int strip_components,
                                               const char *prefix) {
  struct archive *a = archive_read_new();
  struct archive *disk = archive_write_disk_new();
  struct archive_entry *e;
  int r;
  char *cwd = NULL;

  if (a == NULL || disk == NULL) {
    fail_errno("archive allocation");
  }

  archive_read_support_filter_all(a);
  archive_read_support_format_all(a);

  if (archive_read_open(a, in, astream_open_cb, astream_read_cb,
                        astream_close_cb) != ARCHIVE_OK) {
    fail_archive(a, "open nested archive");
  }

  archive_write_disk_set_options(disk, flags);
  archive_write_disk_set_standard_lookup(disk);

  cwd = getcwd(NULL, 0);
  if (cwd == NULL) {
    fail_errno("getcwd");
  }
  if (chdir(outdir) != 0) {
    fail_errno("chdir(outdir)");
  }

  for (;;) {
    r = archive_read_next_header(a, &e);
    if (r == ARCHIVE_EOF) {
      break;
    }
    if (r != ARCHIVE_OK) {
      fail_archive(a, "read nested header");
    }

    const char *p = archive_entry_pathname(e);
    char *rel = normalize_rel_path(p);
    archive_entry_set_pathname(e, rel);

    char *logical_path = join_prefix_path(prefix, rel);
    if (!should_extract_path(matching, logical_path)) {
      archive_read_data_skip(a);
      free(logical_path);
      free(rel);
      continue;
    }
    free(logical_path);

    if (apply_strip_components(e, strip_components)) {
      archive_read_data_skip(a);
      free(rel);
      continue;
    }

    r = archive_read_extract2(a, e, disk);
    if (r != ARCHIVE_OK) {
      free(rel);
      fail_archive(a, "extract nested entry");
    }
    free(rel);
  }

  archive_write_free(disk);
  archive_read_free(a);

  if (chdir(cwd) != 0) {
    fail_errno("chdir(cwd)");
  }
  free(cwd);
}

static int should_be_treated_as_nested_archive(const char *path) {
  if (path == NULL) {
    return (0);
  }
  const char *base = strrchr(path, '/');
  const char *name = base != NULL ? base + 1 : path;
  for (size_t i = 0; nested_archive_names[i] != NULL; i++) {
    if (strcmp(name, nested_archive_names[i]) == 0) {
      return (1);
    }
  }
  return (0);
}

static char *strip_components_path(const char *path, int strip) {
  const char *p = path;
  int remaining = strip;

  if (p == NULL) {
    return (NULL);
  }
  if (strip <= 0) {
    char *dup = strdup(p);
    if (dup == NULL) {
      fail_errno("strdup");
    }
    return (dup);
  }

  while (remaining > 0) {
    switch (*p++) {
    case '/':
#if defined(_WIN32) && !defined(__CYGWIN__)
    case '\\':
#endif
      remaining--;
      break;
    case '\0':
      return (NULL);
    }
  }

  for (;;) {
    switch (*p) {
    case '/':
#if defined(_WIN32) && !defined(__CYGWIN__)
    case '\\':
#endif
      ++p;
      break;
    case '\0':
      return (NULL);
    default: {
      char *out = strdup(p);
      if (out == NULL) {
        fail_errno("strdup");
      }
      return (out);
    }
    }
  }
}

static int apply_strip_components(struct archive_entry *e, int strip) {
  if (strip <= 0) {
    return (0);
  }

  const char *name = archive_entry_pathname(e);
  char *stripped = strip_components_path(name, strip);
  if (stripped == NULL) {
    return (1);
  }
  archive_entry_set_pathname(e, stripped);
  free(stripped);

  const char *hardlink = archive_entry_hardlink(e);
  if (hardlink != NULL) {
    stripped = strip_components_path(hardlink, strip);
    if (stripped == NULL) {
      return (1);
    }
    archive_entry_set_hardlink(e, stripped);
    free(stripped);
  }
  return (0);
}

static int path_component_count(const char *path) {
  int count = 0;
  int in_component = 0;

  if (path == NULL) {
    return (0);
  }

  for (const char *p = path; *p != '\0'; p++) {
    switch (*p) {
    case '/':
#if defined(_WIN32) && !defined(__CYGWIN__)
    case '\\':
#endif
      in_component = 0;
      break;
    default:
      if (!in_component) {
        count++;
        in_component = 1;
      }
      break;
    }
  }

  return (count);
}

static void pattern_list_add(struct pattern_list *list, const char *pattern) {
  if (list->len == list->cap) {
    size_t new_cap = list->cap == 0 ? 8 : list->cap * 2;
    char **new_items = realloc(list->items, new_cap * sizeof(*new_items));
    if (new_items == NULL) {
      fail_errno("realloc");
    }
    list->items = new_items;
    list->cap = new_cap;
  }
  char *dup = strdup(pattern);
  if (dup == NULL) {
    fail_errno("strdup");
  }
  list->items[list->len++] = dup;
}

static void pattern_list_free(struct pattern_list *list) {
  for (size_t i = 0; i < list->len; i++) {
    free(list->items[i]);
  }
  free(list->items);
  list->items = NULL;
  list->len = 0;
  list->cap = 0;
}

static int should_extract_path(struct archive *matching, const char *path) {
  struct archive_entry *entry = archive_entry_new();
  if (entry == NULL) {
    fail_errno("archive_entry_new");
  }
  archive_entry_set_pathname(entry, path);
  int excluded = archive_match_excluded(matching, entry);
  archive_entry_free(entry);
  if (excluded < 0) {
    fail_archive(matching, "archive_match_excluded");
  }
  return (excluded == 0);
}

static int has_include_descendant(const struct pattern_list *includes,
                                  const char *path) {
  size_t plen = strlen(path);
  for (size_t i = 0; i < includes->len; i++) {
    const char *pat = includes->items[i];
    if (strncmp(pat, path, plen) == 0 && pat[plen] == '/') {
      return (1);
    }
  }
  return (0);
}

static char *join_prefix_path(const char *prefix, const char *path) {
  if (prefix == NULL || prefix[0] == '\0' ||
      (prefix[0] == '.' && prefix[1] == '\0')) {
    char *dup = strdup(path);
    if (dup == NULL) {
      fail_errno("strdup");
    }
    return (dup);
  }
  size_t plen = strlen(prefix);
  size_t path_len = strlen(path);
  size_t total = plen + 1 + path_len + 1;
  char *buf = malloc(total);
  if (buf == NULL) {
    fail_errno("malloc");
  }
  memcpy(buf, prefix, plen);
  buf[plen] = '/';
  memcpy(buf + plen + 1, path, path_len + 1);
  return (buf);
}

static int contains_dotdot_segment(const char *path) {
  const char *p = path;
  while (*p != '\0') {
    while (*p == '/') {
      p++;
    }
    const char *seg = p;
    while (*p != '\0' && *p != '/') {
      p++;
    }
    size_t len = (size_t)(p - seg);
    if (len == 2 && seg[0] == '.' && seg[1] == '.') {
      return (1);
    }
  }
  return (0);
}

static char *normalize_rel_path(const char *path) {
  const char *rel = path;
  if (rel == NULL) {
    fprintf(stderr, "entry has empty pathname\n");
    exit(1);
  }
  if (rel[0] == '.' && rel[1] == '/') {
    rel += 2;
  }
  if (rel[0] == '\0') {
    fprintf(stderr, "entry has empty pathname\n");
    exit(1);
  }
  if (rel[0] == '/') {
    fprintf(stderr, "entry pathname is absolute: %s\n", rel);
    exit(1);
  }
  if (contains_dotdot_segment(rel)) {
    fprintf(stderr, "entry pathname contains '..': %s\n", rel);
    exit(1);
  }
  char *dup = strdup(rel);
  if (dup == NULL) {
    fail_errno("strdup");
  }
  return (dup);
}

static void mkdirs_for_path(const char *path) {
  char *tmp = strdup(path);
  if (tmp == NULL) {
    fail_errno("strdup");
  }
  size_t len = strlen(tmp);
  while (len > 1 && tmp[len - 1] == '/') {
    tmp[len - 1] = '\0';
    len--;
  }
  for (char *p = tmp + 1; *p != '\0'; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        free(tmp);
        fail_errno("mkdir(parent)");
      }
      *p = '/';
    }
  }
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
    free(tmp);
    fail_errno("mkdir(path)");
  }
  free(tmp);
}

static void ensure_outdir(const char *outdir, int force) {
  if (outdir == NULL || outdir[0] == '\0') {
    fail_errno("invalid output directory");
  }
  if (access(outdir, F_OK) == 0) {
    return;
  }
  if (mkdir(outdir, 0755) != 0) {
    fail_errno("mkdir(outdir)");
  }
}

int main(int argc, char **argv) {
  const char *xar_path = NULL;
  const char *outdir = NULL;
  struct archive *xar;
  struct archive *matching;
  struct pattern_list includes = {0};
  struct archive *disk;
  struct archive_entry *e;
  int r;
  int opt;
  const char *arg;
  int force = 0;
  int do_expand = 0;
  int do_expand_full = 0;
  int strip_components = 0;
  int flags;

  matching = archive_match_new();
  if (matching == NULL) {
    fail_errno("archive_match_new");
  }

  while ((opt = pkg_getopt(&argc, &argv, &arg)) != -1) {
    switch (opt) {
    case 'f':
      force = 1;
      break;
    case 'h':
      usage(stdout);
      return (0);
    case 'v':
      break;
    case 'X':
      do_expand = 1;
      break;
    case 'E':
      do_expand_full = 1;
      break;
    case opt_include:
      pattern_list_add(&includes, arg);
      if (archive_match_include_pattern(matching, arg) != ARCHIVE_OK) {
        fail_archive(matching, "archive_match_include_pattern");
      }
      break;
    case opt_exclude:
      if (archive_match_exclude_pattern(matching, arg) != ARCHIVE_OK) {
        fail_archive(matching, "archive_match_exclude_pattern");
      }
      break;
    case opt_strip_components:
      strip_components = atoi(arg);
      if (strip_components < 0) {
        fprintf(stderr, "invalid strip-components: %s\n", arg);
        return (2);
      }
      break;
    default:
      usage(stderr);
      return (2);
    }
  }

  if (!do_expand && !do_expand_full) {
    usage(stderr);
    return (2);
  }

  if (argc != 2) {
    usage(stderr);
    return (2);
  }

  xar_path = argv[0];
  outdir = argv[1];

  ensure_outdir(outdir, force);

  xar = archive_read_new();
  if (xar == NULL) {
    fail_errno("archive_read_new");
  }

  disk = archive_write_disk_new();
  if (disk == NULL) {
    fail_errno("archive_write_disk_new");
  }

  flags = disk_flags;
  if (force) {
    flags |= ARCHIVE_EXTRACT_UNLINK;
  }
  // Force no-same-owner behavior
  flags &= ~ARCHIVE_EXTRACT_OWNER;

  flags &= ~(ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
              ARCHIVE_EXTRACT_XATTR | ARCHIVE_EXTRACT_FFLAGS);
#ifdef ARCHIVE_EXTRACT_MAC_METADATA
  flags &= ~ARCHIVE_EXTRACT_MAC_METADATA;
#endif
  archive_write_disk_set_options(disk, flags);
  archive_write_disk_set_standard_lookup(disk);

  archive_read_support_filter_all(xar);
  archive_read_support_format_xar(xar);

  if (strcmp(xar_path, "-") == 0) {
    r = archive_read_open_fd(xar, 0, 10240);
  } else {
    r = archive_read_open_filename(xar, xar_path, 10240);
  }
  if (r != ARCHIVE_OK) {
    fail_archive(xar, "open xar");
  }

  if (chdir(outdir) != 0) {
    fail_errno("chdir(outdir)");
  }

  if (archive_match_set_inclusion_recursion(matching, 1) != ARCHIVE_OK) {
    fail_archive(matching, "archive_match_set_inclusion_recursion");
  }

  while ((r = archive_read_next_header(xar, &e)) == ARCHIVE_OK) {
    const char *p = archive_entry_pathname(e);
    char *rel = normalize_rel_path(p);
    archive_entry_set_pathname(e, rel);
    int is_nested = should_be_treated_as_nested_archive(rel);
    if (do_expand_full && is_nested) {
      char *logical_path = join_prefix_path(NULL, rel);
      int include_nested = should_extract_path(matching, logical_path);
      if (!include_nested && includes.len > 0 &&
          has_include_descendant(&includes, logical_path)) {
        include_nested = 1;
      }
      free(logical_path);
      if (!include_nested) {
        archive_read_data_skip(xar);
        free(rel);
        continue;
      }

      char *nested_outdir = strip_components_path(rel, strip_components);
      int nested_strip = strip_components;
      int rel_components = path_component_count(rel);

      if (nested_outdir == NULL) {
        nested_outdir = strdup(".");
        if (nested_outdir == NULL) {
          fail_errno("strdup");
        }
      }
      if (nested_strip > rel_components) {
        nested_strip -= rel_components;
      } else {
        nested_strip = 0;
      }

      mkdirs_for_path(nested_outdir);

      {
        struct astream in = {
            .a = xar,
            .blk = NULL,
            .blksz = 0,
            .pos = 0,
            .off = 0,
            .eof = 0,
        };

        extract_nested_archive_from_stream(&in, nested_outdir, flags, matching,
                                           nested_strip, rel);
      }
      free(nested_outdir);
      free(rel);
    } else {
      char *logical_path = join_prefix_path(NULL, rel);
      if (!should_extract_path(matching, logical_path)) {
        archive_read_data_skip(xar);
        free(logical_path);
        free(rel);
        continue;
      }
      free(logical_path);
      if (apply_strip_components(e, strip_components)) {
        archive_read_data_skip(xar);
        free(rel);
        continue;
      }
      r = archive_read_extract2(xar, e, disk);
      if (r != ARCHIVE_OK) {
        free(rel);
        fail_archive(xar, "extract entry");
      }
      free(rel);
    }
  }

  archive_write_free(disk);
  archive_read_free(xar);
  archive_match_free(matching);
  pattern_list_free(&includes);
  return (0);
}
