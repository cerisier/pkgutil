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

#define BSIZE (8 * 1024)

static const char *short_options = "EfhvX";

static const struct option {
  const char *name;
  int required;
  int equivalent;
} pkg_longopts[] = {{"expand", 0, 'X'},
                    {"expand-full", 0, 'E'},
                    {"force", 0, 'f'},
                    {"help", 0, 'h'},
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
  fprintf(out, "Usage: pkgutil [OPTIONS] [COMMANDS] ...\n\n"
               "Options:\n"
               "  --help                 Show this usage guide\n"
               "  --verbose, -v          Show contextual information and "
               "format for easy reading\n"
               "  --force, -f            Perform all operations without asking "
               "for confirmation\n\n"
               "File Commands:\n"
               "  --expand PKG DIR       Write flat package entries to DIR\n"
               "  --expand-full PKG DIR  Fully expand package contents to DIR\n");
}

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
    if ((*argv)[0] == NULL)
      return (-1);
    if ((*argv)[0][0] != '-')
      return (-1);
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
    if (p == NULL)
      return ('?');
    if (p[1] == ':')
      required = 1;
    if (*opt_word == '\0')
      state = state_next_word;
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
      if (strncmp(opt_word, popt->name, optlength) != 0)
        continue;
      if (strlen(popt->name) == optlength) {
        match = popt;
        break;
      }
      if (match == NULL)
        match = popt;
      else
        match2 = popt;
    }
    if (match == NULL)
      return ('?');
    if (match2 != NULL)
      return ('?');
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

  if (s->eof)
    return (ARCHIVE_EOF);

  r = archive_read_data_block(s->a, (const void **)&s->blk, &s->blksz, &s->off);
  s->pos = 0;
  if (r == ARCHIVE_EOF) {
    s->eof = 1;
    return (ARCHIVE_EOF);
  }
  if (r != ARCHIVE_OK)
    return (r);

  return (ARCHIVE_OK);
}

static int astream_read(struct astream *s, void *out, size_t n) {
  unsigned char *p = (unsigned char *)out;
  while (n > 0) {
    if (s->blk == NULL || s->pos == s->blksz) {
      int r = astream_fill(s);
      if (r != ARCHIVE_OK)
        return (r);
    }
    if (s->eof)
      return (ARCHIVE_EOF);
    size_t avail = s->blksz - s->pos;
    size_t take = (avail < n) ? avail : n;
    memcpy(p, s->blk + s->pos, take);
    s->pos += take;
    p += take;
    n -= take;
  }
  return (ARCHIVE_OK);
}

static int read_exact(struct astream *s, void *out, size_t n) {
  int r = astream_read(s, out, n);
  return (r);
}

static int read_u64_be(struct astream *s, uint64_t *v) {
  uint64_t tmp;
  int r = read_exact(s, &tmp, sizeof(tmp));
  if (r != ARCHIVE_OK)
    return (r);
  *v = __builtin_bswap64(tmp);
  return (ARCHIVE_OK);
}

/*
 * Parse pbzx framing and write concatenated XZ streams to out.
 * This does not decompress.
 */
static int pbzx_deframe_to_file(struct astream *in, FILE *out) {
  unsigned char magic[4];
  uint64_t flags = 0;
  uint64_t length = 0;

  if (read_exact(in, magic, sizeof(magic)) != ARCHIVE_OK)
    return (ARCHIVE_FATAL);
  if (memcmp(magic, "pbzx", 4) != 0) {
    fprintf(stderr, "Not a pbzx stream\n");
    return (ARCHIVE_FATAL);
  }

  if (read_u64_be(in, &flags) != ARCHIVE_OK)
    return (ARCHIVE_FATAL);

  while (flags & (1ULL << 24)) {
    if (read_u64_be(in, &flags) != ARCHIVE_OK)
      return (ARCHIVE_FATAL);
    if (read_u64_be(in, &length) != ARCHIVE_OK)
      return (ARCHIVE_FATAL);

    unsigned char hdr[6];
    if (read_exact(in, hdr, sizeof(hdr)) != ARCHIVE_OK)
      return (ARCHIVE_FATAL);
    if (memcmp(hdr,
               "\xFD"
               "7zXZ\0",
               6) != 0) {
      fprintf(stderr, "Header is not <FD>7zXZ<00>\n");
      return (ARCHIVE_FATAL);
    }
    if (fwrite(hdr, 1, sizeof(hdr), out) != sizeof(hdr))
      return (ARCHIVE_FATAL);

    if (length < sizeof(hdr)) {
      fprintf(stderr, "pbzx chunk length too small\n");
      return (ARCHIVE_FATAL);
    }

    uint64_t remaining = length - sizeof(hdr);
    unsigned char buf[BSIZE];
    unsigned char tail[2] = {0, 0};

    while (remaining > 0) {
      size_t want = (remaining < sizeof(buf)) ? (size_t)remaining : sizeof(buf);
      if (read_exact(in, buf, want) != ARCHIVE_OK)
        return (ARCHIVE_FATAL);

      if (want >= 2) {
        tail[0] = buf[want - 2];
        tail[1] = buf[want - 1];
      } else if (want == 1) {
        tail[0] = tail[1];
        tail[1] = buf[0];
      }

      if (fwrite(buf, 1, want, out) != want)
        return (ARCHIVE_FATAL);
      remaining -= want;
    }

    if (!(tail[0] == 'Y' && tail[1] == 'Z')) {
      fprintf(stderr, "Footer is not YZ\n");
      return (ARCHIVE_FATAL);
    }
  }

  return (ARCHIVE_OK);
}

static void extract_cpio_xz_from_file(FILE *xz, const char *outdir, int force) {
  struct archive *a = archive_read_new();
  struct archive *disk = archive_write_disk_new();
  struct archive_entry *e;
  int r;
  int flags;

  if (a == NULL || disk == NULL)
    fail_errno("archive allocation");

  archive_read_support_filter_xz(a);
  archive_read_support_format_cpio(a);

  if (archive_read_open_FILE(a, xz) != ARCHIVE_OK)
    fail_archive(a, "open transformed stream 1");

  flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
          ARCHIVE_EXTRACT_XATTR | ARCHIVE_EXTRACT_FFLAGS |
          ARCHIVE_EXTRACT_SECURE_SYMLINKS | ARCHIVE_EXTRACT_SECURE_NODOTDOT;
  if (force)
    flags |= ARCHIVE_EXTRACT_UNLINK;

  archive_write_disk_set_options(disk, flags);
  archive_write_disk_set_standard_lookup(disk);

  if (chdir(outdir) != 0)
    fail_errno("chdir(outdir)");

  for (;;) {
    r = archive_read_next_header(a, &e);
    if (r == ARCHIVE_EOF)
      break;
    if (r != ARCHIVE_OK)
      fail_archive(a, "read cpio header");

    r = archive_read_extract2(a, e, disk);
    if (r != ARCHIVE_OK)
      fail_archive(a, "extract entry");
  }

  archive_write_free(disk);
  archive_read_free(a);
}

static int is_payload_path(const char *path) {
  const char *base;

  if (path == NULL)
    return (0);
  if (strcmp(path, "Payload") == 0)
    return (1);
  if (path[0] == '.' && path[1] == '/' && strcmp(path + 2, "Payload") == 0)
    return (1);
  base = strrchr(path, '/');
  if (base != NULL && strcmp(base + 1, "Payload") == 0)
    return (1);
  return (0);
}

static int write_entry_to_file(struct archive *a, FILE *out) {
  const void *buf;
  size_t size;
  la_int64_t offset;
  int r;

  while ((r = archive_read_data_block(a, &buf, &size, &offset)) == ARCHIVE_OK) {
    if (size > 0 && fwrite(buf, 1, size, out) != size)
      return (ARCHIVE_FATAL);
  }
  if (r == ARCHIVE_EOF)
    return (ARCHIVE_OK);
  return (r);
}

static char *make_output_path(const char *outdir, const char *path) {
  const char *rel = path;
  size_t outlen = strlen(outdir);
  size_t rellen;
  if (rel == NULL)
    rel = "";
  if (rel[0] == '.' && rel[1] == '/')
    rel += 2;
  rellen = strlen(rel);
  if (rellen == 0) {
    fprintf(stderr, "entry has empty pathname\n");
    exit(1);
  }
  if (strchr(rel, '/') != NULL) {
    fprintf(stderr, "entry pathname contains '/': %s\n", rel);
    exit(1);
  }
  size_t need = outlen + 1 + rellen + 1;
  char *full = (char *)malloc(need);
  if (full == NULL)
    fail_errno("malloc");
  snprintf(full, need, "%s/%s", outdir, rel);
  return (full);
}

static FILE *open_output_file(const char *outdir, const char *path, int force) {
  char *full = make_output_path(outdir, path);
  FILE *out;

  if (!force && access(full, F_OK) == 0) {
    fprintf(stderr, "%s: output exists (use --force to overwrite)\n", full);
    free(full);
    exit(1);
  }

  out = fopen(full, "wb");
  if (out == NULL) {
    free(full);
    fail_errno("fopen(output)");
  }

  free(full);
  return (out);
}

static void ensure_outdir(const char *outdir, int force) {
  if (outdir == NULL || outdir[0] == '\0')
    fail_errno("invalid output directory");
  if (access(outdir, F_OK) == 0) {
    return;
  }
  if (mkdir(outdir, 0755) != 0)
    fail_errno("mkdir(outdir)");
}

int main(int argc, char **argv) {
  const char *xar_path = NULL;
  const char *outdir = NULL;
  struct archive *xar;
  struct archive_entry *e;
  int r;
  int opt;
  const char *arg;
  int force = 0;
  int do_expand = 0;
  int do_expand_full = 0;

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
  if (xar == NULL)
    fail_errno("archive_read_new");

  archive_read_support_filter_all(xar);
  archive_read_support_format_xar(xar);

  if (strcmp(xar_path, "-") == 0)
    r = archive_read_open_fd(xar, 0, 10240);
  else
    r = archive_read_open_filename(xar, xar_path, 10240);
  if (r != ARCHIVE_OK)
    fail_archive(xar, "open xar");

  while ((r = archive_read_next_header(xar, &e)) == ARCHIVE_OK) {
    const char *p = archive_entry_pathname(e);
    FILE *tmp;
    int is_payload = is_payload_path(p);

    if (do_expand_full && is_payload) {
      tmp = tmpfile();
      if (tmp == NULL)
        fail_errno("tmpfile");

      {
        struct astream in = {
            .a = xar,
            .blk = NULL,
            .blksz = 0,
            .pos = 0,
            .off = 0,
            .eof = 0,
        };

        if (pbzx_deframe_to_file(&in, tmp) != ARCHIVE_OK) {
          fprintf(stderr, "pbzx deframe failed\n");
          fclose(tmp);
          return (1);
        }
      }

      fflush(tmp);
      rewind(tmp);
      extract_cpio_xz_from_file(tmp, outdir, force);
      fclose(tmp);
    } else {
      if (archive_entry_filetype(e) == AE_IFDIR) {
        char *full = make_output_path(outdir, p);
        if (mkdir(full, 0755) != 0 && errno != EEXIST) {
          free(full);
          fail_errno("mkdir(entry)");
        }
        free(full);
        continue;
      }

      tmp = open_output_file(outdir, p, force);
      r = write_entry_to_file(xar, tmp);
      if (r != ARCHIVE_OK) {
        fclose(tmp);
        fail_archive(xar, "read entry data");
      }
      fclose(tmp);
    }
  }

  archive_read_free(xar);
  return (0);
}
