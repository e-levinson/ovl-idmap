/*
 * ovl_idmap_probe.c — report whether a file's owner is representable
 * in the current user namespace.
 *
 * The OverlayFS copy-up defect (fixed mainline 6.2, 4f11ada10d0a) hinged
 * on exactly this predicate: copy-up proceeded for lower files whose
 * st_uid/st_gid had no mapping in the mounter's userns, producing upper
 * dentries owned by the overflow id. This probe makes the precondition
 * visible from userspace: give it a path, it reports the file's ids,
 * the namespace's mappings, and whether copy-up of that file would be
 * ownership-consistent under a fixed kernel.
 *
 * build:  cc -O2 -o ovl_idmap_probe ovl_idmap_probe.c
 * usage:  ./ovl_idmap_probe /path/to/lower/file
 */
#define _GNU_SOURCE
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_MAP 3400

struct idmap {
    uint32_t count;
    struct { uint32_t first, lower, span; } e[MAX_MAP];
};

static int load_map(const char *path, struct idmap *m)
{
    FILE *f = fopen(path, "r");
    char line[256];
    if (!f)
        return -1;
    m->count = 0;
    while (fgets(line, sizeof line, f) && m->count < MAX_MAP) {
        unsigned long a, b, c;
        if (sscanf(line, "%lu %lu %lu", &a, &b, &c) == 3) {
            m->e[m->count].first = a;
            m->e[m->count].lower = b;
            m->e[m->count].span  = c;
            m->count++;
        }
    }
    fclose(f);
    return 0;
}

/* kernel semantics: id has a mapping in the ns if it falls inside an
 * extent. unmapped ids surface as overflow (65534/65533) via stat(2). */
static int has_mapping(const struct idmap *m, uint32_t id)
{
    for (uint32_t i = 0; i < m->count; i++)
        if (id >= m->e[i].first && id - m->e[i].first < m->e[i].span)
            return 1;
    return 0;
}

static void print_map(const char *name, const struct idmap *m)
{
    printf("  %s (%u extent%s):\n", name, m->count, m->count == 1 ? "" : "s");
    for (uint32_t i = 0; i < m->count; i++)
        printf("    %10u %10u %10u\n", m->e[i].first, m->e[i].lower, m->e[i].span);
    if (!m->count)
        printf("    (empty)\n");
}

int main(int argc, char **argv)
{
    struct stat st;
    struct idmap uid_map, gid_map;
    char p[128];

    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    if (stat(argv[1], &st) < 0)
        err(1, "stat %s", argv[1]);

    snprintf(p, sizeof p, "/proc/self/uid_map");
    if (load_map(p, &uid_map) < 0)
        err(1, "open %s", p);
    snprintf(p, sizeof p, "/proc/self/gid_map");
    if (load_map(p, &gid_map) < 0)
        err(1, "open %s", p);

    printf("file:      %s\n", argv[1]);
    printf("  uid:     %u (fs%u)\n", st.st_uid, st.st_uid);
    printf("  gid:     %u (fs%u)\n", st.st_gid, st.st_gid);
    printf("  mode:    %o\n", st.st_mode & 07777);
    if (st.st_mode & S_ISUID) printf("  setuid bit PRESENT\n");
    if ((st.st_mode & 0755) == 0755 || (st.st_mode & 0555) == 0555)
        printf("  executable: yes\n");

    printf("userns mappings:\n");
    print_map("uid_map", &uid_map);
    print_map("gid_map", &gid_map);

    int u = has_mapping(&uid_map, st.st_uid);
    int g = has_mapping(&gid_map, st.st_gid);
    printf("verdict:\n");
    printf("  uid %u mappable in current userns: %s\n", st.st_uid, u ? "yes" : "NO");
    printf("  gid %u mappable in current userns: %s\n", st.st_gid, g ? "yes" : "NO");
    if (!u || !g) {
        printf("  -> copy-up of this file would stamp an unmapped owner\n");
        printf("     (pre-6.2 kernels: proceeds; fixed kernels: -EOVERFLOW)\n");
        if (!u && (st.st_mode & S_ISUID))
            printf("  -> setuid + unmapped owner: the CVE-2023-0386 precondition\n");
    } else {
        printf("  -> ownership representable; copy-up consistent\n");
    }
    return (!u || !g) ? 1 : 0;
}
