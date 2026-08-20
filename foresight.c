#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "foresight.skel.h"

#define MAXE   16384
#define HIGH   (MAXE*80/100)          // start reclaiming
#define LOW    (MAXE*60/100)          // reclaim down to here
#define NS     1000000000ULL
#define TRANSIENT_MAXAGE    (30ULL*NS)
#define STALE_ACTIVE_MAXAGE (3600ULL*NS)

#define MAXCOMP 16
#define NAMELEN 64
struct open_event {
	__u64 key;
	__u32 mnt_id;
	__u8 ncomp;
	char comp[MAXCOMP][NAMELEN];
};
struct dir_info {
	__u64 file_count, i_size, ino, last_seen;
	char path[256];
	__u32 dev, open_refcount;
	__u8 is_large, active, ever_large;
	signed char state;
	__u8 recount;
};

#define GATTR_SLOTS 64
struct gattr_slot {
	int32_t gt_miss;
	int32_t lk_miss;
	int32_t pw_miss;
	uint32_t epoch;
};
struct gattr_stats {
	struct gattr_slot ring[GATTR_SLOTS];
	uint32_t suppress_until;
};

#define WINDOW_S      30
#define MISS_THRESH   20        // fire on > 20 misses in the 30s window
#define SUPPRESS_S    30        // hold misses at 0 for 30s from prewarm EOF
#define WARM_MAX      256       // concurrent tracked prewarms
#define PREWARM_BUFSZ (1U << 20)
#define PACE_US       50000     // item 3: inter-batch throttle (0 = full speed)

struct pw_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static uint32_t mono_secs(void) {
	// MUST match bpf_ktime_get_ns() -> CLOCK_MONOTONIC seconds
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)ts.tv_sec;
}

static int dirs_fd;
static int gstats_fd;
static int ppids_fd;
static int trace_only;   // NFS_DIRTRACK_TRACE_ONLY set -> observe only, never prewarm

static __u64 ktime_ns(void) {
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec*NS + ts.tv_nsec;
}

static int mnt_prefix(unsigned id, char *out, size_t n) {
	FILE *f = fopen("/proc/self/mountinfo","r"); if (!f) return -1;
	char line[1024], mp[512]; int mid;
	while (fgets(line,sizeof line,f))
		if (sscanf(line,"%d %*d %*s %*s %511s",&mid,mp)==2 && mid==(int)id) {
			snprintf(out,n,"%s",mp); fclose(f); return 0;
		}
	fclose(f);
	return -1;
}

static int on_open(void *ctx, void *data, size_t sz) {
	char p[256], prefix[512] = "";
	int i;
	size_t off = 0;
	struct dir_info v;
	struct open_event *e = data;
	if (bpf_map_lookup_elem(dirs_fd,&e->key,&v))
		// already evicted
		return 0;
	mnt_prefix(e->mnt_id,prefix,sizeof prefix);
	off += snprintf(p+off,sizeof(p)-off,"%s",prefix);
	for (i=e->ncomp-1; i>=0 && off<sizeof(p); i--)
		off += snprintf(p+off,sizeof(p)-off,"/%s",e->comp[i]);
	if (p[0]==0)
		snprintf(p,sizeof p,"/");
	snprintf(v.path,sizeof v.path,"%s",p);
	// write path back
	bpf_map_update_elem(dirs_fd,&e->key,&v,BPF_EXIST);
	return 0;
}

struct cand {
	__u64 key, last_seen, i_size;
};
static int by_size(const void *a, const void *b) {
	// smallest i_size first (cheapest to rebuild)
	__u64 x=((struct cand*)a)->i_size, y=((struct cand*)b)->i_size;
	return (x>y)-(x<y);
}

static void del_dir(__u64 key) {
	// delete dir row + its gattr ring in lockstep
	bpf_map_delete_elem(dirs_fd, &key);
	bpf_map_delete_elem(gstats_fd, &key);
}

/* drop getattr rings idle beyond the window; skip warming dirs (intentionally-zeroed ring) */
static void reap_gattr_rings(void) {
	uint32_t now = mono_secs();
	__u64 k = 0, next, to_del[256];
	int i, n = 0;
	uint32_t newest;
	struct gattr_stats st;
	while (bpf_map_get_next_key(gstats_fd, &k, &next) == 0) {
		if (bpf_map_lookup_elem(gstats_fd, &next, &st) == 0) {
			if (st.suppress_until > now) {
				// warming: keep
				k = next;
				continue;
			}
			newest = 0;
			for (i = 0; i < GATTR_SLOTS; i++)
				if (st.ring[i].epoch > newest)
					newest = st.ring[i].epoch;
			if ((newest == 0 || now - newest > WINDOW_S) && n < 256)
				to_del[n++] = next;
		}
		k = next;
	}
	for (i = 0; i < n; i++)
		bpf_map_delete_elem(gstats_fd, &to_del[i]);
}

static void reap(void) {
	int active, i;
	__u64 key=0, next, now;
	struct dir_info v;
	now=ktime_ns();
	static struct cand cand[MAXE]; int nc=0, count=0;
	while (bpf_map_get_next_key(dirs_fd,&key,&next)==0) {
		key=next;
		if (bpf_map_lookup_elem(dirs_fd,&key,&v))
			continue;
		count++;
		if (!v.ever_large && v.state!=2 && now - v.last_seen >
						   TRANSIENT_MAXAGE) {
			// (A) age out junk
			del_dir(key); count--;
			continue;
		}
		if (v.ever_large) {
			// (B) reap candidates
			active = v.active;
			if (active && now - v.last_seen > STALE_ACTIVE_MAXAGE)
				// leaked-refcount valve
				active = 0;
			if (!active && nc < MAXE) {
				cand[nc].key=key;
				cand[nc].last_seen=v.last_seen;
				cand[nc].i_size=v.i_size; nc++;
			}
		}
	}
	if (count > HIGH) {
		// (C) pressure only
		// smallest large dir first
		qsort(cand,nc,sizeof *cand,by_size);
		for (i=0; i<nc && count>LOW; i++) {
			del_dir(cand[i].key);
			count--;
		}
	}
}

/* ===== background prewarm: paced getdents+statx scan on a getattr/lookup-miss storm ===== */
struct warm_ent {
	__u64 dir_ino;
	pid_t pid;
};
static struct warm_ent warm_tab[WARM_MAX];

// one statx per batch re-arms NFS_INO_ADVISE_RDPLUS; force => FORCE_SYNC else DONT_SYNC
static int advise_rdplus(int fd, char *buf, ssize_t len, int force) {
	size_t off = 0;
	while (off < (size_t)len) {
		struct pw_dirent64 *de = (struct pw_dirent64 *)(buf + off);
		struct statx stx;
		off += de->d_reclen;
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		memset(&stx, 0, sizeof stx);
		if (syscall(SYS_statx, fd, de->d_name,
				AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
				(force ? AT_STATX_FORCE_SYNC : AT_STATX_DONT_SYNC),
				STATX_BASIC_STATS, &stx) == 0)
			return 0;
		if (errno != ENOENT && errno != ESTALE)
			return -errno;
	}
	return -ENOENT;
}

// read to EOF driving READDIRPLUS; pace_us throttles; first batch FORCE_SYNC to prime
static int prewarm_dir(const char *path, unsigned pace_us) {
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	char *buf = malloc(PREWARM_BUFSZ);
	if (!buf) { close(fd); return -ENOMEM; }
	int first = 1, ret = 0;
	ssize_t n;
	for (;;) {
		n = syscall(SYS_getdents64, fd, buf, PREWARM_BUFSZ);
		if (n <= 0)
			break;
		ret = advise_rdplus(fd, buf, n, first);
		if (ret)
			break;
		first = 0;
		if (pace_us)
			usleep(pace_us);
	}
	free(buf);
	close(fd);
	return n < 0 ? -errno : ret;
}

static struct warm_ent *warm_find(__u64 dir_ino) {
	int i;
	for (i = 0; i < WARM_MAX; i++)
		if (warm_tab[i].dir_ino == dir_ino)
			return &warm_tab[i];
	return NULL;
}
static struct warm_ent *warm_alloc(void) {
	int i;
	for (i = 0; i < WARM_MAX; i++)
		if (!warm_tab[i].dir_ino && !warm_tab[i].pid)
			return &warm_tab[i];
	return NULL;
}

// child exit: free slot; success -> suppress from EOF+30; failure -> allow retry
static void reap_prewarms(void) {
	int i, status;
	pid_t pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		__u32 tg = (__u32)pid;
		bpf_map_delete_elem(ppids_fd, &tg);
		for (i = 0; i < WARM_MAX; i++)
			if (warm_tab[i].pid == pid) {
				__u64 dir_ino = warm_tab[i].dir_ino;
				if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
					struct gattr_stats fresh;
					memset(&fresh, 0, sizeof fresh);
					fresh.suppress_until = mono_secs() + SUPPRESS_S;
					bpf_map_update_elem(gstats_fd, &dir_ino, &fresh, BPF_ANY);
				} else {
					fprintf(stderr, "prewarm failed dir_ino=0x%llx pid=%d\n",
						(unsigned long long)dir_ino, (int)pid);
				}
				warm_tab[i].pid = 0;
				warm_tab[i].dir_ino = 0;
				break;
			}
	}
}

static void maybe_prewarm(__u64 dir_ino) {
	pid_t pid;
	struct dir_info v;
	struct warm_ent *e = warm_find(dir_ino);
	if (e && e->pid)
		// already warming this dir
		return;
	// validate BEFORE reserving a slot
	if (bpf_map_lookup_elem(dirs_fd, &dir_ino, &v) || v.path[0] == 0)
		return;
	// item 5: skip if foreground closed the dir or went idle (kernel self-paces)
	if (!v.active || (ktime_ns() - v.last_seen) > (2ULL * NS))
		return;
	if (!e && !(e = warm_alloc()))
		// table full
		return;

	pid = fork();
	if (pid < 0)
		// slot uncommitted -> nothing to undo
		return;
	if (pid == 0)
		// tier1: paced + gated, FORCE_SYNC first batch, full-size batches
		_exit(prewarm_dir(v.path, PACE_US) == 0 ? 0 : 1);
	e->dir_ino = dir_ino;
	e->pid = pid;
	__u32 tg = (__u32)pid;
	__u8 one = 1;
	bpf_map_update_elem(ppids_fd, &tg, &one, BPF_ANY);
	printf("prewarm: scan %s  (dir_ino=0x%llx pid=%d)\n",
	           v.path, (unsigned long long)dir_ino, (int)pid);
}

static void gattr_scan(int gstats_fd, int do_print) {
	struct gattr_stats st;
	int i;
	long lk30, gt30, pw30;
	uint32_t age, e = mono_secs();
	__u64 key = 0, next;
	while (bpf_map_get_next_key(gstats_fd, &key, &next) == 0) {
		if (bpf_map_lookup_elem(gstats_fd, &next, &st) == 0) {
			lk30 = gt30 = pw30 = 0;
			for (i = 0; i < GATTR_SLOTS; i++) {
				if (st.ring[i].epoch == 0)
					continue;
				// unsigned: future/empty -> huge -> skipped
				age = e - st.ring[i].epoch;
				if (age < WINDOW_S) {
					lk30 += st.ring[i].lk_miss;
					gt30 += st.ring[i].gt_miss;
					pw30 += st.ring[i].pw_miss;
				}
			}
			// foreground misses drive the decision; prewarmer's own RPCs (pw) excluded.
			// suppression is set at prewarm completion (reap_prewarms), not here.
			if ((lk30 + gt30) > MISS_THRESH && st.suppress_until <= e && !trace_only)
				maybe_prewarm(next);
			if (do_print && (lk30 + gt30 + pw30))
				printf("dir_ino=0x%llx  30s lk=%ld gt=%ld pw=%ld%s\n",
				       (unsigned long long)next, lk30, gt30, pw30,
				       st.suppress_until > e ? "  [warming]" : "");
		}
		key = next;
	}
}

int main(void) {
	struct nfs_dirtrack_bpf *skel = nfs_dirtrack_bpf__open_and_load();
	__u64 last_reap, now;
	int tick = 0;
	if (!skel) {
		fprintf(stderr,"load failed\n");
		return 1;
	}
	if (nfs_dirtrack_bpf__attach(skel)) {
		fprintf(stderr,"attach failed\n");
		return 1;
	}
	dirs_fd = bpf_map__fd(skel->maps.nfs_dirs);
	// clear stale pin (the bug we hit)
	unlink("/sys/fs/bpf/nfs_dirs");
	if (bpf_map__pin(skel->maps.nfs_dirs,"/sys/fs/bpf/nfs_dirs")) {
		fprintf(stderr,"pin failed\n");
		return 1;
	}
	unlink("/sys/fs/bpf/nfs_dir_gattr");
	bpf_map__pin(skel->maps.dir_gattr_stats, "/sys/fs/bpf/nfs_dir_gattr");
	gstats_fd = bpf_map__fd(skel->maps.dir_gattr_stats);
	ppids_fd = bpf_map__fd(skel->maps.prewarm_pids);
	trace_only = getenv("NFS_DIRTRACK_TRACE_ONLY") != NULL;
	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(skel->maps.events), on_open, NULL, NULL);

	printf("running%s.  inspect: sudo bpftool map dump pinned /sys/fs/bpf/nfs_dirs\n",
	       trace_only ? " [TRACE-ONLY: no prewarm]" : "");
	last_reap = ktime_ns();
	// drains path events
	while (ring_buffer__poll(rb, 200) >= 0) {
		now = ktime_ns();
		// ~1s cadence
		if (now - last_reap >= NS) {
			reap(); last_reap = now;
			reap_prewarms();
			reap_gattr_rings();
			// trigger every ~1s, print every ~5s
			gattr_scan(gstats_fd, ++tick % 5 == 0);
		}
	}
	return 0;
}
