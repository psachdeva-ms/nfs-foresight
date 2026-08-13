#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";

#define THRESH   1000
#define MAXCOMP  16
#define NAMELEN  64

// 1 = stop counting once THRESH crossed
// 0 = original: full count to EOF
#define EARLY_LARGE_CUT 1

struct dir_info {
	__u64 file_count;
	__u64 i_size;
	__u64 ino;
	__u64 last_seen;
	char  path[256];
	__u32 dev;
	__u32 open_refcount;
	__u8  is_large;
	__u8  active;
	__u8  ever_large;
	__s8  state;
	__u8  recount;
};

struct scratch {
	// (u64)inode -> row to write at EOF
	__u64 dir_key;
	// (u64)file  -> walk identity
	__u64 file_ptr;
	// entries this walk (private, no atomic)
	__u64 walk_count;
	// entries this getdents batch (EOF detect)
	__u32 batch_emits;
	// walk started at pos==0
	__u8  clean;
	// early-cut: this walk has stopped counting
	__u8  stop;
};

struct open_event {
	__u64 key;
	__u32 mnt_id;
	__u8  ncomp;
	char  comp[MAXCOMP][NAMELEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct dir_info);
} nfs_dirs SEC(".maps");

// per-task: collision-proof, auto-freed on task exit
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	// required for task storage
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scratch);
} tid_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

// per-directory getattr MISS counting, sliding 30s window
// 1s buckets -> covers 64s (serves the 30s window)
#define GATTR_SLOTS 64

struct gattr_slot {
	__s32 miss;
	// CLOCK_MONOTONIC second this slot represents
	__u32 epoch;
};
struct gattr_stats {
	struct gattr_slot ring[GATTR_SLOTS];
	// CLOCK_MONOTONIC second; skip counting misses until then
	__u32 suppress_until;
};

// keyed by directory inode ptr; created lazily for large dirs only
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct gattr_stats);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dir_gattr_stats SEC(".maps");

// zeroed source for lazy inserts: gattr_stats is too big for the 512B BPF stack
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gattr_stats);
} gattr_zero SEC(".maps");

// per-tid bridge: are we inside a tracked nfs_getattr, and did it miss?
struct gattr_ctx {
	__u64 dir_ino;
	__u8  saw_miss;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct gattr_ctx);
} tid_getattr SEC(".maps");

// record one server round-trip (getattr OR lookup miss) against a large dir
static __always_inline void record_miss(__u64 dir_key)
{
	struct dir_info *d = bpf_map_lookup_elem(&nfs_dirs, &dir_key);
	// only tracked large dirs
	if (!d || !d->ever_large)
		return;
	// keep eviction recency honest
	d->last_seen = bpf_ktime_get_ns();

	struct gattr_stats *st = bpf_map_lookup_elem(&dir_gattr_stats, &dir_key);
	if (!st) {
		__u32 z = 0;
		// per-cpu zeros (>512B won't fit BPF stack)
		struct gattr_stats *zero = bpf_map_lookup_elem(&gattr_zero, &z);
		if (!zero)
			return;
		bpf_map_update_elem(&dir_gattr_stats, &dir_key, zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&dir_gattr_stats, &dir_key);
		if (!st)
			return;
	}
	__u32 e = (__u32)(bpf_ktime_get_ns() / 1000000000ULL);
	// warming in progress -> hold at 0
	if (e < st->suppress_until)
		return;
	__u32 idx = e & (GATTR_SLOTS - 1);
	if (st->ring[idx].epoch != e) {
		st->ring[idx].epoch = e;
		st->ring[idx].miss  = 0;
	}
	st->ring[idx].miss += 1;
}

SEC("kprobe/nfs_opendir")
int BPF_KPROBE(k_open, struct inode *dir, struct file *filp)
{
	__u64 key = (__u64)dir;
	struct dir_info *v = bpf_map_lookup_elem(&nfs_dirs, &key);
	if (v) {
		// reuse existing row (dedup)
		__sync_fetch_and_add(&v->open_refcount, 1);
		v->active = 1;
		v->last_seen = bpf_ktime_get_ns();
		__u64 old = v->i_size;
		// fresh (cached) dir size
		__u64 nsz = BPF_CORE_READ(dir, i_size);
		v->i_size = nsz;
		if (v->ever_large)
			// recount only if shrank >= 3/4
			v->recount = (nsz < (old >> 2)) ? 1 : 0;
		return 0;
	}
	struct dir_info nv = {};
	nv.i_size        = BPF_CORE_READ(dir, i_size);
	nv.ino           = BPF_CORE_READ(dir, i_ino);
	nv.dev           = BPF_CORE_READ(dir, i_sb, s_dev);
	nv.open_refcount = 1;
	nv.active        = 1;
	nv.state         = 0;
	nv.last_seen     = bpf_ktime_get_ns();
	// -E2BIG under saturation: dropped
	bpf_map_update_elem(&nfs_dirs, &key, &nv, BPF_NOEXIST);

	struct open_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;
	e->key = key; e->ncomp = 0;
	struct vfsmount *vmnt = BPF_CORE_READ(filp, f_path.mnt);
	struct mount *m = container_of(vmnt, struct mount, mnt);
	e->mnt_id = BPF_CORE_READ(m, mnt_id);
	struct dentry *de = BPF_CORE_READ(filp, f_path.dentry);
#pragma unroll
for (int i = 0; i < MAXCOMP; i++) {
        struct dentry *parent = BPF_CORE_READ(de, d_parent);
        if (de == parent)
		// mount root
		break;
        const unsigned char *dname = BPF_CORE_READ(de, d_name.name);
        bpf_core_read_str(e->comp[i], NAMELEN, dname);
        e->ncomp = i + 1;
        de = parent;
}
bpf_ringbuf_submit(e, 0);
return 0;
}

SEC("kprobe/nfs_readdir")
int BPF_KPROBE(k_readdir, struct file *file, struct dir_context *dctx)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	__u64 key = (__u64)inode;
	struct dir_info *v = bpf_map_lookup_elem(&nfs_dirs, &key);
	if (!v)
		return 0;

	if (v->ever_large && !v->recount) {
		// known-large, no recount -> skip re-walk
		v->last_seen = bpf_ktime_get_ns();
		return 0;
	}

	v->state = 1;
	v->last_seen = bpf_ktime_get_ns();

	__u64 pos = BPF_CORE_READ(dctx, pos);
	struct task_struct *t = bpf_get_current_task_btf();
	struct scratch *s = bpf_task_storage_get(&tid_scratch, t, NULL, 0);
	if (pos == 0) {
		// new clean walk
		s = bpf_task_storage_get(&tid_scratch, t, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!s) return 0;
		// reset any stale per-task scratch
		__builtin_memset(s, 0, sizeof(*s));
		s->dir_key = key; s->file_ptr = (__u64)file; s->clean = 1;
#if EARLY_LARGE_CUT
		// recount forces a full count
		s->stop = (v->ever_large && !v->recount) ? 1 : 0;
#endif
	} else if (s) {
		// continuing walk -> new batch
		s->batch_emits = 0;
	} else {
		// started mid-stream (seek) -> untrusted
		s = bpf_task_storage_get(&tid_scratch, t, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!s) return 0;
		__builtin_memset(s, 0, sizeof(*s));
		s->dir_key = key; s->file_ptr = (__u64)file; s->clean = 0;
#if EARLY_LARGE_CUT
		s->stop = (v->ever_large && !v->recount) ? 1 : 0;
#endif
	}
	return 0;
}

SEC("kprobe/filldir64")
int BPF_KPROBE(k_fill)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct scratch *s = bpf_task_storage_get(&tid_scratch, t, NULL, 0);
	if (!s) return 0;
#if EARLY_LARGE_CUT
	// known large: cheapest path, no shared touch
	if (s->stop) return 0;
#endif
	// private per-walk counters, no shared write
	s->walk_count++;
	s->batch_emits++;
#if EARLY_LARGE_CUT
	if (s->walk_count > THRESH) {
		// crossing edge: mark row large ONCE
		struct dir_info *v = bpf_map_lookup_elem(&nfs_dirs, &s->dir_key);
		if (v) {
			// monotonic set -> race-safe
			v->is_large = 1;
			v->ever_large = 1;
		}
		s->stop = 1;
	}
#endif
	return 0;
}

SEC("kretprobe/nfs_readdir")
int BPF_KRETPROBE(kr_readdir)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct scratch *s = bpf_task_storage_get(&tid_scratch, t, NULL, 0);
	if (!s) return 0;
	if (s->batch_emits == 0) {
		if (s->clean) {
			struct dir_info *v = bpf_map_lookup_elem(&nfs_dirs, &s->dir_key);
			if (v) {
#if EARLY_LARGE_CUT
				if (!s->stop)
					v->file_count = s->walk_count;
				else if (s->walk_count > v->file_count)
					v->file_count = s->walk_count;
#else
				v->file_count = s->walk_count;
#endif
				v->is_large   = v->file_count > THRESH ? 1 : 0;
				v->ever_large = v->is_large;
				v->recount    = 0;
				v->state      = 2;
				v->last_seen  = bpf_ktime_get_ns();
				if (!v->ever_large && v->open_refcount == 0)
					// small + closed -> drop now
					bpf_map_delete_elem(&nfs_dirs, &s->dir_key);
			}
		}
		bpf_task_storage_delete(&tid_scratch, t);
	}
	// batch_emits > 0 => mid-walk: keep scratch for next batch
	return 0;
}

SEC("kprobe/nfs_closedir")
int BPF_KPROBE(k_close, struct inode *inode, struct file *filp)
{
	__u64 key = (__u64)inode;
	struct dir_info *v = bpf_map_lookup_elem(&nfs_dirs, &key);
	if (!v) return 0;
	if (v->open_refcount > 0)
		// decrement, ignore return
		__sync_fetch_and_add(&v->open_refcount, -1);
	if (v->open_refcount == 0)
		// re-read after decrement
		v->active = 0;
	v->last_seen = bpf_ktime_get_ns();
	if (!v->ever_large && v->state == 2 && v->open_refcount == 0)
		bpf_map_delete_elem(&nfs_dirs, &key);
	return 0;
}

// entry: resolve file->parent-dir; open a tid ctx only for tracked large dirs
SEC("kprobe/nfs_getattr")
int BPF_KPROBE(k_getattr, void *mnt_userns, const struct path *path)
{
	struct dentry *fdent = BPF_CORE_READ(path, dentry);
	struct inode  *dino  = BPF_CORE_READ(fdent, d_parent, d_inode);
	__u64 key = (__u64)dino;

	struct dir_info *d = bpf_map_lookup_elem(&nfs_dirs, &key);
	// only track large dirs
	if (!d || !d->ever_large)
		return 0;

	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct gattr_ctx c;
	// zero padding: verifier rejects uninit stack
	__builtin_memset(&c, 0, sizeof(c));
	c.dir_ino  = key;
	c.saw_miss = 0;
	bpf_map_update_elem(&tid_getattr, &tid, &c, BPF_ANY);
	return 0;
}

// the "went to the server" marker -- MUST be tid-scoped (called from other paths too)
SEC("kprobe/__nfs_revalidate_inode")
int BPF_KPROBE(k_reval)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct gattr_ctx *c = bpf_map_lookup_elem(&tid_getattr, &tid);
	if (c)
		c->saw_miss = 1;
	return 0;
}

// return: count server misses into the current 1s bucket (respect suppression)
SEC("kretprobe/nfs_getattr")
int BPF_KRETPROBE(kr_getattr, int ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct gattr_ctx *c = bpf_map_lookup_elem(&tid_getattr, &tid);
	if (!c)
		return 0;

	__u64 dir_ino  = c->dir_ino;
	__u8  saw_miss = c->saw_miss;
	bpf_map_delete_elem(&tid_getattr, &tid);

	if (!saw_miss)
		// hits: no longer tracked
		return 0;

	record_miss(dir_ino);
	return 0;
}

// dcache-miss lookup -> always a server LOOKUP RPC (the cold LOOKUP storm)
SEC("kprobe/nfs_lookup")
int BPF_KPROBE(k_lookup, struct inode *dir)
{
	record_miss((__u64)dir);
	return 0;
}

// revalidation that goes to the server -> also a LOOKUP RPC (cache-expiry re-lookup)
SEC("kprobe/nfs_lookup_revalidate_dentry")
int BPF_KPROBE(k_lookup_reval, struct inode *dir)
{
	record_miss((__u64)dir);
	return 0;
}

/* inode teardown (mid-life eviction AND unmount sweep) -> drop stale rows.
 * nfs_clear_inode is EXPORT_SYMBOL_GPL, called by both nfs_evict_inode (v3) and
 * nfs4_evict_inode (v4); on unmount evict_inodes() runs it per inode before
 * nfs_kill_super, so unmount is covered here too.
*/
SEC("kprobe/nfs_clear_inode")
int BPF_KPROBE(k_evict, struct inode *inode)
{
	__u64 key = (__u64)inode;
	// no-op miss for non-dir inodes
	bpf_map_delete_elem(&nfs_dirs, &key);
	// paired ring, same key
	bpf_map_delete_elem(&dir_gattr_stats, &key);
	return 0;
}
