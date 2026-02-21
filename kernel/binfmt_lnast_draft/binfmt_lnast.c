// SPDX-License-Identifier: GPL-2.0
/*
 * Experimental LNAST binfmt loader draft for Linux 6.x.
 *
 * Scope:
 * - Magic/version/header validation
 * - Capability-gated opcode dispatch
 * - Deterministic node execution loop shape
 *
 * Non-production by design:
 * - hash verification is a stub
 * - metadata bounds checks are minimal
 * - no seccomp/landlock auto-derivation yet
 */

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define LNA_MAGIC "LNA1"
#define LNA_VERSION 0x0001
#define LNA_MAX_FILE_SIZE (16 * 1024 * 1024)

#define LNA_CAP_IO   (1ULL << 0)
#define LNA_CAP_FS   (1ULL << 1)
#define LNA_CAP_NET  (1ULL << 2)
#define LNA_CAP_MEM  (1ULL << 3)
#define LNA_CAP_PROC (1ULL << 4)
#define LNA_CAP_SYNC (1ULL << 5)

#define LNA_OP_PRINT   0x0001
#define LNA_OP_READ    0x0002
#define LNA_OP_EXIT    0x0003
#define LNA_OP_ADD_U64 0x0100

struct lna_header {
	char magic[4];
	__le16 version;
	__le16 flags;
	u8 hash[32];
	__le64 cap_mask;
	__le32 symbol_count;
	__le32 node_count;
	__le32 child_count;
	__le32 metadata_count;
};

struct lna_node {
	__le16 opcode;
	__le16 arity;
	__le32 child_start;
	__le32 metadata_index;
};

struct lna_ctx {
	struct lna_header *hdr;
	struct lna_node *nodes;
	void *metadata;
	u64 cap_mask;
	u32 node_count;
	size_t file_size;
};

static int lna_verify_hash(void *data, size_t len, const u8 expected_hash[32])
{
	/* TODO: integrate BLAKE3-256 and compare against expected_hash. */
	(void)data;
	(void)len;
	(void)expected_hash;
	return 0;
}

static int lna_check_cap(const struct lna_ctx *ctx, u64 required)
{
	if (required == 0)
		return 0;
	if (!(ctx->cap_mask & required))
		return -EPERM;
	return 0;
}

static int lna_validate_node_offset(const struct lna_ctx *ctx, u32 off)
{
	size_t metadata_off = (size_t)((char *)ctx->metadata - (char *)ctx->hdr);

	if (metadata_off + off >= ctx->file_size)
		return -EINVAL;
	return 0;
}

static int lna_exec_node(struct lna_ctx *ctx, u32 idx)
{
	struct lna_node *n;
	u16 opcode;
	u32 metadata_index;

	if (idx >= ctx->node_count)
		return -EINVAL;

	n = &ctx->nodes[idx];
	opcode = le16_to_cpu(n->opcode);
	metadata_index = le32_to_cpu(n->metadata_index);

	if (lna_validate_node_offset(ctx, metadata_index))
		return -EINVAL;

	switch (opcode) {
	case LNA_OP_PRINT: {
		char *msg;
		long ret;

		ret = lna_check_cap(ctx, LNA_CAP_IO);
		if (ret)
			return (int)ret;

		msg = (char *)ctx->metadata + metadata_index;
		ret = ksys_write(1, msg, strnlen(msg, 4096));
		return ret < 0 ? (int)ret : 0;
	}
	case LNA_OP_READ:
		return lna_check_cap(ctx, LNA_CAP_IO);
	case LNA_OP_EXIT: {
		u64 *exit_code = (u64 *)((char *)ctx->metadata + metadata_index);

		do_exit((long)(*exit_code));
		return 0;
	}
	case LNA_OP_ADD_U64: {
		u64 *vals = (u64 *)((char *)ctx->metadata + metadata_index);

		vals[2] = vals[0] + vals[1];
		return 0;
	}
	default:
		return -EINVAL;
	}
}

static int lna_execute(struct lna_ctx *ctx)
{
	u32 i;
	int ret;

	for (i = 0; i < ctx->node_count; i++) {
		ret = lna_exec_node(ctx, i);
		if (ret)
			return ret;
	}

	return 0;
}

static int load_lna_binary(struct linux_binprm *bprm)
{
	struct lna_header *hdr;
	struct lna_ctx ctx;
	void *file_data;
	ssize_t nread;
	loff_t pos = 0;
	u32 node_count;
	size_t min_size;
	int ret;

	if (bprm->file->f_inode->i_size > LNA_MAX_FILE_SIZE)
		return -EFBIG;

	file_data = vmalloc(bprm->file->f_inode->i_size);
	if (!file_data)
		return -ENOMEM;

	nread = kernel_read(bprm->file, file_data, bprm->file->f_inode->i_size, &pos);
	if (nread < (ssize_t)sizeof(*hdr)) {
		ret = -ENOEXEC;
		goto out_free;
	}

	hdr = file_data;
	if (memcmp(hdr->magic, LNA_MAGIC, sizeof(hdr->magic))) {
		ret = -ENOEXEC;
		goto out_free;
	}

	if (le16_to_cpu(hdr->version) != LNA_VERSION) {
		ret = -EINVAL;
		goto out_free;
	}

	ret = lna_verify_hash(file_data, bprm->file->f_inode->i_size, hdr->hash);
	if (ret)
		goto out_free;

	node_count = le32_to_cpu(hdr->node_count);
	if (node_count == 0 || node_count > 65536) {
		ret = -EINVAL;
		goto out_free;
	}

	min_size = sizeof(*hdr) + (size_t)node_count * sizeof(struct lna_node);
	if (min_size > (size_t)bprm->file->f_inode->i_size) {
		ret = -EINVAL;
		goto out_free;
	}

	ctx.hdr = hdr;
	ctx.nodes = (struct lna_node *)((char *)file_data + sizeof(*hdr));
	ctx.metadata = (void *)((char *)ctx.nodes + node_count * sizeof(struct lna_node));
	ctx.cap_mask = le64_to_cpu(hdr->cap_mask);
	ctx.node_count = node_count;
	ctx.file_size = (size_t)bprm->file->f_inode->i_size;

	ret = lna_execute(&ctx);

out_free:
	vfree(file_data);
	return ret;
}

static struct linux_binfmt lna_format = {
	.module = THIS_MODULE,
	.load_binary = load_lna_binary,
};

static int __init lna_init(void)
{
	int ret = register_binfmt(&lna_format);

	if (!ret)
		pr_info("lnast: binfmt registered\n");
	return ret;
}

static void __exit lna_exit(void)
{
	unregister_binfmt(&lna_format);
	pr_info("lnast: binfmt unregistered\n");
}

module_init(lna_init);
module_exit(lna_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Experimental Linux Native AST (LNAST) binfmt loader");
MODULE_AUTHOR("LINUX-AST");
