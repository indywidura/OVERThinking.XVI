// SPDX-License-Identifier: GPL-2.0
/*
 * Encryption policy functions for per-file encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 * Copyright (C) 2015, Motorola Mobility.
 *
 * Originally written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 * Modified by Eric Biggers, 2019 for v2 policy support.
 */

#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/mount.h>
#include <linux/hie.h>
#include "fscrypt_private.h"

/**
 * fscrypt_policies_equal() - check whether two encryption policies are the same
 * @policy1: the first policy
 * @policy2: the second policy
 *
 * Return: %true if equal, else %false
 */
static bool is_encryption_context_consistent_with_policy(
				const struct fscrypt_context *ctx,
				const struct fscrypt_policy *policy,
				const struct inode *inode)
{

	if ((ctx->contents_encryption_mode !=
		 policy->contents_encryption_mode) &&
		!(hie_is_capable(inode->i_sb) &&
		 (ctx->contents_encryption_mode ==
		 FS_ENCRYPTION_MODE_PRIVATE)))
		return 0;

	return memcmp(ctx->master_key_descriptor, policy->master_key_descriptor,
		      FS_KEY_DESCRIPTOR_SIZE) == 0 &&
		(ctx->flags == policy->flags) &&
		(ctx->filenames_encryption_mode ==
		 policy->filenames_encryption_mode);
bool fscrypt_policies_equal(const union fscrypt_policy *policy1,
			    const union fscrypt_policy *policy2)
{
	if (policy1->version != policy2->version)
		return false;

	return !memcmp(policy1, policy2, fscrypt_policy_size(policy1));
}

static bool fscrypt_valid_enc_modes(u32 contents_mode, u32 filenames_mode)
{
	if (contents_mode == FSCRYPT_MODE_AES_256_XTS &&
	    filenames_mode == FSCRYPT_MODE_AES_256_CTS)
		return true;

	if (contents_mode == FSCRYPT_MODE_AES_128_CBC &&
	    filenames_mode == FSCRYPT_MODE_AES_128_CTS)
		return true;

	if (contents_mode == FSCRYPT_MODE_ADIANTUM &&
	    filenames_mode == FSCRYPT_MODE_ADIANTUM)
		return true;

	return false;
}

static bool supported_direct_key_modes(const struct inode *inode,
				       u32 contents_mode, u32 filenames_mode)
{
	const struct fscrypt_mode *mode;

	if (contents_mode != filenames_mode) {
		fscrypt_warn(inode,
			     "Direct key flag not allowed with different contents and filenames modes");
		return false;
	}
	mode = &fscrypt_modes[contents_mode];

	if (mode->ivsize < offsetofend(union fscrypt_iv, nonce)) {
		fscrypt_warn(inode, "Direct key flag not allowed with %s",
			     mode->friendly_name);
		return false;
	}
	return true;
}

static bool supported_iv_ino_lblk_policy(const struct fscrypt_policy_v2 *policy,
					 const struct inode *inode,
					 const char *type,
					 int max_ino_bits, int max_lblk_bits)
{
	struct super_block *sb = inode->i_sb;
	int ino_bits = 64, lblk_bits = 64;

	/*
	 * It's unsafe to include inode numbers in the IVs if the filesystem can
	 * potentially renumber inodes, e.g. via filesystem shrinking.
	 */
	if (!sb->s_cop->has_stable_inodes ||
	    !sb->s_cop->has_stable_inodes(sb)) {
		fscrypt_warn(inode,
			     "Can't use %s policy on filesystem '%s' because it doesn't have stable inode numbers",
			     type, sb->s_id);
		return false;
	}
	if (sb->s_cop->get_ino_and_lblk_bits)
		sb->s_cop->get_ino_and_lblk_bits(sb, &ino_bits, &lblk_bits);
	if (ino_bits > max_ino_bits) {
		fscrypt_warn(inode,
			     "Can't use %s policy on filesystem '%s' because its inode numbers are too long",
			     type, sb->s_id);
		return false;
	}
	if (lblk_bits > max_lblk_bits) {
		fscrypt_warn(inode,
			     "Can't use %s policy on filesystem '%s' because its block numbers are too long",
			     type, sb->s_id);
		return false;
	}
	return true;
}

static bool fscrypt_supported_v1_policy(const struct fscrypt_policy_v1 *policy,
					const struct inode *inode)
{
	if (!fscrypt_valid_enc_modes(policy->contents_encryption_mode,
				     policy->filenames_encryption_mode)) {
		fscrypt_warn(inode,
			     "Unsupported encryption modes (contents %d, filenames %d)",
			     policy->contents_encryption_mode,
			     policy->filenames_encryption_mode);
		return false;
	}

	if (policy->flags & ~(FSCRYPT_POLICY_FLAGS_PAD_MASK |
			      FSCRYPT_POLICY_FLAG_DIRECT_KEY)) {
		fscrypt_warn(inode, "Unsupported encryption flags (0x%02x)",
			     policy->flags);
		return false;
	}

	if ((policy->flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY) &&
	    !supported_direct_key_modes(inode, policy->contents_encryption_mode,
					policy->filenames_encryption_mode))
		return false;

	if (IS_CASEFOLDED(inode)) {
		/* With v1, there's no way to derive dirhash keys. */
		fscrypt_warn(inode,
			     "v1 policies can't be used on casefolded directories");
		return false;
	}

	return true;
}

static bool fscrypt_supported_v2_policy(const struct fscrypt_policy_v2 *policy,
					const struct inode *inode)
{
	int count = 0;

	if (!fscrypt_valid_enc_modes(policy->contents_encryption_mode,
				     policy->filenames_encryption_mode)) {
		fscrypt_warn(inode,
			     "Unsupported encryption modes (contents %d, filenames %d)",
			     policy->contents_encryption_mode,
			     policy->filenames_encryption_mode);
		return false;
	}

	if (policy->flags & ~FSCRYPT_POLICY_FLAGS_VALID) {
		fscrypt_warn(inode, "Unsupported encryption flags (0x%02x)",
			     policy->flags);
		return false;
	}

	count += !!(policy->flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY);
	count += !!(policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64);
	count += !!(policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32);
	if (count > 1) {
		fscrypt_warn(inode, "Mutually exclusive encryption flags (0x%02x)",
			     policy->flags);
		return false;
	}

	if ((policy->flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY) &&
	    !supported_direct_key_modes(inode, policy->contents_encryption_mode,
					policy->filenames_encryption_mode))
		return false;

	if ((policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64) &&
	    !supported_iv_ino_lblk_policy(policy, inode, "IV_INO_LBLK_64",
					  32, 32))
		return false;

	if ((policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32) &&
	    /* This uses hashed inode numbers, so ino_bits doesn't matter. */
	    !supported_iv_ino_lblk_policy(policy, inode, "IV_INO_LBLK_32",
					  INT_MAX, 32))
		return false;

	if (memchr_inv(policy->__reserved, 0, sizeof(policy->__reserved))) {
		fscrypt_warn(inode, "Reserved bits set in encryption policy");
		return false;
	}

	return true;
}

/**
 * fscrypt_supported_policy() - check whether an encryption policy is supported
 * @policy_u: the encryption policy
 * @inode: the inode on which the policy will be used
 *
 * Given an encryption policy, check whether all its encryption modes and other
 * settings are supported by this kernel on the given inode.  (But we don't
 * currently don't check for crypto API support here, so attempting to use an
 * algorithm not configured into the crypto API will still fail later.)
 *
 * Return: %true if supported, else %false
 */
bool fscrypt_supported_policy(const union fscrypt_policy *policy_u,
			      const struct inode *inode)
{
	switch (policy_u->version) {
	case FSCRYPT_POLICY_V1:
		return fscrypt_supported_v1_policy(&policy_u->v1, inode);
	case FSCRYPT_POLICY_V2:
		return fscrypt_supported_v2_policy(&policy_u->v2, inode);
	}
	return false;
}

/**
 * fscrypt_new_context_from_policy() - create a new fscrypt_context from
 *				       an fscrypt_policy
 * @ctx_u: output context
 * @policy_u: input policy
 *
 * Create an fscrypt_context for an inode that is being assigned the given
 * encryption policy.  A new nonce is randomly generated.
 *
 * Return: the size of the new context in bytes.
 */
static int fscrypt_new_context_from_policy(union fscrypt_context *ctx_u,
					   const union fscrypt_policy *policy_u)
{
	memset(ctx_u, 0, sizeof(*ctx_u));

	switch (policy_u->version) {
	case FSCRYPT_POLICY_V1: {
		const struct fscrypt_policy_v1 *policy = &policy_u->v1;
		struct fscrypt_context_v1 *ctx = &ctx_u->v1;

		ctx->version = FSCRYPT_CONTEXT_V1;
		ctx->contents_encryption_mode =
			policy->contents_encryption_mode;
		ctx->filenames_encryption_mode =
			policy->filenames_encryption_mode;
		ctx->flags = policy->flags;
		memcpy(ctx->master_key_descriptor,
		       policy->master_key_descriptor,
		       sizeof(ctx->master_key_descriptor));
		get_random_bytes(ctx->nonce, sizeof(ctx->nonce));
		return sizeof(*ctx);
	}
	case FSCRYPT_POLICY_V2: {
		const struct fscrypt_policy_v2 *policy = &policy_u->v2;
		struct fscrypt_context_v2 *ctx = &ctx_u->v2;

		ctx->version = FSCRYPT_CONTEXT_V2;
		ctx->contents_encryption_mode =
			policy->contents_encryption_mode;
		ctx->filenames_encryption_mode =
			policy->filenames_encryption_mode;
		ctx->flags = policy->flags;
		memcpy(ctx->master_key_identifier,
		       policy->master_key_identifier,
		       sizeof(ctx->master_key_identifier));
		get_random_bytes(ctx->nonce, sizeof(ctx->nonce));
		return sizeof(*ctx);
	}
	}
	BUG();
}

/**
 * fscrypt_policy_from_context() - convert an fscrypt_context to
 *				   an fscrypt_policy
 * @policy_u: output policy
 * @ctx_u: input context
 * @ctx_size: size of input context in bytes
 *
 * Given an fscrypt_context, build the corresponding fscrypt_policy.
 *
 * Return: 0 on success, or -EINVAL if the fscrypt_context has an unrecognized
 * version number or size.
 *
 * This does *not* validate the settings within the policy itself, e.g. the
 * modes, flags, and reserved bits.  Use fscrypt_supported_policy() for that.
 */
int fscrypt_policy_from_context(union fscrypt_policy *policy_u,
				const union fscrypt_context *ctx_u,
				int ctx_size)
{
	memset(policy_u, 0, sizeof(*policy_u));

	if (!fscrypt_context_is_valid(ctx_u, ctx_size))
		return -EINVAL;

	switch (ctx_u->version) {
	case FSCRYPT_CONTEXT_V1: {
		const struct fscrypt_context_v1 *ctx = &ctx_u->v1;
		struct fscrypt_policy_v1 *policy = &policy_u->v1;

		policy->version = FSCRYPT_POLICY_V1;
		policy->contents_encryption_mode =
			ctx->contents_encryption_mode;
		policy->filenames_encryption_mode =
			ctx->filenames_encryption_mode;
		policy->flags = ctx->flags;
		memcpy(policy->master_key_descriptor,
		       ctx->master_key_descriptor,
		       sizeof(policy->master_key_descriptor));
		return 0;
	}
	case FSCRYPT_CONTEXT_V2: {
		const struct fscrypt_context_v2 *ctx = &ctx_u->v2;
		struct fscrypt_policy_v2 *policy = &policy_u->v2;

		policy->version = FSCRYPT_POLICY_V2;
		policy->contents_encryption_mode =
			ctx->contents_encryption_mode;
		policy->filenames_encryption_mode =
			ctx->filenames_encryption_mode;
		policy->flags = ctx->flags;
		memcpy(policy->__reserved, ctx->__reserved,
		       sizeof(policy->__reserved));
		memcpy(policy->master_key_identifier,
		       ctx->master_key_identifier,
		       sizeof(policy->master_key_identifier));
		return 0;
	}
	}
	/* unreachable */
	return -EINVAL;
}

/* Retrieve an inode's encryption policy */
static int fscrypt_get_policy(struct inode *inode, union fscrypt_policy *policy)
{
	const struct fscrypt_info *ci;
	union fscrypt_context ctx;
	int ret;

	ci = READ_ONCE(inode->i_crypt_info);
	if (ci) {
		/* key available, use the cached policy */
		*policy = ci->ci_policy;
		return 0;
	}

	if (!IS_ENCRYPTED(inode))
		return -ENODATA;

	ret = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (ret < 0)
		return (ret == -ERANGE) ? -EINVAL : ret;

	return fscrypt_policy_from_context(policy, &ctx, ret);
}

static int set_encryption_policy(struct inode *inode,
				 const union fscrypt_policy *policy)
{
	union fscrypt_context ctx;
	int ctxsize;
	int err;

	if (!fscrypt_supported_policy(policy, inode))
		return -EINVAL;

	ctx.contents_encryption_mode =
		fscrypt_data_crypt_mode(inode,
		policy->contents_encryption_mode);
	ctx.filenames_encryption_mode = policy->filenames_encryption_mode;
	ctx.flags = policy->flags;
	BUILD_BUG_ON(sizeof(ctx.nonce) != FS_KEY_DERIVATION_NONCE_SIZE);
	get_random_bytes(ctx.nonce, FS_KEY_DERIVATION_NONCE_SIZE);
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		/*
		 * The original encryption policy version provided no way of
		 * verifying that the correct master key was supplied, which was
		 * insecure in scenarios where multiple users have access to the
		 * same encrypted files (even just read-only access).  The new
		 * encryption policy version fixes this and also implies use of
		 * an improved key derivation function and allows non-root users
		 * to securely remove keys.  So as long as compatibility with
		 * old kernels isn't required, it is recommended to use the new
		 * policy version for all new encrypted directories.
		 */
		pr_warn_once("%s (pid %d) is setting deprecated v1 encryption policy; recommend upgrading to v2.\n",
			     current->comm, current->pid);
		break;
	case FSCRYPT_POLICY_V2:
		err = fscrypt_verify_key_added(inode->i_sb,
					       policy->v2.master_key_identifier);
		if (err)
			return err;
		if (policy->v2.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)
			pr_warn_once("%s (pid %d) is setting an IV_INO_LBLK_32 encryption policy.  This should only be used if there are certain hardware limitations.\n",
				     current->comm, current->pid);
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	ctxsize = fscrypt_new_context_from_policy(&ctx, policy);

	return inode->i_sb->s_cop->set_context(inode, &ctx, ctxsize, NULL);
}

int fscrypt_ioctl_set_policy(struct file *filp, const void __user *arg)
{
	union fscrypt_policy policy;
	union fscrypt_policy existing_policy;
	struct inode *inode = file_inode(filp);
	u8 version;
	int size;
	int ret;

	if (get_user(policy.version, (const u8 __user *)arg))
		return -EFAULT;

	size = fscrypt_policy_size(&policy);
	if (size <= 0)
		return -EINVAL;

	/*
	 * We should just copy the remaining 'size - 1' bytes here, but a
	 * bizarre bug in gcc 7 and earlier (fixed by gcc r255731) causes gcc to
	 * think that size can be 0 here (despite the check above!) *and* that
	 * it's a compile-time constant.  Thus it would think copy_from_user()
	 * is passed compile-time constant ULONG_MAX, causing the compile-time
	 * buffer overflow check to fail, breaking the build. This only occurred
	 * when building an i386 kernel with -Os and branch profiling enabled.
	 *
	 * Work around it by just copying the first byte again...
	 */
	version = policy.version;
	if (copy_from_user(&policy, arg, size))
		return -EFAULT;
	policy.version = version;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	ret = fscrypt_get_policy(inode, &existing_policy);
	if (ret == -ENODATA) {
		if (!S_ISDIR(inode->i_mode))
			ret = -ENOTDIR;
		else if (IS_DEADDIR(inode))
			ret = -ENOENT;
		else if (!inode->i_sb->s_cop->empty_dir(inode))
			ret = -ENOTEMPTY;
		else
			ret = create_encryption_context_from_policy(inode,
								    &policy);
	} else if (ret == sizeof(ctx) &&
		   is_encryption_context_consistent_with_policy(&ctx,
								&policy,
								inode)) {
		/* The file already uses the same encryption policy. */
		ret = 0;
	} else if (ret >= 0 || ret == -ERANGE) {
			ret = set_encryption_policy(inode, &policy);
	} else if (ret == -EINVAL ||
		   (ret == 0 && !fscrypt_policies_equal(&policy,
							&existing_policy))) {
		/* The file already uses a different encryption policy. */
		ret = -EEXIST;
	}

	inode_unlock(inode);

	mnt_drop_write_file(filp);
	return ret;
}
EXPORT_SYMBOL(fscrypt_ioctl_set_policy);

/* Original ioctl version; can only get the original policy version */
int fscrypt_ioctl_get_policy(struct file *filp, void __user *arg)
{
	union fscrypt_policy policy;
	int err;

	err = fscrypt_get_policy(file_inode(filp), &policy);
	if (err)
		return err;

	if (policy.version != FSCRYPT_POLICY_V1)
		return -EINVAL;
	if (ctx.format != FS_ENCRYPTION_CONTEXT_FORMAT_V1)
		return -EINVAL;

	policy.version = 0;
	policy.contents_encryption_mode = ctx.contents_encryption_mode;
	policy.filenames_encryption_mode = ctx.filenames_encryption_mode;
	policy.flags = ctx.flags;

	/* in compliance with android */
	if (S_ISDIR(inode->i_mode) &&
		policy.contents_encryption_mode !=
		FS_ENCRYPTION_MODE_INVALID)
		policy.contents_encryption_mode =
			FS_ENCRYPTION_MODE_AES_256_XTS;

	memcpy(policy.master_key_descriptor, ctx.master_key_descriptor,
				FS_KEY_DESCRIPTOR_SIZE);

	if (copy_to_user(arg, &policy, sizeof(policy.v1)))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(fscrypt_ioctl_get_policy);

/* Extended ioctl version; can get policies of any version */
int fscrypt_ioctl_get_policy_ex(struct file *filp, void __user *uarg)
{
	struct fscrypt_get_policy_ex_arg arg;
	union fscrypt_policy *policy = (union fscrypt_policy *)&arg.policy;
	size_t policy_size;
	int err;

	/* arg is policy_size, then policy */
	BUILD_BUG_ON(offsetof(typeof(arg), policy_size) != 0);
	BUILD_BUG_ON(offsetofend(typeof(arg), policy_size) !=
		     offsetof(typeof(arg), policy));
	BUILD_BUG_ON(sizeof(arg.policy) != sizeof(*policy));

	err = fscrypt_get_policy(file_inode(filp), policy);
	if (err)
		return err;
	policy_size = fscrypt_policy_size(policy);

	if (copy_from_user(&arg, uarg, sizeof(arg.policy_size)))
		return -EFAULT;

	if (policy_size > arg.policy_size)
		return -EOVERFLOW;
	arg.policy_size = policy_size;

	if (copy_to_user(uarg, &arg, sizeof(arg.policy_size) + policy_size))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_get_policy_ex);

/* FS_IOC_GET_ENCRYPTION_NONCE: retrieve file's encryption nonce for testing */
int fscrypt_ioctl_get_nonce(struct file *filp, void __user *arg)
{
	struct inode *inode = file_inode(filp);
	union fscrypt_context ctx;
	int ret;

	ret = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (ret < 0)
		return ret;
	if (!fscrypt_context_is_valid(&ctx, ret))
		return -EINVAL;
	if (copy_to_user(arg, fscrypt_context_nonce(&ctx),
			 FS_KEY_DERIVATION_NONCE_SIZE))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_get_nonce);

/**
 * fscrypt_has_permitted_context() - is a file's encryption policy permitted
 *				     within its directory?
 *
 * @parent: inode for parent directory
 * @child: inode for file being looked up, opened, or linked into @parent
 *
 * Filesystems must call this before permitting access to an inode in a
 * situation where the parent directory is encrypted (either before allowing
 * ->lookup() to succeed, or for a regular file before allowing it to be opened)
 * and before any operation that involves linking an inode into an encrypted
 * directory, including link, rename, and cross rename.  It enforces the
 * constraint that within a given encrypted directory tree, all files use the
 * same encryption policy.  The pre-access check is needed to detect potentially
 * malicious offline violations of this constraint, while the link and rename
 * checks are needed to prevent online violations of this constraint.
 *
 * Return: 1 if permitted, 0 if forbidden.
 */
int fscrypt_has_permitted_context(struct inode *parent, struct inode *child)
{
	union fscrypt_policy parent_policy, child_policy;
	int err;

	/* No restrictions on file types which are never encrypted */
	if (!S_ISREG(child->i_mode) && !S_ISDIR(child->i_mode) &&
	    !S_ISLNK(child->i_mode))
		return 1;

	/* No restrictions if the parent directory is unencrypted */
	if (!IS_ENCRYPTED(parent))
		return 1;

	/* Encrypted directories must not contain unencrypted files */
	if (!IS_ENCRYPTED(child))
		return 0;

	/*
	 * Both parent and child are encrypted, so verify they use the same
	 * encryption policy.  Compare the fscrypt_info structs if the keys are
	 * available, otherwise retrieve and compare the fscrypt_contexts.
	 *
	 * Note that the fscrypt_context retrieval will be required frequently
	 * when accessing an encrypted directory tree without the key.
	 * Performance-wise this is not a big deal because we already don't
	 * really optimize for file access without the key (to the extent that
	 * such access is even possible), given that any attempted access
	 * already causes a fscrypt_context retrieval and keyring search.
	 *
	 * In any case, if an unexpected error occurs, fall back to "forbidden".
	 */

	err = fscrypt_get_encryption_info(parent);
	if (err)
		return 0;
	err = fscrypt_get_encryption_info(child);
	if (err)
		return 0;
	parent_ci = parent->i_crypt_info;
	child_ci = child->i_crypt_info;

	if (parent_ci && child_ci) {
		return memcmp(parent_ci->ci_master_key_descriptor,
			      child_ci->ci_master_key_descriptor,
			      FS_KEY_DESCRIPTOR_SIZE) == 0 &&
			(parent_ci->ci_data_mode == child_ci->ci_data_mode) &&
			(parent_ci->ci_filename_mode ==
			 child_ci->ci_filename_mode) &&
			(parent_ci->ci_flags == child_ci->ci_flags);
	}

	err = fscrypt_get_policy(parent, &parent_policy);
	if (err)
		return 0;

	err = fscrypt_get_policy(child, &child_policy);
	if (err)
		return 0;

	parent_ctx.contents_encryption_mode =
		fscrypt_data_crypt_mode(parent,
		parent_ctx.contents_encryption_mode);
	child_ctx.contents_encryption_mode =
		fscrypt_data_crypt_mode(child,
		child_ctx.contents_encryption_mode);

	return memcmp(parent_ctx.master_key_descriptor,
		      child_ctx.master_key_descriptor,
		      FS_KEY_DESCRIPTOR_SIZE) == 0 &&
		(parent_ctx.contents_encryption_mode ==
		 child_ctx.contents_encryption_mode) &&
		(parent_ctx.filenames_encryption_mode ==
		 child_ctx.filenames_encryption_mode) &&
		(parent_ctx.flags == child_ctx.flags);
	return fscrypt_policies_equal(&parent_policy, &child_policy);
}
EXPORT_SYMBOL(fscrypt_has_permitted_context);

/**
 * fscrypt_inherit_context() - Sets a child context from its parent
 * @parent: Parent inode from which the context is inherited.
 * @child:  Child inode that inherits the context from @parent.
 * @fs_data:  private data given by FS.
 * @preload:  preload child i_crypt_info if true
 *
 * Return: 0 on success, -errno on failure
 */
int fscrypt_inherit_context(struct inode *parent, struct inode *child,
						void *fs_data, bool preload)
{
	union fscrypt_context ctx;
	int ctxsize;
	struct fscrypt_info *ci;
	int res;

	res = fscrypt_get_encryption_info(parent);
	if (res < 0)
		return res;

	ci = READ_ONCE(parent->i_crypt_info);
	if (ci == NULL)
		return -ENOKEY;

	ctx.format = FS_ENCRYPTION_CONTEXT_FORMAT_V1;
	ctx.contents_encryption_mode = ci->ci_data_mode;
	ctx.filenames_encryption_mode = ci->ci_filename_mode;
	ctx.flags = ci->ci_flags;
	memcpy(ctx.master_key_descriptor, ci->ci_master_key_descriptor,
	       FS_KEY_DESCRIPTOR_SIZE);
	get_random_bytes(ctx.nonce, FS_KEY_DERIVATION_NONCE_SIZE);
	ctxsize = fscrypt_new_context_from_policy(&ctx, &ci->ci_policy);

	BUILD_BUG_ON(sizeof(ctx) != FSCRYPT_SET_CONTEXT_MAX_SIZE);
	res = parent->i_sb->s_cop->set_context(child, &ctx, ctxsize, fs_data);
	if (res)
		return res;
	return preload ? fscrypt_get_encryption_info(child): 0;
}
EXPORT_SYMBOL(fscrypt_inherit_context);

int fscrypt_set_bio_ctx(struct inode *inode, struct bio *bio)
{
	struct fscrypt_info *ci;
	int ret = -ENOENT;

	if (!inode || !bio)
		return ret;

	ci = inode->i_crypt_info;

	if (S_ISREG(inode->i_mode) && ci &&
	    (ci->ci_data_mode == FS_ENCRYPTION_MODE_PRIVATE)) {
		WARN_ON(!hie_is_capable(inode->i_sb));
		/* HIE: default use aes-256-xts */
		bio_bcf_set(bio, BC_CRYPT | BC_AES_256_XTS);
		bio->bi_crypt_ctx.bc_key_size = FS_AES_256_XTS_KEY_SIZE;
		bio->bi_crypt_ctx.bc_ino = inode->i_ino;
		bio->bi_crypt_ctx.bc_sb = inode->i_sb;

		bio->bi_crypt_ctx.bc_info_act = &fscrypt_crypt_info_act;
		bio->bi_crypt_ctx.bc_info =
			fscrypt_crypt_info_act(
			ci, BIO_BC_INFO_GET);
		WARN_ON(!bio->bi_crypt_ctx.bc_info);

#ifdef CONFIG_HIE_DEBUG
		if (hie_debug(HIE_DBG_FS))
			pr_info("HIE: %s: ino: %ld, bio: %p\n",
				__func__, inode->i_ino, bio);
#endif
		ret = 0;
	} else
		bio_bcf_clear(bio, BC_CRYPT);

	return ret;
}

int fscrypt_key_payload(struct bio_crypt_ctx *ctx,
		const unsigned char **key)
{
	struct fscrypt_info *fi;

	fi = (struct fscrypt_info *)ctx->bc_info;

	if (!fi) {
		pr_info("HIE: %s: missing crypto info\n", __func__);
		return -ENOKEY;
	}

	if (key)
		*key = &(fi->ci_raw_key[0]);

	return ctx->bc_key_size;
}

int fscrypt_is_hw_encrypt(const struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;

	return S_ISREG(inode->i_mode) && ci &&
		ci->ci_data_mode == FS_ENCRYPTION_MODE_PRIVATE;
}

int fscrypt_is_sw_encrypt(const struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;

	return S_ISREG(inode->i_mode) && ci &&
		ci->ci_data_mode != FS_ENCRYPTION_MODE_INVALID &&
		ci->ci_data_mode != FS_ENCRYPTION_MODE_PRIVATE;
}
/**
 * fscrypt_set_test_dummy_encryption() - handle '-o test_dummy_encryption'
 * @sb: the filesystem on which test_dummy_encryption is being specified
 * @arg: the argument to the test_dummy_encryption option.
 *	 If no argument was specified, then @arg->from == NULL.
 * @dummy_ctx: the filesystem's current dummy context (input/output, see below)
 *
 * Handle the test_dummy_encryption mount option by creating a dummy encryption
 * context, saving it in @dummy_ctx, and adding the corresponding dummy
 * encryption key to the filesystem.  If the @dummy_ctx is already set, then
 * instead validate that it matches @arg.  Don't support changing it via
 * remount, as that is difficult to do safely.
 *
 * The reason we use an fscrypt_context rather than an fscrypt_policy is because
 * we mustn't generate a new nonce each time we access a dummy-encrypted
 * directory, as that would change the way filenames are encrypted.
 *
 * Return: 0 on success (dummy context set, or the same context is already set);
 *         -EEXIST if a different dummy context is already set;
 *         or another -errno value.
 */
int fscrypt_set_test_dummy_encryption(struct super_block *sb,
				      const substring_t *arg,
				      struct fscrypt_dummy_context *dummy_ctx)
{
	const char *argstr = "v2";
	const char *argstr_to_free = NULL;
	struct fscrypt_key_specifier key_spec = { 0 };
	int version;
	union fscrypt_context *ctx = NULL;
	int err;

	if (arg->from) {
		argstr = argstr_to_free = match_strdup(arg);
		if (!argstr)
			return -ENOMEM;
	}

	if (!strcmp(argstr, "v1")) {
		version = FSCRYPT_CONTEXT_V1;
		key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
		memset(key_spec.u.descriptor, 0x42,
		       FSCRYPT_KEY_DESCRIPTOR_SIZE);
	} else if (!strcmp(argstr, "v2")) {
		version = FSCRYPT_CONTEXT_V2;
		key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
		/* key_spec.u.identifier gets filled in when adding the key */
	} else {
		err = -EINVAL;
		goto out;
	}

	if (dummy_ctx->ctx) {
		/*
		 * Note: if we ever make test_dummy_encryption support
		 * specifying other encryption settings, such as the encryption
		 * modes, we'll need to compare those settings here.
		 */
		if (dummy_ctx->ctx->version == version)
			err = 0;
		else
			err = -EEXIST;
		goto out;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}

	err = fscrypt_add_test_dummy_key(sb, &key_spec);
	if (err)
		goto out;

	ctx->version = version;
	switch (ctx->version) {
	case FSCRYPT_CONTEXT_V1:
		ctx->v1.contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS;
		ctx->v1.filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS;
		memcpy(ctx->v1.master_key_descriptor, key_spec.u.descriptor,
		       FSCRYPT_KEY_DESCRIPTOR_SIZE);
		break;
	case FSCRYPT_CONTEXT_V2:
		ctx->v2.contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS;
		ctx->v2.filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS;
		memcpy(ctx->v2.master_key_identifier, key_spec.u.identifier,
		       FSCRYPT_KEY_IDENTIFIER_SIZE);
		break;
	default:
		WARN_ON(1);
		err = -EINVAL;
		goto out;
	}
	dummy_ctx->ctx = ctx;
	ctx = NULL;
	err = 0;
out:
	kfree(ctx);
	kfree(argstr_to_free);
	return err;
}
EXPORT_SYMBOL_GPL(fscrypt_set_test_dummy_encryption);

/**
 * fscrypt_show_test_dummy_encryption() - show '-o test_dummy_encryption'
 * @seq: the seq_file to print the option to
 * @sep: the separator character to use
 * @sb: the filesystem whose options are being shown
 *
 * Show the test_dummy_encryption mount option, if it was specified.
 * This is mainly used for /proc/mounts.
 */
void fscrypt_show_test_dummy_encryption(struct seq_file *seq, char sep,
					struct super_block *sb)
{
	const union fscrypt_context *ctx = fscrypt_get_dummy_context(sb);

	if (!ctx)
		return;
	seq_printf(seq, "%ctest_dummy_encryption=v%d", sep, ctx->version);
}
EXPORT_SYMBOL_GPL(fscrypt_show_test_dummy_encryption);
