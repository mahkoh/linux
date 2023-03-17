// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright © 2023 Julian Orth <ju.orth@gmail.com>
 */

#ifndef _DRM_URING_H_
#define _DRM_URING_H_

struct io_uring_cmd;
struct drm_device;
struct drm_file;

#ifdef CONFIG_IO_URING
#define DRM_URING_FOPS \
	.uring_cmd = drm_uring_cmd, \
	.uring_cmd_cancel = drm_uring_cmd_cancel,
#else
#define DRM_URING_FOPS
#endif

typedef int drm_uring_cmd_t(struct drm_device *dev, struct drm_file *file_priv,
			    struct io_uring_cmd *cmd, unsigned int issue_flags);

typedef int drm_uring_cancel_cmd_t(struct io_uring_cmd *cmd);

struct drm_uring_cmd_desc {
	drm_uring_cmd_t *func;
	drm_uring_cancel_cmd_t *cancel;
	const char *name;
};

int drm_uring_cmd_cancel(struct io_uring_cmd *cmd);
int drm_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);

#endif /* _DRM_URING_H_ */
