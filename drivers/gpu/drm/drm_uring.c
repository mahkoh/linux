// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright © 2023 Julian Orth <ju.orth@gmail.com>
 */

#include <linux/io_uring.h>

#include <drm/drm_drv.h>
#include <drm/drm_uring.h>
#include <drm/drm_print.h>

#include "drm_internal.h"

#define DRM_URING_CMD_DEF(cmd_op, _func, _cancel)	\
	[cmd_op] = {					\
		.func = _func,				\
		.name = #cmd_op,			\
		.cancel = _cancel,			\
	}

static const struct drm_uring_cmd_desc drm_cmds[] = {
	DRM_URING_CMD_DEF(DRM_URING_SYNCOBJ_WAIT, drm_syncobj_uring_cmd_wait,
			  drm_syncobj_uring_cmd_wait_cancel),
};

#define DRM_CORE_URING_CMD_COUNT ARRAY_SIZE(drm_cmds)

int drm_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct drm_file *file_priv = cmd->file->private_data;
	struct drm_device *dev = file_priv->minor->dev;
	const struct drm_uring_cmd_desc *desc = NULL;
	int ret;

	if (drm_dev_is_unplugged(dev))
		return -ENODEV;

	if (cmd->cmd_op >= DRM_CORE_URING_CMD_COUNT) {
		drm_dbg_core(dev,
			     "invalid uring_cmd: comm=\"%s\", pid=%d, dev=0x%lx, auth=%d, cmd=0x%02x\n",
			     current->comm, task_pid_nr(current),
			     (long)old_encode_dev(file_priv->minor->kdev->devt),
			     file_priv->authenticated, cmd->cmd_op);
		return -EINVAL;
	}

	desc = &drm_cmds[cmd->cmd_op];

	drm_dbg_core(dev, "comm=\"%s\" pid=%d, dev=0x%lx, auth=%d, uring_cmd=%s\n",
		     current->comm, task_pid_nr(current),
		     (long)old_encode_dev(file_priv->minor->kdev->devt),
		     file_priv->authenticated, desc->name);

	ret = desc->func(dev, file_priv, cmd, issue_flags);
	if (ret)
		drm_dbg_core(dev, "comm=\"%s\", pid=%d, ret=%d\n",
			     current->comm, task_pid_nr(current), ret);
	return ret;
}
EXPORT_SYMBOL(drm_uring_cmd);

int drm_uring_cmd_cancel(struct io_uring_cmd *cmd)
{
	const struct drm_uring_cmd_desc *desc = NULL;

	if (WARN_ON(cmd->cmd_op >= DRM_CORE_URING_CMD_COUNT))
		return -EINVAL;

	desc = &drm_cmds[cmd->cmd_op];

	if (!desc->cancel)
		return -EINVAL;

	return desc->cancel(cmd);
}
EXPORT_SYMBOL(drm_uring_cmd_cancel);
