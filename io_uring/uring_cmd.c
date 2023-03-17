// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring.h>
#include <linux/security.h>
#include <linux/nospec.h>

#include <uapi/linux/io_uring.h>

#include "cancel.h"
#include "io_uring.h"
#include "rsrc.h"
#include "uring_cmd.h"

static void io_uring_cmd_work(struct io_kiocb *req, bool *locked)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);

	ioucmd->task_work_cb(ioucmd);
}

void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *))
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	ioucmd->task_work_cb = task_work_cb;
	req->io_task_work.func = io_uring_cmd_work;
	io_req_task_work_add(req);
}
EXPORT_SYMBOL_GPL(io_uring_cmd_complete_in_task);

static inline void io_req_set_cqe32_extra(struct io_kiocb *req,
					  u64 extra1, u64 extra2)
{
	req->extra1 = extra1;
	req->extra2 = extra2;
	req->flags |= REQ_F_CQE32_INIT;
}

/*
 * Called by consumers of io_uring_cmd, if they originally returned
 * -EIOCBQUEUED upon receiving the command.
 */
void io_uring_cmd_done(struct io_uring_cmd *ioucmd, ssize_t ret, ssize_t res2)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	spin_lock(&req->ctx->cmd_lock);
	list_del(&ioucmd->list);
	spin_unlock(&req->ctx->cmd_lock);

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);
	if (req->ctx->flags & IORING_SETUP_CQE32)
		io_req_set_cqe32_extra(req, res2, 0);
	if (req->ctx->flags & IORING_SETUP_IOPOLL)
		/* order with io_iopoll_req_issued() checking ->iopoll_complete */
		smp_store_release(&req->iopoll_completed, 1);
	else
		io_req_complete_post(req, 0);
}
EXPORT_SYMBOL_GPL(io_uring_cmd_done);

int io_uring_cmd_prep_async(struct io_kiocb *req)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	size_t cmd_size;

	BUILD_BUG_ON(uring_cmd_pdu_size(0) != 16);
	BUILD_BUG_ON(uring_cmd_pdu_size(1) != 80);

	cmd_size = uring_cmd_pdu_size(req->ctx->flags & IORING_SETUP_SQE128);

	memcpy(req->async_data, ioucmd->cmd, cmd_size);
	return 0;
}

int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);

	if (sqe->__pad1)
		return -EINVAL;

	ioucmd->flags = READ_ONCE(sqe->uring_cmd_flags);
	if (ioucmd->flags & ~IORING_URING_CMD_FIXED)
		return -EINVAL;

	if (ioucmd->flags & IORING_URING_CMD_FIXED) {
		struct io_ring_ctx *ctx = req->ctx;
		u16 index;

		req->buf_index = READ_ONCE(sqe->buf_index);
		if (unlikely(req->buf_index >= ctx->nr_user_bufs))
			return -EFAULT;
		index = array_index_nospec(req->buf_index, ctx->nr_user_bufs);
		req->imu = ctx->user_bufs[index];
		io_req_set_rsrc_node(req, ctx, 0);
	}
	ioucmd->cmd = sqe->cmd;
	ioucmd->cmd_op = READ_ONCE(sqe->cmd_op);
	return 0;
}

int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	struct io_ring_ctx *ctx = req->ctx;
	struct file *file = req->file;
	int ret;

	if (!file->f_op->uring_cmd)
		return -EOPNOTSUPP;

	ret = security_uring_cmd(ioucmd);
	if (ret)
		return ret;

	if (ctx->flags & IORING_SETUP_SQE128)
		issue_flags |= IO_URING_F_SQE128;
	if (ctx->flags & IORING_SETUP_CQE32)
		issue_flags |= IO_URING_F_CQE32;
	if (ctx->flags & IORING_SETUP_IOPOLL) {
		if (!file->f_op->uring_cmd_iopoll)
			return -EOPNOTSUPP;
		issue_flags |= IO_URING_F_IOPOLL;
		req->iopoll_completed = 0;
		WRITE_ONCE(ioucmd->cookie, NULL);
	}

	if (req_has_async_data(req))
		ioucmd->cmd = req->async_data;

	spin_lock(&req->ctx->cmd_lock);
	ret = file->f_op->uring_cmd(ioucmd, issue_flags);
	if (ret == -EIOCBQUEUED)
		list_add_tail(&ioucmd->list, &req->ctx->cmd_list);
	spin_unlock(&req->ctx->cmd_lock);

	if (ret == -EAGAIN) {
		if (!req_has_async_data(req)) {
			if (io_alloc_async_data(req))
				return -ENOMEM;
			io_uring_cmd_prep_async(req);
		}
		return -EAGAIN;
	}

	if (ret != -EIOCBQUEUED) {
		if (ret < 0)
			req_set_fail(req);
		io_req_set_res(req, ret, 0);
		return ret;
	}

	return IOU_ISSUE_SKIP_COMPLETE;
}

int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	return io_import_fixed(rw, iter, req->imu, ubuf, len);
}
EXPORT_SYMBOL_GPL(io_uring_cmd_import_fixed);

int io_uring_cmd_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd)
{
	struct io_uring_cmd *cmd;
	struct io_kiocb *req;
	int res = -ENOENT;

	spin_lock(&ctx->cmd_lock);

	list_for_each_entry(cmd, &ctx->cmd_list, list) {
		req = cmd_to_io_kiocb(cmd);

		if (!(cd->flags & IORING_ASYNC_CANCEL_ANY)) {
			if (cd->flags & IORING_ASYNC_CANCEL_FD) {
				if (cd->file != cmd->file)
					continue;
			} else {
				if (cd->data != req->cqe.user_data)
					continue;
			}
		}

		res = -EINVAL;
		if (req->file->f_op->uring_cmd_cancel) {
			res = req->file->f_op->uring_cmd_cancel(cmd);
			if (!res)
				list_del(&cmd->list);
		}
		break;
	}

	spin_unlock(&ctx->cmd_lock);

	if (!res)
		io_req_task_queue_fail(req, -ECANCELED);
	return res;
}


/* Returns true if we found and killed one or more cmds */
__cold bool io_uring_kill_cmds(struct io_ring_ctx *ctx, struct task_struct *tsk)
{
	struct io_uring_cmd *cmd, *tmp;
	int canceled = 0, res;

	spin_lock(&ctx->cmd_lock);
	list_for_each_entry_safe(cmd, tmp, &ctx->cmd_list, list) {
		struct io_kiocb *req = cmd_to_io_kiocb(cmd);

		if (tsk && req->task != tsk)
			continue;
		if (req->file->f_op->uring_cmd_cancel) {
			res = req->file->f_op->uring_cmd_cancel(cmd);
			if (!res) {
				list_del(&cmd->list);
				io_req_queue_tw_complete(req, -ECANCELED);
				canceled++;
			}
		}
	}
	spin_unlock(&ctx->cmd_lock);
	return canceled != 0;
}