// SPDX-License-Identifier: GPL-2.0

int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_uring_cmd_prep_async(struct io_kiocb *req);
int io_uring_cmd_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);
__cold bool io_uring_kill_cmds(struct io_ring_ctx *ctx, struct task_struct *tsk);

/*
 * The URING_CMD payload starts at 'cmd' in the first sqe, and continues into
 * the following sqe if SQE128 is used.
 */
#define uring_cmd_pdu_size(is_sqe128)				\
	((1 + !!(is_sqe128)) * sizeof(struct io_uring_sqe) -	\
		offsetof(struct io_uring_sqe, cmd))
