/*
 * Copyright (C) 2020 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "../module.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

#define err_return(err) do { last_error = err; return NULL; } while(0)

static const struct uc_ops *ops;

static int last_error = 0;

static struct json_object *
uc_fs_error(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = json_object_new_string(strerror(last_error));
	last_error = 0;

	return errmsg;
}

static struct json_object *
uc_fs_read_common(struct uc_state *s, uint32_t off, struct json_object *args, const char *type)
{
	struct json_object *limit = json_object_array_get_idx(args, 0);
	struct json_object *rv = NULL;
	char buf[128], *p = NULL, *tmp;
	size_t rlen, len = 0;
	const char *lstr;
	int64_t lsize;

	FILE **fp = (FILE **)ops->get_type(s->ctx, type);

	if (!fp || !*fp)
		err_return(EBADF);

	if (json_object_is_type(limit, json_type_string)) {
		lstr = json_object_get_string(limit);

		if (!strcmp(lstr, "line")) {
			while (true) {
				if (!fgets(buf, sizeof(buf), *fp))
					break;

				rlen = strlen(buf);
				tmp = realloc(p, len + rlen + 1);

				if (!tmp) {
					free(p);
					err_return(ENOMEM);
				}

				snprintf(tmp + len, rlen + 1, "%s", buf);

				p = tmp;
				len += rlen;

				if (rlen > 0 && buf[rlen - 1] == '\n')
					break;
			}
		}
		else if (!strcmp(lstr, "all")) {
			while (true) {
				rlen = fread(buf, 1, sizeof(buf), *fp);

				tmp = realloc(p, len + rlen);

				if (!tmp) {
					free(p);
					err_return(ENOMEM);
				}

				memcpy(tmp + len, buf, rlen);

				p = tmp;
				len += rlen;

				if (rlen == 0)
					break;
			}
		}
		else {
			return NULL;
		}
	}
	else if (json_object_is_type(limit, json_type_int)) {
		lsize = json_object_get_int64(limit);

		if (lsize <= 0)
			return NULL;

		p = calloc(1, lsize);

		if (!p)
			err_return(ENOMEM);

		len = fread(p, 1, lsize, *fp);

		if (ferror(*fp)) {
			free(p);
			err_return(errno);
		}
	}
	else {
		err_return(EINVAL);
	}

	rv = json_object_new_string_len(p, len);
	free(p);

	return rv;
}

static struct json_object *
uc_fs_write_common(struct uc_state *s, uint32_t off, struct json_object *args, const char *type)
{
	struct json_object *data = json_object_array_get_idx(args, 0);
	size_t len, wsize;
	const char *str;

	FILE **fp = (FILE **)ops->get_type(s->ctx, type);

	if (!fp || !*fp)
		err_return(EBADF);

	if (json_object_is_type(data, json_type_string)) {
		str = json_object_get_string(data);
		len = json_object_get_string_len(data);
	}
	else {
		str = json_object_to_json_string(data);
		len = str ? strlen(str) : 0;
	}

	wsize = fwrite(str, 1, len, *fp);

	if (wsize < len && ferror(*fp))
		err_return(errno);

	return json_object_new_int64(wsize);
}


static struct json_object *
uc_fs_pclose(struct uc_state *s, uint32_t off, struct json_object *args)
{
	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.proc");
	int rc;

	if (!fp || !*fp)
		err_return(EBADF);

	rc = pclose(*fp);
	*fp = NULL;

	if (rc == -1)
		err_return(errno);

	if (WIFEXITED(rc))
		return xjs_new_int64(WEXITSTATUS(rc));

	if (WIFSIGNALED(rc))
		return xjs_new_int64(-WTERMSIG(rc));

	return xjs_new_int64(0);
}

static struct json_object *
uc_fs_pread(struct uc_state *s, uint32_t off, struct json_object *args)
{
	return uc_fs_read_common(s, off, args, "fs.proc");
}

static struct json_object *
uc_fs_pwrite(struct uc_state *s, uint32_t off, struct json_object *args)
{
	return uc_fs_write_common(s, off, args, "fs.proc");
}

static struct json_object *
uc_fs_popen(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *comm = json_object_array_get_idx(args, 0);
	struct json_object *mode = json_object_array_get_idx(args, 1);
	struct json_object *fo;
	FILE *fp;

	if (!json_object_is_type(comm, json_type_string))
		err_return(EINVAL);

	fp = popen(json_object_get_string(comm),
		json_object_is_type(mode, json_type_string) ? json_object_get_string(mode) : "r");

	if (!fp)
		err_return(errno);

	fo = json_object_new_object();

	if (!fo) {
		pclose(fp);
		err_return(ENOMEM);
	}

	return ops->set_type(fo, "fs.proc", fp);
}


static struct json_object *
uc_fs_close(struct uc_state *s, uint32_t off, struct json_object *args)
{
	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	fclose(*fp);
	*fp = NULL;

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_read(struct uc_state *s, uint32_t off, struct json_object *args)
{
	return uc_fs_read_common(s, off, args, "fs.file");
}

static struct json_object *
uc_fs_write(struct uc_state *s, uint32_t off, struct json_object *args)
{
	return uc_fs_write_common(s, off, args, "fs.file");
}

static struct json_object *
uc_fs_seek(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *ofs  = json_object_array_get_idx(args, 0);
	struct json_object *how  = json_object_array_get_idx(args, 1);
	int whence, res;
	long offset;

	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	if (!ofs)
		offset = 0;
	else if (!json_object_is_type(ofs, json_type_int))
		err_return(EINVAL);
	else
		offset = (long)json_object_get_int64(ofs);

	if (!how)
		whence = 0;
	else if (!json_object_is_type(how, json_type_int))
		err_return(EINVAL);
	else
		whence = (int)json_object_get_int64(how);

	res = fseek(*fp, offset, whence);

	if (res < 0)
		err_return(errno);

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_tell(struct uc_state *s, uint32_t off, struct json_object *args)
{
	long offset;

	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	offset = ftell(*fp);

	if (offset < 0)
		err_return(errno);

	return json_object_new_int64(offset);
}

static struct json_object *
uc_fs_open(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);
	struct json_object *mode = json_object_array_get_idx(args, 1);
	struct json_object *fo;
	FILE *fp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	fp = fopen(json_object_get_string(path),
		json_object_is_type(mode, json_type_string) ? json_object_get_string(mode) : "r");

	if (!fp)
		err_return(errno);

	fo = json_object_new_object();

	if (!fo) {
		fclose(fp);
		err_return(ENOMEM);
	}

	return ops->set_type(fo, "fs.file", fp);
}


static struct json_object *
uc_fs_readdir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	DIR **dp = (DIR **)ops->get_type(s->ctx, "fs.dir");
	struct dirent *e;

	if (!dp || !*dp)
		err_return(EINVAL);

	errno = 0;
	e = readdir(*dp);

	if (!e)
		err_return(errno);

	return json_object_new_string(e->d_name);
}

static struct json_object *
uc_fs_telldir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	DIR **dp = (DIR **)ops->get_type(s->ctx, "fs.dir");
	long position;

	if (!dp || !*dp)
		err_return(EBADF);

	position = telldir(*dp);

	if (position == -1)
		err_return(errno);

	return json_object_new_int64((int64_t)position);
}

static struct json_object *
uc_fs_seekdir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *ofs = json_object_array_get_idx(args, 0);
	DIR **dp = (DIR **)ops->get_type(s->ctx, "fs.dir");
	long position;

	if (!json_object_is_type(ofs, json_type_int))
		err_return(EINVAL);

	if (!dp || !*dp)
		err_return(EBADF);

	position = (long)json_object_get_int64(ofs);

	seekdir(*dp, position);

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_closedir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	DIR **dp = (DIR **)ops->get_type(s->ctx, "fs.dir");

	if (!dp || !*dp)
		err_return(EBADF);

	closedir(*dp);
	*dp = NULL;

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_opendir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);
	struct json_object *diro;
	DIR *dp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	dp = opendir(json_object_get_string(path));

	if (!dp)
		err_return(errno);

	diro = json_object_new_object();

	if (!diro) {
		closedir(dp);
		err_return(ENOMEM);
	}

	return ops->set_type(diro, "fs.dir", dp);
}

static struct json_object *
uc_fs_readlink(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);
	struct json_object *res;
	ssize_t buflen = 0, rv;
	char *buf = NULL, *tmp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	do {
		buflen += 128;
		tmp = realloc(buf, buflen);

		if (!tmp) {
			free(buf);
			err_return(ENOMEM);
		}

		buf = tmp;
		rv = readlink(json_object_get_string(path), buf, buflen);

		if (rv == -1) {
			free(buf);
			err_return(errno);
		}

		if (rv < buflen)
			break;
	}
	while (true);

	res = json_object_new_string_len(buf, buflen);

	free(buf);

	return res;
}

static struct json_object *
uc_fs_stat_common(struct uc_state *s, uint32_t off, struct json_object *args, bool use_lstat)
{
	struct json_object *path = json_object_array_get_idx(args, 0);
	struct json_object *res, *o;
	struct stat st;
	int rv;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	rv = (use_lstat ? lstat : stat)(json_object_get_string(path), &st);

	if (rv == -1)
		err_return(errno);

	res = json_object_new_object();

	if (!res)
		err_return(ENOMEM);

	o = json_object_new_object();

	if (o) {
		json_object_object_add(o, "major", json_object_new_int64(major(st.st_dev)));
		json_object_object_add(o, "minor", json_object_new_int64(minor(st.st_dev)));

		json_object_object_add(res, "dev", o);
	}

	o = json_object_new_object();

	if (o) {
		json_object_object_add(o, "setuid", json_object_new_boolean(st.st_mode & S_ISUID));
		json_object_object_add(o, "setgid", json_object_new_boolean(st.st_mode & S_ISGID));
		json_object_object_add(o, "sticky", json_object_new_boolean(st.st_mode & S_ISVTX));

		json_object_object_add(o, "user_read", json_object_new_boolean(st.st_mode & S_IRUSR));
		json_object_object_add(o, "user_write", json_object_new_boolean(st.st_mode & S_IWUSR));
		json_object_object_add(o, "user_exec", json_object_new_boolean(st.st_mode & S_IXUSR));

		json_object_object_add(o, "group_read", json_object_new_boolean(st.st_mode & S_IRGRP));
		json_object_object_add(o, "group_write", json_object_new_boolean(st.st_mode & S_IWGRP));
		json_object_object_add(o, "group_exec", json_object_new_boolean(st.st_mode & S_IXGRP));

		json_object_object_add(o, "other_read", json_object_new_boolean(st.st_mode & S_IROTH));
		json_object_object_add(o, "other_write", json_object_new_boolean(st.st_mode & S_IWOTH));
		json_object_object_add(o, "other_exec", json_object_new_boolean(st.st_mode & S_IXOTH));

		json_object_object_add(res, "perm", o);
	}

	json_object_object_add(res, "inode", json_object_new_int64((int64_t)st.st_ino));
	json_object_object_add(res, "mode", json_object_new_int64((int64_t)st.st_mode & ~S_IFMT));
	json_object_object_add(res, "nlink", json_object_new_int64((int64_t)st.st_nlink));
	json_object_object_add(res, "uid", json_object_new_int64((int64_t)st.st_uid));
	json_object_object_add(res, "gid", json_object_new_int64((int64_t)st.st_gid));
	json_object_object_add(res, "size", json_object_new_int64((int64_t)st.st_size));
	json_object_object_add(res, "blksize", json_object_new_int64((int64_t)st.st_blksize));
	json_object_object_add(res, "blocks", json_object_new_int64((int64_t)st.st_blocks));
	json_object_object_add(res, "atime", json_object_new_int64((int64_t)st.st_atime));
	json_object_object_add(res, "mtime", json_object_new_int64((int64_t)st.st_mtime));
	json_object_object_add(res, "ctime", json_object_new_int64((int64_t)st.st_ctime));

	if (S_ISREG(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("file"));
	else if (S_ISDIR(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("directory"));
	else if (S_ISCHR(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("char"));
	else if (S_ISBLK(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("block"));
	else if (S_ISFIFO(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("fifo"));
	else if (S_ISLNK(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("link"));
	else if (S_ISSOCK(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("socket"));
	else
		json_object_object_add(res, "type", json_object_new_string("unknown"));

	return res;
}

static struct json_object *
uc_fs_stat(struct uc_state *s, uint32_t off, struct json_object *args)
{
	return uc_fs_stat_common(s, off, args, false);
}

static struct json_object *
uc_fs_lstat(struct uc_state *s, uint32_t off, struct json_object *args)
{
	return uc_fs_stat_common(s, off, args, true);
}

static struct json_object *
uc_fs_mkdir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);
	struct json_object *mode = json_object_array_get_idx(args, 1);

	if (!json_object_is_type(path, json_type_string) ||
	    (mode && !json_object_is_type(mode, json_type_int)))
		err_return(EINVAL);

	if (mkdir(json_object_get_string(path), (mode_t)(mode ? json_object_get_int64(mode) : 0777)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_rmdir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (rmdir(json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_symlink(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *dest = json_object_array_get_idx(args, 0);
	struct json_object *path = json_object_array_get_idx(args, 1);

	if (!json_object_is_type(dest, json_type_string) ||
	    !json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (symlink(json_object_get_string(dest), json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_unlink(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (unlink(json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static struct json_object *
uc_fs_getcwd(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *res;
	char *buf = NULL, *tmp;
	size_t buflen = 0;

	do {
		buflen += 128;
		tmp = realloc(buf, buflen);

		if (!tmp) {
			free(buf);
			err_return(ENOMEM);
		}

		buf = tmp;

		if (getcwd(buf, buflen) != NULL)
			break;

		if (errno == ERANGE)
			continue;

		err_return(errno);
	}
	while (true);

	res = json_object_new_string(buf);

	free(buf);

	return res;
}

static struct json_object *
uc_fs_chdir(struct uc_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (chdir(json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static const struct { const char *name; uc_c_fn *func; } proc_fns[] = {
	{ "read",		uc_fs_pread },
	{ "write",		uc_fs_pwrite },
	{ "close",		uc_fs_pclose },
};

static const struct { const char *name; uc_c_fn *func; } file_fns[] = {
	{ "read",		uc_fs_read },
	{ "write",		uc_fs_write },
	{ "seek",		uc_fs_seek },
	{ "tell",		uc_fs_tell },
	{ "close",		uc_fs_close },
};

static const struct { const char *name; uc_c_fn *func; } dir_fns[] = {
	{ "read",		uc_fs_readdir },
	{ "seek",		uc_fs_seekdir },
	{ "tell",		uc_fs_telldir },
	{ "close",		uc_fs_closedir },
};

static const struct { const char *name; uc_c_fn *func; } global_fns[] = {
	{ "error",		uc_fs_error },
	{ "open",		uc_fs_open },
	{ "opendir",	uc_fs_opendir },
	{ "popen",		uc_fs_popen },
	{ "readlink",	uc_fs_readlink },
	{ "stat",		uc_fs_stat },
	{ "lstat",		uc_fs_lstat },
	{ "mkdir",		uc_fs_mkdir },
	{ "rmdir",		uc_fs_rmdir },
	{ "symlink",	uc_fs_symlink },
	{ "unlink",		uc_fs_unlink },
	{ "getcwd",		uc_fs_getcwd },
	{ "chdir",		uc_fs_chdir },
};


static void close_proc(void *ud) {
	pclose((FILE *)ud);
}

static void close_file(void *ud) {
	FILE *fp = ud;

	if (fp != stdin && fp != stdout && fp != stderr)
		fclose(fp);
}

static void close_dir(void *ud) {
	closedir((DIR *)ud);
}

void uc_module_init(const struct uc_ops *ut, struct uc_state *s, struct json_object *scope)
{
	struct json_object *proc_proto, *file_proto, *dir_proto;

	ops = ut;
	proc_proto = ops->new_object(NULL);
	file_proto = ops->new_object(NULL);
	dir_proto = ops->new_object(NULL);

	register_functions(s, ops, global_fns, scope);
	register_functions(s, ops, proc_fns, proc_proto);
	register_functions(s, ops, file_fns, file_proto);
	register_functions(s, ops, dir_fns, dir_proto);

	ops->register_type("fs.proc", proc_proto, close_proc);
	ops->register_type("fs.file", file_proto, close_file);
	ops->register_type("fs.dir", dir_proto, close_dir);

	json_object_object_add(scope, "stdin",  ops->set_type(xjs_new_object(), "fs.file", stdin));
	json_object_object_add(scope, "stdout", ops->set_type(xjs_new_object(), "fs.file", stdout));
	json_object_object_add(scope, "stderr", ops->set_type(xjs_new_object(), "fs.file", stderr));
}
