#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/file.h>

struct file_state {
	char *filepath;
	off_t size;
	time_t mtime;
	time_t atime;
	int open_count;
	time_t last_open_time;
	time_t last_read_time;
	time_t last_write_time;
	time_t last_delete_time;
	time_t last_mkdir_time;
	time_t last_dirdelete_time;
	time_t last_symlink_time;
	int open_sequence;
	int is_new_file;
	struct file_state *next;
};

static TALLOC_CTX *file_states_ctx = NULL;
static struct file_state *file_states_head = NULL;

static void log_operation(vfs_handle_struct *handle, const char *filepath, const char *action);
static void remove_file_state(const char *filepath);
static struct file_state* get_file_state(const char *filepath);
static struct file_state* find_file_state(const char *filepath);
static int was_file_written(struct file_state *state, const char *filepath);
static int was_file_read(struct file_state *state, const char *filepath);
static void update_file_attrs(struct file_state *state, const char *filepath);
static void log_directory_nested_files(vfs_handle_struct *handle, const char *dir_path);

static const char* get_current_user(vfs_handle_struct *handle)
{
	uid_t uid = geteuid();
	struct passwd *pw = getpwuid(uid);
	if (pw && pw->pw_name) {
		return pw->pw_name;
	}
	return "unknown";
}

static char* get_full_path(vfs_handle_struct *handle, const struct smb_filename *smb_fname)
{
	char *full_path = NULL;
	const char *share_path = handle->conn->connectpath;

	if (share_path && smb_fname && smb_fname->base_name) {
		if (smb_fname->base_name[0] == '/') {
			full_path = talloc_asprintf(talloc_tos(), "%s",
						    smb_fname->base_name);
		} else {
			full_path = talloc_asprintf(talloc_tos(), "%s/%s",
						    share_path,
						    smb_fname->base_name);
		}
	}

	return full_path;
}

static char* resolve_path(vfs_handle_struct *handle,
			  const struct files_struct *dirfsp,
			  const struct smb_filename *smb_fname)
{
	struct smb_filename *full_fname = NULL;
	char *result = NULL;
	const char *share_path = handle->conn->connectpath;

	if (smb_fname == NULL || smb_fname->base_name == NULL) {
		return NULL;
	}

	full_fname = full_path_from_dirfsp_atname(talloc_tos(), dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return get_full_path(handle, smb_fname);
	}

	if (full_fname->base_name[0] == '/') {
		result = talloc_strdup(talloc_tos(), full_fname->base_name);
	} else if (share_path) {
		result = talloc_asprintf(talloc_tos(), "%s/%s",
					share_path, full_fname->base_name);
	}

	TALLOC_FREE(full_fname);
	return result;
}

static char* resolve_mkdir_path(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname)
{
	const char *share_path = handle->conn->connectpath;
	const char *base = smb_fname->base_name;
	const char *dir_name;
	const char *p;

	if (base == NULL || share_path == NULL) {
		return NULL;
	}

	if (strstr(base, "::TMPNAME") != NULL) {
		p = strrchr(base, ':');
		dir_name = (p != NULL) ? p + 1 : base;
	} else {
		dir_name = base;
	}

	if (dir_name[0] == '/') {
		return talloc_strdup(talloc_tos(), dir_name);
	}

	if (dirfsp == dirfsp->conn->cwd_fsp ||
	    (dirfsp->fsp_name && ISDOT(dirfsp->fsp_name->base_name))) {
		return talloc_asprintf(talloc_tos(), "%s/%s",
				       share_path, dir_name);
	}

	if (dirfsp->fsp_name && dirfsp->fsp_name->base_name) {
		return talloc_asprintf(talloc_tos(), "%s/%s/%s",
				      share_path,
				      dirfsp->fsp_name->base_name,
				      dir_name);
	}

	return talloc_asprintf(talloc_tos(), "%s/%s", share_path, dir_name);
}

static const char* get_log_path(vfs_handle_struct *handle)
{
	const char *log_path;
	log_path = lp_parm_const_string(SNUM(handle->conn),
				       "file_logger", "log_path",
				       "/var/samba/file_logger.log");
	return log_path;
}

static int get_file_attrs(const char *filepath, off_t *size,
			  time_t *mtime, time_t *atime)
{
	struct stat st;

	if (stat(filepath, &st) != 0) {
		return -1;
	}

	if (size) *size = st.st_size;
	if (mtime) *mtime = st.st_mtime;
	if (atime) *atime = st.st_atime;

	return 0;
}

static void update_file_attrs(struct file_state *state, const char *filepath)
{
	get_file_attrs(filepath, &state->size, &state->mtime, &state->atime);
}

static int was_file_read(struct file_state *state, const char *filepath)
{
	time_t current_atime;

	if (get_file_attrs(filepath, NULL, NULL, &current_atime) != 0) {
		return 0;
	}

	if (state->is_new_file && current_atime == state->atime) {
		return 0;
	}

	if (current_atime > state->atime) {
		return 1;
	}

	return 0;
}

static int was_file_written(struct file_state *state, const char *filepath)
{
	off_t current_size;
	time_t current_mtime;

	if (get_file_attrs(filepath, &current_size, &current_mtime, NULL) != 0) {
		return 0;
	}

	if (current_size != state->size || current_mtime != state->mtime) {
		return 1;
	}

	return 0;
}

static int is_text_file(const char *filename)
{
	const char *text_extensions[] = {".txt", ".log", ".conf", ".cfg",
					 ".ini", ".c", ".h", ".cpp", ".py",
					 ".sh", ".md", ".json", ".xml",
					 ".yaml", ".yml", NULL};
	const char *ext;
	int i;

	if (filename == NULL) return 0;

	ext = strrchr(filename, '.');
	if (ext == NULL) return 0;

	for (i = 0; text_extensions[i] != NULL; i++) {
		if (strcmp(ext, text_extensions[i]) == 0) {
			return 1;
		}
	}

	return 0;
}

static struct file_state* find_file_state(const char *filepath)
{
	struct file_state *cur;
	for (cur = file_states_head; cur; cur = cur->next) {
		if (cur->filepath && strcmp(cur->filepath, filepath) == 0) {
			return cur;
		}
	}
	return NULL;
}

static struct file_state* get_file_state(const char *filepath)
{
	struct file_state *new_state;
	struct file_state *existing;

	existing = find_file_state(filepath);
	if (existing) {
		return existing;
	}

	if (file_states_ctx == NULL) {
		file_states_ctx = talloc_named_const(NULL, 0,
						     "file_logger_states");
		if (file_states_ctx == NULL) return NULL;
	}

	new_state = talloc_zero(file_states_ctx, struct file_state);
	if (new_state == NULL) return NULL;

	new_state->filepath = talloc_strdup(new_state, filepath);
	if (new_state->filepath == NULL) {
		TALLOC_FREE(new_state);
		return NULL;
	}

	new_state->next = file_states_head;
	file_states_head = new_state;

	return new_state;
}

static void remove_file_state(const char *filepath)
{
	struct file_state **pp = &file_states_head;
	struct file_state *del;
	while (*pp) {
		if ((*pp)->filepath && strcmp((*pp)->filepath, filepath) == 0) {
			del = *pp;
			*pp = del->next;
			TALLOC_FREE(del);
			return;
		}
		pp = &(*pp)->next;
	}
}

static void log_directory_nested_files(vfs_handle_struct *handle,
				       const char *dir_path)
{
	DIR *dir;
	struct dirent *entry;
	struct stat st;
	char *entry_path;
	struct file_state *state;

	dir = opendir(dir_path);
	if (dir == NULL) {
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		entry_path = talloc_asprintf(talloc_tos(), "%s/%s",
					     dir_path, entry->d_name);
		if (entry_path == NULL) {
			continue;
		}

		if (lstat(entry_path, &st) != 0) {
			TALLOC_FREE(entry_path);
			continue;
		}

		if (S_ISLNK(st.st_mode)) {
			log_operation(handle, entry_path, "SymlinkDelete");
			remove_file_state(entry_path);
		} else if (S_ISDIR(st.st_mode)) {
			log_directory_nested_files(handle, entry_path);
			log_operation(handle, entry_path, "DirDelete");
			remove_file_state(entry_path);
		} else if (S_ISREG(st.st_mode)) {
			state = find_file_state(entry_path);
			if (state && state->open_count > 0 &&
			    was_file_written(state, entry_path)) {
				log_operation(handle, entry_path, "Write");
				update_file_attrs(state, entry_path);
			} else if (state && state->open_count > 0 &&
				   was_file_read(state, entry_path)) {
				log_operation(handle, entry_path, "Read");
			}
			log_operation(handle, entry_path, "Delete");
			remove_file_state(entry_path);
		}

		TALLOC_FREE(entry_path);
	}

	closedir(dir);
}

static int is_duplicate_operation(struct file_state *state,
				 const char *action, time_t now)
{
	if (!state) return 0;

	if (strcmp(action, "Open") == 0) {
		if (state->last_open_time >= now - 3) {
			state->open_sequence++;
			if (state->open_sequence > 1) {
				return 1;
			}
		} else {
			state->open_sequence = 1;
			state->last_open_time = now;
			return 0;
		}
		return 0;
	} else if (strcmp(action, "Read") == 0) {
		if (state->last_read_time >= now - 2) return 1;
		state->last_read_time = now;
	} else if (strcmp(action, "Write") == 0) {
		if (state->last_write_time >= now - 2) return 1;
		state->last_write_time = now;
	} else if (strcmp(action, "Delete") == 0) {
		if (state->last_delete_time == now) return 1;
		state->last_delete_time = now;
    } else if (strcmp(action, "MkDir") == 0) {
        if (state->last_mkdir_time == now) return 1;
        state->last_mkdir_time = now;
    } else if (strcmp(action, "DirDelete") == 0) {
        if (state->last_dirdelete_time == now) return 1;
        state->last_dirdelete_time = now;
    } else if (strcmp(action, "SymlinkCreate") == 0 ||
               strcmp(action, "SymlinkRead") == 0 ||
               strcmp(action, "SymlinkDelete") == 0) {
        if (state->last_symlink_time == now) return 1;
        state->last_symlink_time = now;
    }

	return 0;
}

static void log_operation(vfs_handle_struct *handle, const char *filepath,
			  const char *action)
{
	char *log_entry = NULL;
	char *current_time = NULL;
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char *existing_content = NULL;
	char *final_content = NULL;
	char *filepath_line = NULL;
	char *block_start = NULL;
	char *block_end = NULL;
	char *logs_start = NULL;
	char *search_start = NULL;
	char *summary_start = NULL;
	char *logs_header = NULL;
	char *summary_line = NULL;
	char *before_block = NULL;
	char *after_block = NULL;
	char *new_logs = NULL;
	int fd = -1;
	int open_count = 0, read_count = 0, write_count = 0;
	ssize_t bytes_read = 0;
	ssize_t total_read = 0;
	struct stat log_st;
	const char *log_path;
	const char *user;
	struct file_state *state;
	int init_open, init_read, init_write;

	log_path = get_log_path(handle);
	user = get_current_user(handle);
	state = get_file_state(filepath);

	if (!state) return;

	if (is_duplicate_operation(state, action, now)) {
		DEBUG(10, ("FILE_LOGGER: Skipping duplicate %s for %s\n",
			   action, filepath));
		return;
	}

	current_time = talloc_asprintf(talloc_tos(),
				      "%04d-%02d-%02d %02d:%02d:%02d",
				      tm_info->tm_year + 1900,
				      tm_info->tm_mon + 1,
				      tm_info->tm_mday,
				      tm_info->tm_hour,
				      tm_info->tm_min,
				      tm_info->tm_sec);

	log_entry = talloc_asprintf(talloc_tos(),
				    "datetime=%s\tuser=%s\taction=%s\n",
				    current_time, user, action);

	DEBUG(0, ("FILE_LOGGER: [pid=%d] %s - %s\n", (int)getpid(), action, filepath));

	fd = open(log_path, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		DEBUG(0, ("FILE_LOGGER: ERROR - cannot open log file %s: %s\n",
			  log_path, strerror(errno)));
		goto done;
	}

	if (flock(fd, LOCK_EX) != 0) {
		DEBUG(0, ("FILE_LOGGER: ERROR - cannot lock log file %s: %s\n",
			  log_path, strerror(errno)));
		close(fd);
		goto done;
	}

	if (fstat(fd, &log_st) == 0 && log_st.st_size > 0) {
		existing_content = talloc_size(talloc_tos(),
					       log_st.st_size + 1);
		if (existing_content) {
			total_read = 0;
			while (total_read < log_st.st_size) {
				bytes_read = read(fd, existing_content + total_read,
						  log_st.st_size - total_read);
				if (bytes_read <= 0) break;
				total_read += bytes_read;
			}
			if (total_read > 0) {
				existing_content[total_read] = '\0';
			}
		}
	}

	if (!existing_content) {
		existing_content = talloc_strdup(talloc_tos(), "");
	}

	filepath_line = talloc_asprintf(talloc_tos(), "FILE- %s\n", filepath);

	block_start = NULL;
	if (strncmp(existing_content, filepath_line,
		    strlen(filepath_line)) == 0) {
		block_start = existing_content;
	} else {
		char *sep = talloc_asprintf(talloc_tos(), "\n\n\n%s",
					    filepath_line);
		char *found = strstr(existing_content, sep);
		if (found) {
			block_start = found + 3;
		}
		TALLOC_FREE(sep);
	}

	if (block_start != NULL) {
		search_start = block_start + strlen(filepath_line);
		block_end = strstr(search_start, "\n\n\nFILE- ");
		if (block_end != NULL) {
			block_end += 3;
		} else {
			block_end = existing_content + strlen(existing_content);
		}

		summary_start = strchr(block_start, '\n');
		if (summary_start) {
			summary_start++;
			logs_header = strstr(summary_start, "LOGS:\n");
			if (logs_header) {
				summary_line = talloc_strndup(talloc_tos(),
							      summary_start,
							      logs_header -
							      summary_start);
				sscanf(summary_line,
				       "SUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d",
				       &open_count, &read_count, &write_count);
				TALLOC_FREE(summary_line);

				if (strcmp(action, "Open") == 0) open_count++;
				else if (strcmp(action, "Read") == 0) read_count++;
				else if (strcmp(action, "Write") == 0) write_count++;

				before_block = talloc_strndup(talloc_tos(),
							      existing_content,
							      block_start -
							      existing_content);
				after_block = talloc_strdup(talloc_tos(), block_end);

				if (logs_header) {
					logs_start = logs_header + 6;
					new_logs = talloc_asprintf(talloc_tos(),
								   "LOGS:\n%s%s",
								   logs_start,
								   log_entry);
				} else {
					new_logs = talloc_asprintf(talloc_tos(),
								   "LOGS:\n%s",
								   log_entry);
				}

				if (after_block && after_block[0] != '\0') {
				final_content = talloc_asprintf(talloc_tos(),
					"%sFILE- %s\nSUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d\n%s\n\n%s",
					before_block, filepath,
					open_count, read_count, write_count,
					new_logs, after_block);
			} else {
				final_content = talloc_asprintf(talloc_tos(),
					"%sFILE- %s\nSUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d\n%s",
					before_block, filepath,
					open_count, read_count, write_count,
					new_logs);
			}

				TALLOC_FREE(before_block);
				TALLOC_FREE(after_block);
				TALLOC_FREE(new_logs);
			}
		}
	} else {
		init_open = (strcmp(action, "Open") == 0) ? 1 : 0;
		init_read = (strcmp(action, "Read") == 0) ? 1 : 0;
		init_write = (strcmp(action, "Write") == 0) ? 1 : 0;

		if (state->is_new_file && init_write && !init_read) {
			init_read = 0;
		}

		if (existing_content[0] != '\0') {
			final_content = talloc_asprintf(talloc_tos(),
				"%s\n\nFILE- %s\nSUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d\nLOGS:\n%s",
				existing_content, filepath,
				init_open, init_read, init_write,
				log_entry);
		} else {
			final_content = talloc_asprintf(talloc_tos(),
				"FILE- %s\nSUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d\nLOGS:\n%s",
				filepath,
				init_open, init_read, init_write,
				log_entry);
		}
	}

	if (final_content) {
		if (lseek(fd, 0, SEEK_SET) != 0) {
			DEBUG(0, ("FILE_LOGGER: ERROR - cannot seek: %s\n",
				  strerror(errno)));
		}
		if (ftruncate(fd, 0) != 0) {
			DEBUG(0, ("FILE_LOGGER: ERROR - cannot truncate: %s\n",
				  strerror(errno)));
		}
		write(fd, final_content, strlen(final_content));
	}

	flock(fd, LOCK_UN);
	close(fd);

done:
	TALLOC_FREE(current_time);
	TALLOC_FREE(log_entry);
	TALLOC_FREE(existing_content);
	TALLOC_FREE(final_content);
	TALLOC_FREE(filepath_line);
}

static int file_logger_openat(vfs_handle_struct *handle,
			      const struct files_struct *dirfsp,
			      const struct smb_filename *smb_fname,
			      struct files_struct *fsp,
			      const struct vfs_open_how *how)
{
	int result;
	char *full_path = NULL;
	struct stat st;
	struct file_state *state = NULL;

	if (smb_fname && smb_fname->base_name &&
	    is_text_file(smb_fname->base_name)) {
		full_path = resolve_path(handle, dirfsp, smb_fname);
		if (full_path) {
			state = get_file_state(full_path);
			if (state) {
				if (state->open_count == 0) {
					if (stat(full_path, &st) != 0) {
						state->is_new_file = 1;
					} else {
						state->is_new_file = 0;
					}
					update_file_attrs(state, full_path);
				}
				state->open_count++;
				log_operation(handle, full_path, "Open");
			}
			TALLOC_FREE(full_path);
		}
	}

	result = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
	return result;
}

static int file_logger_close(vfs_handle_struct *handle,
			     struct files_struct *fsp)
{
	int result;
	char *full_path = NULL;
	struct file_state *state = NULL;

	if (fsp && fsp->fsp_name && fsp->fsp_name->base_name &&
	    is_text_file(fsp->fsp_name->base_name)) {
		full_path = get_full_path(handle, fsp->fsp_name);
		if (full_path) {
			state = find_file_state(full_path);

			if (state && state->open_count > 0) {
				state->open_count--;

				if (fsp->access_mask & SEC_FILE_WRITE_DATA) {
					log_operation(handle, full_path,
						      "Write");
				}
				else if (fsp->access_mask & SEC_FILE_READ_DATA) {
					log_operation(handle, full_path,
						      "Read");
				}

				if (state->open_count == 0) {
					remove_file_state(full_path);
				}
			}
			TALLOC_FREE(full_path);
		}
	}

	result = SMB_VFS_NEXT_CLOSE(handle, fsp);
	return result;
}

static int file_logger_unlinkat(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				int flags)
{
	int result;
	char *full_path = NULL;
	struct stat st;

	if (smb_fname && smb_fname->base_name) {
		full_path = resolve_path(handle, dirfsp, smb_fname);
		if (full_path) {
			if (flags & AT_REMOVEDIR) {
				log_directory_nested_files(handle, full_path);
				log_operation(handle, full_path, "DirDelete");
				remove_file_state(full_path);
			} else {
				if (lstat(full_path, &st) == 0 &&
				    S_ISLNK(st.st_mode)) {
					log_operation(handle, full_path,
						      "SymlinkDelete");
					remove_file_state(full_path);
				} else if (is_text_file(smb_fname->base_name)) {
					log_operation(handle, full_path,
						      "Delete");
					remove_file_state(full_path);
				}
			}
			TALLOC_FREE(full_path);
		}
	}

	result = SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
	return result;
}

static int file_logger_mkdirat(vfs_handle_struct *handle,
			       struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       mode_t mode)
{
	int result;
	char *full_path = NULL;

	result = SMB_VFS_NEXT_MKDIRAT(handle, dirfsp, smb_fname, mode);

	if (smb_fname && smb_fname->base_name) {
		full_path = resolve_mkdir_path(handle, dirfsp, smb_fname);
		if (full_path) {
			log_operation(handle, full_path, "MkDir");
			TALLOC_FREE(full_path);
		}
	}

	return result;
}

static int file_logger_symlinkat(vfs_handle_struct *handle,
				 const struct smb_filename *link_contents,
				 struct files_struct *dirfsp,
				 const struct smb_filename *new_smb_fname)
{
	int result;
	char *full_path = NULL;

	result = SMB_VFS_NEXT_SYMLINKAT(handle, link_contents, dirfsp,
					new_smb_fname);

	if (new_smb_fname && new_smb_fname->base_name) {
		full_path = resolve_path(handle, dirfsp, new_smb_fname);
		if (full_path) {
			log_operation(handle, full_path, "SymlinkCreate");
			TALLOC_FREE(full_path);
		}
	}

	return result;
}

static int file_logger_readlinkat(vfs_handle_struct *handle,
				  const struct files_struct *dirfsp,
				  const struct smb_filename *smb_fname,
				  char *buf,
				  size_t bufsiz)
{
	int result;
	char *full_path = NULL;

	result = SMB_VFS_NEXT_READLINKAT(handle, dirfsp, smb_fname,
					 buf, bufsiz);

	if (smb_fname && smb_fname->base_name) {
		full_path = resolve_path(handle, dirfsp, smb_fname);
		if (full_path) {
			log_operation(handle, full_path, "SymlinkRead");
			TALLOC_FREE(full_path);
		}
	}

	return result;
}

static struct vfs_fn_pointers vfs_file_logger_fns = {
	.openat_fn = file_logger_openat,
	.close_fn = file_logger_close,
	.unlinkat_fn = file_logger_unlinkat,
	.mkdirat_fn = file_logger_mkdirat,
	.symlinkat_fn = file_logger_symlinkat,
	.readlinkat_fn = file_logger_readlinkat,
};

NTSTATUS vfs_file_logger_init(TALLOC_CTX *ctx)
{
	DEBUG(0, ("========================================\n"));
	DEBUG(0, ("FILE_LOGGER MODULE LOADED SUCCESSFULLY\n"));
	DEBUG(0, ("FILE_LOGGER: Tracking Open/Read/Write/Delete/DirOps/SymlinkOps\n"));
	DEBUG(0, ("========================================\n"));
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"file_logger",
				&vfs_file_logger_fns);
}
