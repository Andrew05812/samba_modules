#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>

/* Структура для хранения состояния файла */
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
    int open_sequence;
    int is_new_file;
};

static struct file_state file_states[256];
static int num_states = 0;

/* Функция получения пользователя */
static const char* get_current_user(vfs_handle_struct *handle)
{
    uid_t uid = geteuid();
    struct passwd *pw = getpwuid(uid);
    if (pw && pw->pw_name) {
        return pw->pw_name;
    }
    return "unknown";
}

/* Функция получения полного пути к файлу */
static char* get_full_path(vfs_handle_struct *handle, const struct smb_filename *smb_fname)
{
    char *full_path = NULL;
    const char *share_path = handle->conn->connectpath;

    if (share_path && smb_fname && smb_fname->base_name) {
        if (smb_fname->base_name[0] == '/') {
            full_path = talloc_asprintf(talloc_tos(), "%s", smb_fname->base_name);
        } else {
            full_path = talloc_asprintf(talloc_tos(), "%s/%s", share_path, smb_fname->base_name);
        }
    }

    return full_path;
}

/* Функция получения пути к лог-файлу */
static const char* get_log_path(vfs_handle_struct *handle)
{
    const char *log_path = lp_parm_const_string(SNUM(handle->conn), "file_logger", "log_path",
                                                "/var/samba/file_logger.log");
    return log_path;
}

/* Функция получения атрибутов файла */
static int get_file_attrs(const char *filepath, off_t *size, time_t *mtime, time_t *atime)
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

/* Функция обновления атрибутов файла */
static void update_file_attrs(struct file_state *state, const char *filepath)
{
    get_file_attrs(filepath, &state->size, &state->mtime, &state->atime);
}

/* Функция проверки, был ли файл прочитан */
static int was_file_read(struct file_state *state, const char *filepath)
{
    time_t current_atime;

    if (get_file_attrs(filepath, NULL, NULL, &current_atime) != 0) {
        return 0;
    }

    /* Для новых файлов не логируем Read при создании */
    if (state->is_new_file && current_atime == state->atime) {
        return 0;
    }

    if (current_atime > state->atime) {
        return 1;
    }

    return 0;
}

/* Функция проверки, был ли файл изменен */
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

/* Функция проверки, является ли файл текстовым */
static int is_text_file(const char *filename)
{
    const char *text_extensions[] = {".txt", ".log", ".conf", ".cfg", ".ini",
                                      ".c", ".h", ".cpp", ".py", ".sh", ".md",
                                      ".json", ".xml", ".yaml", ".yml", NULL};
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

/* Функция получения состояния файла */
static struct file_state* get_file_state(const char *filepath)
{
    int i;
    for (i = 0; i < num_states; i++) {
        if (file_states[i].filepath && strcmp(file_states[i].filepath, filepath) == 0) {
            return &file_states[i];
        }
    }

    if (num_states < 256) {
        file_states[num_states].filepath = strdup(filepath);
        file_states[num_states].size = 0;
        file_states[num_states].mtime = 0;
        file_states[num_states].atime = 0;
        file_states[num_states].open_count = 0;
        file_states[num_states].last_open_time = 0;
        file_states[num_states].last_read_time = 0;
        file_states[num_states].last_write_time = 0;
        file_states[num_states].last_delete_time = 0;
        file_states[num_states].open_sequence = 0;
        file_states[num_states].is_new_file = 0;
        return &file_states[num_states++];
    }

    return NULL;
}

/* Функция удаления состояния файла */
static void remove_file_state(const char *filepath)
{
    int i;
    for (i = 0; i < num_states; i++) {
        if (file_states[i].filepath && strcmp(file_states[i].filepath, filepath) == 0) {
            free(file_states[i].filepath);
            for (int j = i; j < num_states - 1; j++) {
                file_states[j] = file_states[j + 1];
            }
            num_states--;
            break;
        }
    }
}

/* Функция проверки дубликата операции */
static int is_duplicate_operation(struct file_state *state, const char *action, time_t now)
{
    if (!state) return 0;

    if (strcmp(action, "Open") == 0) {
        /* Разрешаем только 1 Open за 3 секунды */
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
        /* Разрешаем только 1 Read за 2 секунды */
        if (state->last_read_time >= now - 2) return 1;
        state->last_read_time = now;
    } else if (strcmp(action, "Write") == 0) {
        /* Разрешаем только 1 Write за 2 секунды */
        if (state->last_write_time >= now - 2) return 1;
        state->last_write_time = now;
    } else if (strcmp(action, "Delete") == 0) {
        if (state->last_delete_time == now) return 1;
        state->last_delete_time = now;
    }

    return 0;
}

/* Функция обновления лог-файла */
static void update_log_file(const char *log_path, const char *new_content)
{
    int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd != -1) {
        write(fd, new_content, strlen(new_content));
        close(fd);
    } else {
        DEBUG(0, ("FILE_LOGGER: ERROR - cannot write to log file %s: %s\n",
                  log_path, strerror(errno)));
    }
}

/* Функция логирования операции */
static void log_operation(vfs_handle_struct *handle, const char *filepath, const char *action)
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
    int fd = -1;
    int open_count = 0, read_count = 0, write_count = 0;
    const char *log_path = get_log_path(handle);
    const char *user = get_current_user(handle);
    struct file_state *state = get_file_state(filepath);

    if (!state) return;

    if (is_duplicate_operation(state, action, now)) {
        DEBUG(10, ("FILE_LOGGER: Skipping duplicate %s for %s\n", action, filepath));
        return;
    }

    current_time = talloc_asprintf(talloc_tos(), "%04d-%02d-%02d %02d:%02d:%02d",
                                   tm_info->tm_year + 1900,
                                   tm_info->tm_mon + 1,
                                   tm_info->tm_mday,
                                   tm_info->tm_hour,
                                   tm_info->tm_min,
                                   tm_info->tm_sec);

    log_entry = talloc_asprintf(talloc_tos(), "datetime=%s\tuser=%s\taction=%s\n",
                               current_time, user, action);

    DEBUG(0, ("FILE_LOGGER: %s - %s\n", action, filepath));

    /* Читаем существующий лог */
    fd = open(log_path, O_RDONLY);
    if (fd != -1) {
        struct stat log_st;
        if (fstat(fd, &log_st) == 0 && log_st.st_size > 0) {
            existing_content = talloc_size(talloc_tos(), log_st.st_size + 1);
            if (existing_content) {
                ssize_t bytes_read = read(fd, existing_content, log_st.st_size);
                if (bytes_read > 0) {
                    existing_content[bytes_read] = '\0';
                }
            }
        }
        close(fd);
    }

    if (!existing_content) {
        existing_content = talloc_strdup(talloc_tos(), "");
    }

    filepath_line = talloc_asprintf(talloc_tos(), "FILE- %s\n", filepath);
    block_start = strstr(existing_content, filepath_line);

    if (block_start != NULL) {
        char *search_start = block_start + strlen(filepath_line);
        block_end = strstr(search_start, "\n\n\n");
        if (block_end == NULL) {
            block_end = existing_content + strlen(existing_content);
        } else {
            block_end += 3;
        }

        char *summary_start = strchr(block_start, '\n');
        if (summary_start) {
            summary_start++;
            char *logs_header = strstr(summary_start, "LOGS:\n");
            if (logs_header) {
                char *summary_line = talloc_strndup(talloc_tos(), summary_start,
                                                   logs_header - summary_start);
                sscanf(summary_line, "SUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d",
                       &open_count, &read_count, &write_count);
                TALLOC_FREE(summary_line);

                if (strcmp(action, "Open") == 0) open_count++;
                else if (strcmp(action, "Read") == 0) read_count++;
                else if (strcmp(action, "Write") == 0) write_count++;

                char *before_block = talloc_strndup(talloc_tos(), existing_content,
                                                   block_start - existing_content);
                char *after_block = talloc_strdup(talloc_tos(), block_end);
                char *new_logs = NULL;

                if (logs_header) {
                    logs_start = logs_header + 6;
                    new_logs = talloc_asprintf(talloc_tos(), "LOGS:\n%s%s",
                                              logs_start, log_entry);
                } else {
                    new_logs = talloc_asprintf(talloc_tos(), "LOGS:\n%s", log_entry);
                }

                final_content = talloc_asprintf(talloc_tos(), "%sFILE- %s\nSUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d\n%s%s",
                                               before_block, filepath, open_count, read_count, write_count,
                                               new_logs, after_block);

                TALLOC_FREE(before_block);
                TALLOC_FREE(after_block);
                TALLOC_FREE(new_logs);
            }
        }
    } else {
        int init_open = (strcmp(action, "Open") == 0) ? 1 : 0;
        int init_read = (strcmp(action, "Read") == 0) ? 1 : 0;
        int init_write = (strcmp(action, "Write") == 0) ? 1 : 0;

        /* Для нового файла, если первая операция Write, не добавляем Read */
        if (state->is_new_file && init_write && !init_read) {
            init_read = 0;
        }

        if (existing_content[0] != '\0') {
            final_content = talloc_asprintf(talloc_tos(), "%s\n\n\nFILE- %s\nSUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d\nLOGS:\n%s",
                                           existing_content, filepath,
                                           init_open, init_read, init_write,
                                           log_entry);
        } else {
            final_content = talloc_asprintf(talloc_tos(), "FILE- %s\nSUMMARY OPERATIONS: Open - %d, Read - %d, Write - %d\nLOGS:\n%s",
                                           filepath,
                                           init_open, init_read, init_write,
                                           log_entry);
        }
    }

    if (final_content) {
        update_log_file(log_path, final_content);
    }

    TALLOC_FREE(current_time);
    TALLOC_FREE(log_entry);
    TALLOC_FREE(existing_content);
    TALLOC_FREE(final_content);
    TALLOC_FREE(filepath_line);
}

/* Перехват операции openat */
static int file_logger_openat(vfs_handle_struct *handle,
                              const struct files_struct *dirfsp,
                              const struct smb_filename *smb_fname,
                              struct files_struct *fsp,
                              const struct vfs_open_how *how)
{
    int result;
    char *full_path = NULL;
    struct stat st;

    if (smb_fname && smb_fname->base_name && is_text_file(smb_fname->base_name)) {
        full_path = get_full_path(handle, smb_fname);
        if (full_path) {
            struct file_state *state = get_file_state(full_path);
            if (state) {
                /* Проверяем, существует ли файл (новый ли он) */
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

/* Перехват операции close - здесь определяем Read и Write */
static int file_logger_close(vfs_handle_struct *handle, struct files_struct *fsp)
{
    int result;
    char *full_path = NULL;

    if (fsp && fsp->fsp_name && fsp->fsp_name->base_name &&
        is_text_file(fsp->fsp_name->base_name)) {
        full_path = get_full_path(handle, fsp->fsp_name);
        if (full_path) {
            struct file_state *state = get_file_state(full_path);

            if (state && state->open_count > 0) {
                state->open_count--;

                /* Проверяем, был ли файл изменен (сначала Write) */
                if (was_file_written(state, full_path)) {
                    log_operation(handle, full_path, "Write");
                    update_file_attrs(state, full_path);
                }
                /* Затем проверяем, был ли файл прочитан (только если не было Write) */
                else if (was_file_read(state, full_path)) {
                    log_operation(handle, full_path, "Read");
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

/* Перехват операции unlinkat */
static int file_logger_unlinkat(vfs_handle_struct *handle,
                               struct files_struct *dirfsp,
                               const struct smb_filename *smb_fname,
                               int flags)
{
    int result;
    char *full_path = NULL;

    if (smb_fname && smb_fname->base_name && is_text_file(smb_fname->base_name)) {
        full_path = get_full_path(handle, smb_fname);
        if (full_path) {
            log_operation(handle, full_path, "Delete");
            remove_file_state(full_path);
            TALLOC_FREE(full_path);
        }
    }

    result = SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
    return result;
}

/* Структура с указателями на функции VFS */
static struct vfs_fn_pointers vfs_file_logger_fns = {
    .openat_fn = file_logger_openat,
    .close_fn = file_logger_close,
    .unlinkat_fn = file_logger_unlinkat,
};

/* Функция инициализации модуля */
NTSTATUS vfs_file_logger_init(TALLOC_CTX *ctx)
{
    DEBUG(0, ("========================================\n"));
    DEBUG(0, ("FILE_LOGGER MODULE LOADED SUCCESSFULLY\n"));
    DEBUG(0, ("FILE_LOGGER: Tracking Open/Read/Write/Delete via file attributes\n"));
    DEBUG(0, ("========================================\n"));
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
                           "file_logger",
                           &vfs_file_logger_fns);
}
