#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"

static int recycle_bin_unlinkat(vfs_handle_struct *handle,
                               struct files_struct *dirfsp,
                               const struct smb_filename *smb_fname,
                               int flags)
{
    const char *backup_path;
    char *backup_full_path;
    char *filename_only;
    char *timestamp;
    char *backup_filename;
    int fd_in, fd_out;
    char buffer[8192];
    ssize_t nread;
    int ret = 0;
    time_t now;
    struct tm *tm_info;
    
    /* Получаем путь для бэкапа из конфига */
    backup_path = lp_parm_const_string(SNUM(handle->conn), "recycle_bin", "backup_path", 
                                       "/var/samba/recycle_bin");
    
    DEBUG(0, ("RECYCLE BIN: unlinkat called for %s\n", smb_fname->base_name));
    DEBUG(0, ("RECYCLE BIN: backup_path = %s\n", backup_path));
    
    /* Получаем только имя файла */
    filename_only = strrchr(smb_fname->base_name, '/');
    if (filename_only) {
        filename_only++;
    } else {
        filename_only = (char *)smb_fname->base_name;
    }
    
    DEBUG(0, ("RECYCLE BIN: filename = %s\n", filename_only));
    
    /* Создаем временную метку */
    now = time(NULL);
    tm_info = localtime(&now);
    timestamp = talloc_asprintf(talloc_tos(), "%04d%02d%02d_%02d%02d%02d",
                                tm_info->tm_year + 1900,
                                tm_info->tm_mon + 1,
                                tm_info->tm_mday,
                                tm_info->tm_hour,
                                tm_info->tm_min,
                                tm_info->tm_sec);
    
    /* Формируем имя для бэкапа */
    backup_filename = talloc_asprintf(talloc_tos(), "%s_%s", filename_only, timestamp);
    
    /* Формируем полный путь для бэкапа */
    backup_full_path = talloc_asprintf(talloc_tos(), "%s/%s", 
                                      backup_path, backup_filename);
    
    DEBUG(0, ("RECYCLE BIN: backup_full_path = %s\n", backup_full_path));
    
    /* Создаем директорию для бэкапов */
    ret = mkdir(backup_path, 0755);
    if (ret != 0 && errno != EEXIST) {
        DEBUG(0, ("RECYCLE BIN: ERROR - cannot create backup dir: %s\n", 
                  strerror(errno)));
        goto done;
    }
    
    /* Копируем файл вручную */
    fd_in = open(smb_fname->base_name, O_RDONLY);
    if (fd_in == -1) {
        DEBUG(0, ("RECYCLE BIN: ERROR - cannot open source file: %s\n", 
                  strerror(errno)));
        ret = -1;
        goto done;
    }
    
    fd_out = open(backup_full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out == -1) {
        DEBUG(0, ("RECYCLE BIN: ERROR - cannot create backup file: %s\n", 
                  strerror(errno)));
        close(fd_in);
        ret = -1;
        goto done;
    }
    
    while ((nread = read(fd_in, buffer, sizeof(buffer))) > 0) {
        if (write(fd_out, buffer, nread) != nread) {
            DEBUG(0, ("RECYCLE BIN: ERROR - write failed: %s\n", 
                      strerror(errno)));
            ret = -1;
            break;
        }
    }
    
    close(fd_in);
    close(fd_out);
    
    if (ret == 0) {
        DEBUG(0, ("RECYCLE BIN: SUCCESS - backed up to %s\n", backup_full_path));
    }
    
done:
    TALLOC_FREE(timestamp);
    TALLOC_FREE(backup_filename);
    TALLOC_FREE(backup_full_path);
    
    /* Выполняем оригинальное удаление */
    return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
}

static struct vfs_fn_pointers vfs_recycle_bin_fns = {
    .unlinkat_fn = recycle_bin_unlinkat,
};

NTSTATUS samba_init_module(TALLOC_CTX *ctx)
{
    DEBUG(0, ("RECYCLE BIN MODULE LOADED SUCCESSFULLY\n"));
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, 
                           "recycle_bin", 
                           &vfs_recycle_bin_fns);
}
