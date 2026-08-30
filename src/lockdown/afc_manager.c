#include "l0fck.h"
#include "lockdown/afc_manager.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int get_afc_client(idevice_t dev, lockdownd_client_t ld, afc_client_t *out_afc)
{
    if (!dev || !ld || !out_afc) return -1;
    *out_afc = NULL;

    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = lockdownd_start_service(ld, "com.apple.afc", &desc);
    if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
        LOG_INFO("get_afc_client: Session inactive (Error -23). Attempting escrow bag negotiation...");
        lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.afc", &desc);
    }
    if (lerr != LOCKDOWN_E_SUCCESS || !desc) {
        LOG_ERROR("Failed to start com.apple.afc service (error %d)", lerr);
        return -1;
    }

    afc_client_t afc = NULL;
    afc_error_t aerr = afc_client_new(dev, desc, &afc);
    lockdownd_service_descriptor_free(desc);

    if (aerr != AFC_E_SUCCESS || !afc) {
        LOG_ERROR("Failed to connect AFC client (error %d)", aerr);
        return -1;
    }

    *out_afc = afc;
    return 0;
}

int afc_manager_list_dir(idevice_t dev, lockdownd_client_t ld, const char *path)
{
    afc_client_t afc = NULL;
    if (get_afc_client(dev, ld, &afc) != 0 || !afc) return -1;

    const char *target_path = (path && *path) ? path : "/";
    char **dir_list = NULL;
    afc_error_t err = afc_read_directory(afc, target_path, &dir_list);
    if (err != AFC_E_SUCCESS || !dir_list) {
        LOG_ERROR("afc_read_directory failed for '%s' (error %d)", target_path, err);
        afc_client_free(afc);
        return -1;
    }

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "Listing Media Partition Path: %s" ANSI_COLOR_RESET "\n", target_path);
    printf("--------------------------------------------------------------------\n");
    for (int i = 0; dir_list[i] != NULL; i++) {
        if (strcmp(dir_list[i], ".") == 0 || strcmp(dir_list[i], "..") == 0) continue;

        char subpath[1024];
        if (strcmp(target_path, "/") == 0) {
            snprintf(subpath, sizeof(subpath), "/%s", dir_list[i]);
        } else {
            snprintf(subpath, sizeof(subpath), "%s/%s", target_path, dir_list[i]);
        }

        char **file_info = NULL;
        afc_get_file_info(afc, subpath, &file_info);
        const char *type = "file";
        const char *size = "0";

        if (file_info) {
            for (int k = 0; file_info[k] != NULL; k += 2) {
                if (strcmp(file_info[k], "st_ifmt") == 0) {
                    type = strcmp(file_info[k+1], "S_IFDIR") == 0 ? "dir " : "file";
                } else if (strcmp(file_info[k], "st_size") == 0) {
                    size = file_info[k+1];
                }
            }
        }

        printf("  [%s] %10s bytes  %s\n", type, size, dir_list[i]);
        if (file_info) afc_dictionary_free(file_info);
    }
    printf("--------------------------------------------------------------------\n\n");

    afc_dictionary_free(dir_list);
    afc_client_free(afc);
    return 0;
}

int afc_manager_pull_file(idevice_t dev, lockdownd_client_t ld, const char *remote_path, const char *local_path)
{
    if (!remote_path || !local_path) return -1;
    afc_client_t afc = NULL;
    if (get_afc_client(dev, ld, &afc) != 0 || !afc) return -1;

    uint64_t handle = 0;
    afc_error_t err = afc_file_open(afc, remote_path, AFC_FOPEN_RDONLY, &handle);
    if (err != AFC_E_SUCCESS) {
        LOG_ERROR("Failed to open remote file '%s' (error %d)", remote_path, err);
        afc_client_free(afc);
        return -1;
    }

    FILE *local_f = fopen(local_path, "wb");
    if (!local_f) {
        LOG_ERROR("Failed to create local file '%s'", local_path);
        afc_file_close(afc, handle);
        afc_client_free(afc);
        return -1;
    }

    char chunk[8192];
    uint32_t bytes_read = 0;
    size_t total_transferred = 0;

    while (afc_file_read(afc, handle, chunk, sizeof(chunk), &bytes_read) == AFC_E_SUCCESS && bytes_read > 0) {
        fwrite(chunk, 1, bytes_read, local_f);
        total_transferred += bytes_read;
    }

    fclose(local_f);
    afc_file_close(afc, handle);
    afc_client_free(afc);

    LOG_SUCCESS("Successfully downloaded '%s' -> '%s' (%zu bytes)", remote_path, local_path, total_transferred);
    return 0;
}

int afc_mkdir_p(afc_client_t afc, const char *path)
{
    if (!afc || !path || !*path) return -1;

    char temp[1024];
    snprintf(temp, sizeof(temp), "%s", path);
    size_t len = strlen(temp);
    if (len == 0) return 0;

    /* Normalize leading slash and create intermediate directories */
    size_t start = (temp[0] == '/') ? 1 : 0;
    for (size_t i = start; i < len; i++) {
        if (temp[i] == '/') {
            temp[i] = '\0';
            if (strlen(temp) > 0) {
                afc_make_directory(afc, temp);
            }
            temp[i] = '/';
        }
    }
    afc_make_directory(afc, temp);
    return 0;
}

int afc_write_file_data(afc_client_t afc, const char *path, const char *buf, uint32_t len)
{
    if (!afc || !path || !buf || len == 0) return -1;

    // Strip duplicate or problematic slashes (basic normalization)
    char norm_path[1024];
    int j = 0;
    for (int i = 0; path[i] != '\0' && j < sizeof(norm_path) - 1; i++) {
        if (path[i] == '/' && (i > 0 && path[i-1] == '/')) continue;
        norm_path[j++] = path[i];
    }
    norm_path[j] = '\0';

    uint64_t handle = 0;
    // Attempt multiple valid AFC open modes
    afc_error_t err = afc_file_open(afc, norm_path, AFC_FOPEN_WRONLY, &handle);
    if (err != AFC_E_SUCCESS || handle == 0) {
        err = afc_file_open(afc, norm_path, AFC_FOPEN_RW, &handle);
    }
    if (err != AFC_E_SUCCESS || handle == 0) {
        err = afc_file_open(afc, norm_path, AFC_FOPEN_WR, &handle);
    }
    if (err != AFC_E_SUCCESS || handle == 0) {
        LOG_DEBUG("afc_write_file_data: Failed to open '%s' (AFC error %d)", norm_path, err);
        return -1;
    }

    uint32_t total_written = 0;
    while (total_written < len) {
        uint32_t chunk = len - total_written;
        if (chunk > 4096) chunk = 4096;
        uint32_t bytes_written = 0;
        err = afc_file_write(afc, handle, buf + total_written, chunk, &bytes_written);
        if (err != AFC_E_SUCCESS || bytes_written == 0) {
            break;
        }
        total_written += bytes_written;
    }

    afc_file_close(afc, handle);
    return (total_written == len) ? 0 : -1;
}

int afc_manager_push_file(idevice_t dev, lockdownd_client_t ld, const char *local_path, const char *remote_path)
{
    if (!local_path || !remote_path) return -1;
    FILE *local_f = fopen(local_path, "rb");
    if (!local_f) {
        LOG_ERROR("Failed to open local file '%s'", local_path);
        return -1;
    }

    afc_client_t afc = NULL;
    if (get_afc_client(dev, ld, &afc) != 0 || !afc) {
        fclose(local_f);
        return -1;
    }

    /* Ensure parent directories exist */
    const char *last_slash = strrchr(remote_path, '/');
    if (last_slash && last_slash != remote_path) {
        char dir_path[1024];
        size_t dlen = last_slash - remote_path;
        if (dlen < sizeof(dir_path)) {
            strncpy(dir_path, remote_path, dlen);
            dir_path[dlen] = '\0';
            afc_mkdir_p(afc, dir_path);
        }
    }

    uint64_t handle = 0;
    afc_error_t err = afc_file_open(afc, remote_path, AFC_FOPEN_WRONLY, &handle);
    if (err != AFC_E_SUCCESS || handle == 0) {
        err = afc_file_open(afc, remote_path, AFC_FOPEN_RW, &handle);
    }
    if (err != AFC_E_SUCCESS || handle == 0) {
        err = afc_file_open(afc, remote_path, AFC_FOPEN_WR, &handle);
    }
    if (err != AFC_E_SUCCESS || handle == 0) {
        LOG_ERROR("Failed to open remote destination '%s' (error %d)", remote_path, err);
        fclose(local_f);
        afc_client_free(afc);
        return -1;
    }

    char chunk[8192];
    size_t bytes_read = 0;
    size_t total_transferred = 0;

    while ((bytes_read = fread(chunk, 1, sizeof(chunk), local_f)) > 0) {
        uint32_t written = 0;
        err = afc_file_write(afc, handle, chunk, (uint32_t)bytes_read, &written);
        if (err != AFC_E_SUCCESS || written != bytes_read) {
            LOG_ERROR("Error writing to remote file '%s'", remote_path);
            break;
        }
        total_transferred += written;
    }

    fclose(local_f);
    afc_file_close(afc, handle);
    afc_client_free(afc);

    LOG_SUCCESS("Successfully uploaded '%s' -> '%s' (%zu bytes)", local_path, remote_path, total_transferred);
    return 0;
}

int afc_manager_write_test(idevice_t dev, lockdownd_client_t ld)
{
    afc_client_t afc = NULL;
    if (get_afc_client(dev, ld, &afc) != 0 || !afc) return -1;

    const char *test_path = "/_l0fck_test_write.tmp";
    const char *payload = "L0FCK_A18PRO_VULN02_CONFIRMED";
    uint32_t payload_len = (uint32_t)strlen(payload);

    uint64_t handle = 0;
    afc_error_t err = afc_file_open(afc, test_path, AFC_FOPEN_WRONLY, &handle);
    if (err != AFC_E_SUCCESS || handle == 0) {
        err = afc_file_open(afc, test_path, AFC_FOPEN_RW, &handle);
    }
    if (err != AFC_E_SUCCESS || handle == 0) {
        err = afc_file_open(afc, test_path, AFC_FOPEN_WR, &handle);
    }
    if (err != AFC_E_SUCCESS || handle == 0) {
        afc_client_free(afc);
        return -1;
    }

    uint32_t written = 0;
    afc_file_write(afc, handle, payload, payload_len, &written);
    afc_file_close(afc, handle);

    afc_remove_path(afc, test_path);
    afc_client_free(afc);

    return (written == payload_len) ? 0 : -1;
}
