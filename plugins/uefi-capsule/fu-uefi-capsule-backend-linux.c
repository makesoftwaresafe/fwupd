/*
 * Copyright 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <gio/gunixmounts.h>

#include "fu-uefi-capsule-backend-linux.h"
#include "fu-uefi-cod-device.h"
#include "fu-uefi-common.h"
#include "fu-uefi-nvram-device.h"

struct _FuUefiCapsuleBackendLinux {
	FuUefiCapsuleBackend parent_instance;
	gboolean use_rt_set_variable;
};

G_DEFINE_TYPE(FuUefiCapsuleBackendLinux,
	      fu_uefi_capsule_backend_linux,
	      FU_TYPE_UEFI_CAPSULE_BACKEND)

/* yes, unsized uint_t */
static guint
fu_uefi_capsule_backend_linux_read(const gchar *path, const gchar *filename)
{
	return fu_uefi_read_file_as_uint64(path, filename);
}

static FuUefiCapsuleDevice *
fu_uefi_capsule_backend_linux_device_new(FuUefiCapsuleBackendLinux *self,
					 const gchar *physical_id,
					 const gchar *path)
{
	g_autoptr(FuUefiCapsuleDevice) dev = NULL;
	g_autofree gchar *fw_class = NULL;
	g_autofree gchar *fw_class_fn = NULL;

	g_return_val_if_fail(path != NULL, NULL);

	/* read values from sysfs */
	fw_class_fn = g_build_filename(path, "fw_class", NULL);
	if (g_file_get_contents(fw_class_fn, &fw_class, NULL, NULL))
		g_strdelimit(fw_class, "\n", '\0');

	/* Create object, assuming a verfmt of NUMBER unless told otherwise by
	 * a quirk entry or metadata.
	 *
	 * The hardware instance is not in the ESRT table and we should really
	 * write the EFI stub to query with FMP -- but we still have not ever
	 * seen a PCIe device with FMP support... */
	dev = g_object_new(fu_uefi_capsule_backend_get_device_gtype(FU_UEFI_CAPSULE_BACKEND(self)),
			   "fw-class",
			   fw_class,
			   "capsule-flags",
			   fu_uefi_capsule_backend_linux_read(path, "capsule_flags"),
			   "kind",
			   fu_uefi_capsule_backend_linux_read(path, "fw_type"),
			   "fw-version",
			   fu_uefi_capsule_backend_linux_read(path, "fw_version"),
			   "last-attempt-status",
			   fu_uefi_capsule_backend_linux_read(path, "last_attempt_status"),
			   "last-attempt-version",
			   fu_uefi_capsule_backend_linux_read(path, "last_attempt_version"),
			   "fw-version-lowest",
			   fu_uefi_capsule_backend_linux_read(path, "lowest_supported_fw_version"),
			   "fmp-hardware-instance",
			   (guint64)0x0,
			   "version-format",
			   FWUPD_VERSION_FORMAT_NUMBER,
			   NULL);

	/* u-boot for instance */
	if (!self->use_rt_set_variable)
		fu_device_add_private_flag(FU_DEVICE(dev),
					   FU_UEFI_CAPSULE_DEVICE_FLAG_NO_RT_SET_VARIABLE);

	/* set ID */
	fu_device_set_backend_id(FU_DEVICE(dev), path);
	fu_device_set_physical_id(FU_DEVICE(dev), physical_id);
	fu_device_set_logical_id(FU_DEVICE(dev), fw_class);
	return g_steal_pointer(&dev);
}

static gboolean
fu_uefi_capsule_backend_linux_check_efivarfs(FuUefiCapsuleBackendLinux *self, GError **error)
{
	gboolean is_readonly;
	g_autofree gchar *sysfsfwdir = fu_path_from_kind(FU_PATH_KIND_SYSFSDIR_FW);
	g_autofree gchar *sysfsefivardir = g_build_filename(sysfsfwdir, "efi", "efivars", NULL);
	g_autoptr(GUnixMountEntry) mount = NULL;

	/* in the self tests */
	if (g_getenv("FWUPD_UEFI_TEST") != NULL)
		return TRUE;
#if GLIB_CHECK_VERSION(2, 83, 1)
	mount = g_unix_mount_entry_at(sysfsefivardir, NULL);
#else
	mount = g_unix_mount_at(sysfsefivardir, NULL);
#endif
	if (mount == NULL) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_FOUND,
			    "%s was not mounted",
			    sysfsefivardir);
		return FALSE;
	}
#if GLIB_CHECK_VERSION(2, 83, 1)
	is_readonly = g_unix_mount_entry_is_readonly(mount);
#else
	is_readonly = g_unix_mount_is_readonly(mount);
#endif
	if (is_readonly) {
		GType gtype =
		    fu_uefi_capsule_backend_get_device_gtype(FU_UEFI_CAPSULE_BACKEND(self));
		if (gtype != FU_TYPE_UEFI_COD_DEVICE) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_WRITE,
				    "%s is read only and no CoD",
				    sysfsefivardir);
			return FALSE;
		}

		/* this is fine! just do not use SetVariable... */
		self->use_rt_set_variable = FALSE;
	}

	return TRUE;
}

static gboolean
fu_uefi_capsule_backend_linux_coldplug(FuBackend *backend, FuProgress *progress, GError **error)
{
	FuUefiCapsuleBackendLinux *self = FU_UEFI_CAPSULE_BACKEND_LINUX(backend);
	const gchar *fn;
	g_autofree gchar *esrt_entries = NULL;
	g_autofree gchar *esrt_path = NULL;
	g_autofree gchar *sysfsfwdir = NULL;
	g_autoptr(GDir) dir = NULL;

	/* make sure that efivarfs is suitable */
	if (!fu_uefi_capsule_backend_linux_check_efivarfs(self, error))
		return FALSE;

	/* get the directory of ESRT entries */
	sysfsfwdir = fu_path_from_kind(FU_PATH_KIND_SYSFSDIR_FW);
	esrt_path = g_build_filename(sysfsfwdir, "efi", "esrt", NULL);
	esrt_entries = g_build_filename(esrt_path, "entries", NULL);
	dir = g_dir_open(esrt_entries, 0, error);
	if (dir == NULL)
		return FALSE;

	/* add each device */
	while ((fn = g_dir_read_name(dir)) != NULL) {
		g_autofree gchar *path = g_build_filename(esrt_entries, fn, NULL);
		g_autoptr(FuUefiCapsuleDevice) dev =
		    fu_uefi_capsule_backend_linux_device_new(self, esrt_path, path);
		fu_backend_device_added(backend, FU_DEVICE(dev));
	}

	/* success */
	return TRUE;
}

static gboolean
fu_uefi_capsule_backend_linux_check_smbios_enabled(FuContext *ctx, GError **error)
{
	GBytes *bios_blob;
	const guint8 *data;
	gsize sz;
	g_autoptr(GPtrArray) bios_tables = NULL;

	bios_tables = fu_context_get_smbios_data(ctx, 0, FU_SMBIOS_STRUCTURE_LENGTH_ANY, NULL);
	if (bios_tables == NULL) {
		const gchar *tmp = g_getenv("FWUPD_DELL_FAKE_SMBIOS");
		if (tmp != NULL)
			return TRUE;
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "SMBIOS not supported");
		return FALSE;
	}
	bios_blob = g_ptr_array_index(bios_tables, 0);
	data = g_bytes_get_data(bios_blob, &sz);
	if (sz < 0x14) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "offset bigger than size %" G_GSIZE_FORMAT,
			    sz);
		return FALSE;
	}
	if (data[1] < 0x14) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "SMBIOS 2.3 not supported");
		return FALSE;
	}
	if (!(data[0x13] & (1 << 3))) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "System does not support UEFI mode");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_uefi_capsule_backend_linux_setup(FuBackend *backend,
				    FuBackendSetupFlags flags,
				    FuProgress *progress,
				    GError **error)
{
	g_autoptr(GError) error_local = NULL;

	/* using a pre-cooked SMBIOS */
	if (g_getenv("FWUPD_SYSFSFWDIR") != NULL)
		return TRUE;

	/* check SMBIOS for 'UEFI Specification is supported' */
	if (!fu_uefi_capsule_backend_linux_check_smbios_enabled(fu_backend_get_context(backend),
								&error_local)) {
		g_autofree gchar *fw = fu_path_from_kind(FU_PATH_KIND_SYSFSDIR_FW);
		g_autofree gchar *fn = g_build_filename(fw, "efi", NULL);
		if (g_file_test(fn, G_FILE_TEST_EXISTS)) {
			g_warning("SMBIOS BIOS Characteristics Extension Byte 2 is invalid -- "
				  "UEFI Specification is unsupported, but %s exists: %s",
				  fn,
				  error_local->message);
			return TRUE;
		}
		g_propagate_error(error, g_steal_pointer(&error_local));
		return FALSE;
	}
	return TRUE;
}

static void
fu_uefi_capsule_backend_linux_init(FuUefiCapsuleBackendLinux *self)
{
	self->use_rt_set_variable = TRUE;
}

static void
fu_uefi_capsule_backend_linux_class_init(FuUefiCapsuleBackendLinuxClass *klass)
{
	FuBackendClass *backend_class = FU_BACKEND_CLASS(klass);
	backend_class->coldplug = fu_uefi_capsule_backend_linux_coldplug;
	backend_class->setup = fu_uefi_capsule_backend_linux_setup;
}

FuBackend *
fu_uefi_capsule_backend_new(FuContext *ctx)
{
	return g_object_new(FU_TYPE_UEFI_CAPSULE_BACKEND_LINUX,
			    "name",
			    "uefi",
			    "context",
			    ctx,
			    NULL);
}
