/*
 * Copyright 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <scsi/sg.h>
#include <stddef.h>

#include "fu-ata-device.h"

#define FU_ATA_IDENTIFY_SIZE 512 /* bytes */
#define FU_ATA_BLOCK_SIZE    512 /* bytes */

struct ata_tf {
	guint8 dev;
	guint8 command;
	guint8 error;
	guint8 status;
	guint8 feat;
	guint8 nsect;
	guint8 lbal;
	guint8 lbam;
	guint8 lbah;
};

#define ATA_USING_LBA (1 << 6)
#define ATA_STAT_DRQ  (1 << 3)
#define ATA_STAT_ERR  (1 << 0)

#define ATA_OP_IDENTIFY		  0xec
#define ATA_OP_FLUSH_CACHE	  0xe7
#define ATA_OP_DOWNLOAD_MICROCODE 0x92
#define ATA_OP_STANDBY_IMMEDIATE  0xe0

#define ATA_SUBCMD_MICROCODE_OBSOLETE		      0x01
#define ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS_ACTIVATE 0x03
#define ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNK	      0x07
#define ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS	      0x0e
#define ATA_SUBCMD_MICROCODE_ACTIVATE		      0x0f

#define SG_CHECK_CONDITION 0x02
#define SG_DRIVER_SENSE	   0x08

#define SG_ATA_12     0xa1
#define SG_ATA_12_LEN 12

#define SG_ATA_PROTO_NON_DATA (3 << 1)
#define SG_ATA_PROTO_PIO_IN   (4 << 1)
#define SG_ATA_PROTO_PIO_OUT  (5 << 1)

#define FU_ATA_DEVICE_IOCTL_TIMEOUT 5000 /* ms */

enum {
	SG_CDB2_TLEN_NODATA = 0 << 0,
	SG_CDB2_TLEN_FEAT = 1 << 0,
	SG_CDB2_TLEN_NSECT = 2 << 0,

	SG_CDB2_TLEN_BYTES = 0 << 2,
	SG_CDB2_TLEN_SECTORS = 1 << 2,

	SG_CDB2_TDIR_TO_DEV = 0 << 3,
	SG_CDB2_TDIR_FROM_DEV = 1 << 3,

	SG_CDB2_CHECK_COND = 1 << 5,
};

struct _FuAtaDevice {
	FuUdevDevice parent_instance;
	guint pci_depth;
	guint usb_depth;
	guint16 transfer_blocks;
	guint8 transfer_mode;
	guint32 oui;
};

G_DEFINE_TYPE(FuAtaDevice, fu_ata_device, FU_TYPE_UDEV_DEVICE)

guint8
fu_ata_device_get_transfer_mode(FuAtaDevice *self)
{
	return self->transfer_mode;
}

guint16
fu_ata_device_get_transfer_blocks(FuAtaDevice *self)
{
	return self->transfer_blocks;
}

static gchar *
fu_ata_device_get_string(const guint16 *buf, guint start, guint end)
{
	g_autoptr(GString) str = g_string_new(NULL);
	for (guint i = start; i <= end; i++) {
		g_string_append_c(str, (gchar)(buf[i] >> 8));
		g_string_append_c(str, (gchar)(buf[i] & 0xff));
	}

	/* remove whitespace before returning */
	if (str->len > 0) {
		g_strstrip(str->str);
		if (str->str[0] == '\0')
			return NULL;
	}
	return g_string_free(g_steal_pointer(&str), FALSE);
}

static void
fu_ata_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuAtaDevice *self = FU_ATA_DEVICE(device);
	fwupd_codec_string_append_hex(str, idt, "TransferMode", self->transfer_mode);
	fwupd_codec_string_append_hex(str, idt, "TransferBlocks", self->transfer_blocks);
	fwupd_codec_string_append_hex(str, idt, "OUI", self->oui);
	fwupd_codec_string_append_int(str, idt, "PciDepth", self->pci_depth);
	fwupd_codec_string_append_int(str, idt, "UsbDepth", self->usb_depth);
}

/* https://docs.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-for-ide-devices */
static gchar *
fu_ata_device_pad_string_for_id(const gchar *name)
{
	GString *str = g_string_new(name);
	g_string_replace(str, " ", "_", 0);
	for (guint i = str->len; i < 40; i++)
		g_string_append_c(str, '_');
	return g_string_free(str, FALSE);
}

static gchar *
fu_ata_device_get_guid_safe(const guint16 *buf, guint16 addr_start)
{
	if (!fu_common_guid_is_plausible((((guint8 *)buf) + addr_start)))
		return NULL;
	return fwupd_guid_to_string((const fwupd_guid_t *)(((guint8 *)buf) + addr_start),
				    FWUPD_GUID_FLAG_MIXED_ENDIAN);
}

static void
fu_ata_device_parse_id_maybe_dell(FuAtaDevice *self, const guint16 *buf)
{
	g_autofree gchar *component_id = NULL;
	g_autofree gchar *guid_efi = NULL;
	g_autofree gchar *guid_id = NULL;

	/* add extra component ID if set */
	component_id = fu_ata_device_get_string(buf, 137, 140);
	if (component_id == NULL || !g_str_is_ascii(component_id) || strlen(component_id) < 6) {
		g_debug("invalid component ID, skipping");
		return;
	}

	/* do not add the FuUdevDevice instance IDs as generic firmware
	 * should not be used on these OEM-specific devices */
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_NO_AUTO_INSTANCE_IDS);

	/* add instance ID *and* GUID as using no-auto-instance-ids */
	guid_id = g_strdup_printf("STORAGE-DELL-%s", component_id);
	fu_device_add_instance_id(FU_DEVICE(self), guid_id);

	/* also add the EFI GUID */
	guid_efi = fu_ata_device_get_guid_safe(buf, 129);
	if (guid_efi != NULL)
		fu_device_add_instance_id(FU_DEVICE(self), guid_efi);

	/* owned by Dell */
	fu_device_set_vendor(FU_DEVICE(self), "Dell");
	fu_device_build_vendor_id_u16(FU_DEVICE(self), "ATA", 0x1028);
}

static void
fu_ata_device_parse_vendor_name(FuAtaDevice *self, const gchar *name)
{
	struct {
		const gchar *prefix; /* in CAPS */
		guint16 vid;
		const gchar *name;
	} map_name[] = {/* vendor matches */
			{"ADATA*", 0x1cc1, "ADATA"},
			{"APACER*", 0x0000, "Apacer"}, /* not in pci.ids */
			{"APPLE*", 0x106b, "Apple"},
			{"CORSAIR*", 0x1987, "Corsair"}, /* identifies as Phison */
			{"CRUCIAL*", 0xc0a9, "Crucial"},
			{"FUJITSU*", 0x10cf, "Fujitsu"},
			{"GIGABYTE*", 0x1458, "Gigabyte"},
			{"HGST*", 0x101c, "Western Digital"},
			{"HITACHI*", 0x101c, "Western Digital"}, /* was acquired by WD */
			{"HITACHI*", 0x1054, "Hitachi"},
			{"HP SSD*", 0x103c, "HP"},
			{"INTEL*", 0x8086, "Intel"},
			{"KINGSPEC*", 0x0000, "KingSpec"}, /* not in pci.ids */
			{"KINGSTON*", 0x2646, "Kingston"},
			{"LITEON*", 0x14a4, "LITE-ON"},
			{"MAXTOR*", 0x115f, "Maxtor"},
			{"MICRON*", 0x1344, "Micron"},
			{"OCZ*", 0x1179, "Toshiba"},
			{"PNY*", 0x196e, "PNY"},
			{"QEMU*", 0x1b36, "QEMU"}, /* identifies as Red Hat! */
			{"SAMSUNG*", 0x144d, "Samsung"},
			{"SANDISK*", 0x15b7, "SanDisk"},
			{"SEAGATE*", 0x1bb1, "Seagate"},
			{
			    "SK HYNIX*",
			    0x1c5c,
			    "SK hynix",
			},
			{"SUPERMICRO*", 0x15d9, "SuperMicro"},
			{"TOSHIBA*", 0x1179, "Toshiba"},
			{"WDC*", 0x101c, "Western Digital"},
			{NULL, 0x0000, NULL}};
	struct {
		const gchar *prefix; /* in CAPS */
		guint16 vid;
		const gchar *name;
	} map_fuzzy[] = {/* fuzzy name matches -- also see legacy list at:
			  * https://github.com/linuxhw/hw-probe/blob/master/hw-probe.pl#L647 */
			 {"001-*", 0x1bb1, "Seagate"},
			 {"726060*", 0x101c, "Western Digital"},
			 {"CT*", 0xc0a9, "Crucial"},
			 {"DT0*", 0x1179, "Toshiba"},
			 {"EK0*", 0x1590, "HPE"},
			 {"EZEX*", 0x101c, "Western Digital"},
			 {"GB0*", 0x1590, "HPE"},
			 {"GOODRAM*", 0x1987, "Phison"},
			 {"H??54*", 0x101c, "Western Digital"},
			 {"H??72?0*", 0x101c, "Western Digital"},
			 {"HDWG*", 0x1179, "Toshiba"},
			 {"M?0??CA*", 0x1179, "Toshiba"}, /* enterprise */
			 {"M4-CT*", 0xc0a9, "Crucial"},
			 {
			     "MA*",
			     0x10cf,
			     "Fujitsu",
			 },
			 {
			     "MB*",
			     0x10cf,
			     "Fujitsu",
			 },
			 {"MK0*", 0x1590, "HPE"},
			 {"MTFDDAK*", 0x1344, "Micron"},
			 {
			     "NIM*",
			     0x0000,
			     "Nimbus",
			 }, /* no PCI ID */
			 {
			     "SATADOM*",
			     0x0000,
			     "Innodisk",
			 }, /* no PCI ID */
			 {"SSD 860*", 0x144d, "Samsung"},
			 {"SSDPR*", 0x1987, "Phison"},
			 {"SSDSC?K*", 0x8086, "Intel"},
			 {
			     "ST*",
			     0x1bb1,
			     "Seagate",
			 },
			 {"TEAM*", 0x0000, "Team Group"}, /* not in pci.ids */
			 {"TS*", 0x8564, "Transcend"},
			 {"VK0*", 0x1590, "HPE"},
			 {"WD*", 0x101c, "Western Digital"},
			 {NULL, 0x0000, NULL}};
	struct {
		const gchar *prefix; /* in CAPS */
		guint16 vid;
		const gchar *name;
	} map_version[] = {/* fuzzy version matches */
			   {"CS2111*", 0x196e, "PNY"},
			   {"S?FM*", 0x1987, "Phison"},
			   {NULL, 0x0000, NULL}};
	guint16 vid = 0;
	g_autofree gchar *name_up = g_ascii_strup(name, -1);

	/* find match */
	for (guint i = 0; map_name[i].prefix != NULL; i++) {
		if (g_pattern_match_simple(map_name[i].prefix, name_up)) {
			name += strlen(map_name[i].prefix) - 1;
			fu_device_set_vendor(FU_DEVICE(self), map_name[i].name);
			vid = map_name[i].vid;
			break;
		}
	}

	/* fall back to fuzzy match */
	if (vid == 0x0) {
		for (guint i = 0; map_fuzzy[i].prefix != NULL; i++) {
			if (g_pattern_match_simple(map_fuzzy[i].prefix, name_up)) {
				fu_device_set_vendor(FU_DEVICE(self), map_fuzzy[i].name);
				vid = map_fuzzy[i].vid;
				break;
			}
		}
	}

	/* fall back to version */
	if (vid == 0x0) {
		g_autofree gchar *version_up =
		    g_ascii_strup(fu_device_get_version(FU_DEVICE(self)), -1);
		for (guint i = 0; map_version[i].prefix != NULL; i++) {
			if (g_pattern_match_simple(map_version[i].prefix, version_up)) {
				fu_device_set_vendor(FU_DEVICE(self), map_version[i].name);
				vid = map_version[i].vid;
				break;
			}
		}
	}

	/* devices without a vendor ID will not be UPGRADABLE */
	fu_device_build_vendor_id_u16(FU_DEVICE(self), "ATA", vid);

	/* remove leading junk */
	while (name[0] == ' ' || name[0] == '_' || name[0] == '-')
		name += 1;

	/* if changed */
	if (g_strcmp0(fu_device_get_name(FU_DEVICE(self)), name) != 0)
		fu_device_set_name(FU_DEVICE(self), name);
}

static gboolean
fu_ata_device_parse_id(FuAtaDevice *self, const guint8 *buf, gsize sz, GError **error)
{
	FuDevice *device = FU_DEVICE(self);
	gboolean has_oui_quirk = FALSE;
	guint16 xfer_min = 1;
	guint16 xfer_max = 0xffff;
	guint16 id[FU_ATA_IDENTIFY_SIZE / 2] = {0};
	g_autofree gchar *name = NULL;
	g_autofree gchar *sku = NULL;

	/* check size */
	if (sz != FU_ATA_IDENTIFY_SIZE) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "ID incorrect size, got 0x%02x",
			    (guint)sz);
		return FALSE;
	}

	/* read LE buffer */
	for (guint i = 0; i < sz / 2; i++)
		id[i] = fu_memread_uint16(buf + (i * 2), G_LITTLE_ENDIAN);

	/* verify drive correctly supports DOWNLOAD_MICROCODE */
	if (!(id[83] & 1 && id[86] & 1)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "DOWNLOAD_MICROCODE not supported by device");
		return FALSE;
	}

	fu_ata_device_parse_id_maybe_dell(self, id);

	/* firmware will be applied when the device restarts */
	if (self->transfer_mode == ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS)
		fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_NEEDS_REBOOT);

	/* the newer, segmented transfer mode */
	if (self->transfer_mode == ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS_ACTIVATE ||
	    self->transfer_mode == ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS) {
		xfer_min = id[234];
		if (xfer_min == 0x0 || xfer_min == 0xffff)
			xfer_min = 1;
		xfer_max = id[235];
		if (xfer_max == 0x0 || xfer_max == 0xffff)
			xfer_max = xfer_min;
	}

	/* fall back to a sane block size */
	if (self->transfer_blocks == 0x0)
		self->transfer_blocks = xfer_min;
	else if (self->transfer_blocks == 0xffff)
		self->transfer_blocks = xfer_max;

	/* get values in case the kernel didn't */
	if (fu_device_get_serial(device) == NULL) {
		g_autofree gchar *tmp = NULL;
		tmp = fu_ata_device_get_string(id, 10, 19);
		if (tmp != NULL)
			fu_device_set_serial(device, tmp);
	}
	if (fu_device_get_version(device) == NULL) {
		g_autofree gchar *tmp = NULL;
		tmp = fu_ata_device_get_string(id, 23, 26);
		if (tmp != NULL)
			fu_device_set_version(device, tmp);
	}

	/* get OUI if set */
	self->oui = ((guint32)(id[108] & 0x0fff)) << 12 | ((guint32)(id[109] & 0xfff0)) >> 4;
	if (self->oui > 0x0) {
		g_autofree gchar *tmp = NULL;
		tmp = g_strdup_printf("OUI\\VID_%06x", self->oui);
		fu_device_add_instance_id_full(device, tmp, FU_DEVICE_INSTANCE_FLAG_QUIRKS);
		has_oui_quirk = fu_device_get_vendor(FU_DEVICE(self)) != NULL;
	}
	if (self->oui > 0x0) {
		g_autofree gchar *vendor_id = g_strdup_printf("%06x", self->oui);
		fu_device_build_vendor_id(device, "OUI", vendor_id);
	}

	/* if not already set using the vendor block or a OUI quirk */
	name = fu_ata_device_get_string(id, 27, 46);
	if (name != NULL) {
		/* use the name as-is */
		if (has_oui_quirk) {
			fu_device_set_name(FU_DEVICE(self), name);
		} else {
			fu_ata_device_parse_vendor_name(self, name);
		}
	}

	/* 8 byte additional product identifier == SKU? */
	sku = fu_ata_device_get_string(id, 170, 173);
	if (sku != NULL)
		g_debug("SKU=%s", sku);

	/* add extra GUIDs if none detected from identify block */
	if (name != NULL && fu_device_get_guids(device)->len == 0) {
		g_autofree gchar *name_pad = fu_ata_device_pad_string_for_id(name);
		if (name_pad != NULL && fu_device_get_version(device) != NULL) {
			g_autofree gchar *tmp = NULL;
			tmp = g_strdup_printf("IDE\\%s%s", name_pad, fu_device_get_version(device));
			fu_device_add_instance_id(device, tmp);
		}
		if (name_pad != NULL) {
			g_autofree gchar *tmp = NULL;
			tmp = g_strdup_printf("IDE\\0%s", name_pad);
			fu_device_add_instance_id(device, tmp);
		}

		/* add the name fallback */
		fu_device_add_instance_id(device, name);
	}

	/* for Phison this is per-chipset -- which is specified in the version prefix */
	if (g_strcmp0(fu_device_get_vendor(device), "Phison") == 0 &&
	    fu_device_get_version(device) != NULL) {
		if (g_str_has_prefix(fu_device_get_version(device), "SB")) {
			fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UNSIGNED_PAYLOAD);
		} else if (g_str_has_prefix(fu_device_get_version(device), "SC") ||
			   g_str_has_prefix(fu_device_get_version(device), "SH")) {
			fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_SIGNED_PAYLOAD);
		}
	}

	return TRUE;
}

static gboolean
fu_ata_device_probe(FuDevice *device, GError **error)
{
	FuAtaDevice *self = FU_ATA_DEVICE(device);
	g_autoptr(FuDevice) scsi_parent = NULL;

	/* set the SCSI physical ID for compat */
	scsi_parent = fu_device_get_backend_parent_with_subsystem(device, "scsi", error);
	if (scsi_parent == NULL)
		return FALSE;
	fu_device_set_physical_id(device, fu_device_get_backend_id(scsi_parent));

	/* look at the PCI and USB depth to work out if in an external enclosure */
	self->pci_depth = fu_udev_device_get_subsystem_depth(FU_UDEV_DEVICE(device), "pci");
	self->usb_depth = fu_udev_device_get_subsystem_depth(FU_UDEV_DEVICE(device), "usb");
	if (self->pci_depth <= 2 && self->usb_depth <= 2) {
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_INTERNAL);
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_USABLE_DURING_UPDATE);
	}

	return TRUE;
}

static guint64
fu_ata_device_tf_to_pack_id(struct ata_tf *tf)
{
	guint32 lba24 = (tf->lbah << 16) | (tf->lbam << 8) | (tf->lbal);
	guint32 lbah = tf->dev & 0x0f;
	return (((guint64)lbah) << 24) | (guint64)lba24;
}

static gboolean
fu_ata_device_ioctl_buf_cb(FuIoctl *self, gpointer ptr, guint8 *buf, gsize bufsz, GError **error)
{
	struct sg_io_hdr *io_hdr = (struct sg_io_hdr *)ptr;
	io_hdr->dxferp = buf;
	io_hdr->dxfer_len = bufsz;
	return TRUE;
}

static gboolean
fu_ata_device_ioctl_cdb_cb(FuIoctl *self, gpointer ptr, guint8 *buf, gsize bufsz, GError **error)
{
	struct sg_io_hdr *io_hdr = (struct sg_io_hdr *)ptr;
	io_hdr->cmdp = buf;
	io_hdr->cmd_len = bufsz;
	return TRUE;
}

static gboolean
fu_ata_device_ioctl_sense_cb(FuIoctl *self, gpointer ptr, guint8 *buf, gsize bufsz, GError **error)
{
	struct sg_io_hdr *io_hdr = (struct sg_io_hdr *)ptr;
	io_hdr->sbp = buf;
	io_hdr->mx_sb_len = bufsz;
	return TRUE;
}

static gboolean
fu_ata_device_command(FuAtaDevice *self,
		      struct ata_tf *tf,
		      gint dxfer_direction,
		      guint timeout_ms,
		      guint8 *dxferp,
		      gsize dxfer_len,
		      GError **error)
{
	guint8 cdb[SG_ATA_12_LEN] = {0x0};
	guint8 sb[32] = {0x0};
	sg_io_hdr_t io_hdr = {0x0};
	g_autoptr(FuIoctl) ioctl = fu_udev_device_ioctl_new(FU_UDEV_DEVICE(self));

	/* map _TO_DEV to PIO mode */
	if (dxfer_direction == SG_DXFER_TO_DEV)
		cdb[1] = SG_ATA_PROTO_PIO_OUT;
	else if (dxfer_direction == SG_DXFER_FROM_DEV)
		cdb[1] = SG_ATA_PROTO_PIO_IN;
	else
		cdb[1] = SG_ATA_PROTO_NON_DATA;

	/* libata workaround: don't demand sense data for IDENTIFY */
	if (dxfer_len > 0) {
		cdb[2] |= SG_CDB2_TLEN_NSECT | SG_CDB2_TLEN_SECTORS;
		cdb[2] |= dxfer_direction == SG_DXFER_TO_DEV ? SG_CDB2_TDIR_TO_DEV
							     : SG_CDB2_TDIR_FROM_DEV;
	} else {
		cdb[2] = SG_CDB2_CHECK_COND;
	}

	/* populate non-LBA48 CDB */
	cdb[0] = SG_ATA_12;
	cdb[3] = tf->feat;
	cdb[4] = tf->nsect;
	cdb[5] = tf->lbal;
	cdb[6] = tf->lbam;
	cdb[7] = tf->lbah;
	cdb[8] = tf->dev;
	cdb[9] = tf->command;

	/* hit hardware */
	io_hdr.interface_id = 'S';
	io_hdr.dxfer_direction = dxfer_direction;
	io_hdr.pack_id = fu_ata_device_tf_to_pack_id(tf);
	io_hdr.timeout = timeout_ms;

	/* include these when generating the emulation event */
	fu_ioctl_add_key_as_u16(ioctl, "Request", SG_IO);
	fu_ioctl_add_key_as_u8(ioctl, "DxferDirection", io_hdr.dxfer_direction);
	fu_ioctl_add_key_as_u8(ioctl, "PackId", io_hdr.pack_id);
	fu_ioctl_add_mutable_buffer(ioctl, NULL, dxferp, dxfer_len, fu_ata_device_ioctl_buf_cb);
	fu_ioctl_add_const_buffer(ioctl, "Cdb", cdb, sizeof(cdb), fu_ata_device_ioctl_cdb_cb);
	fu_ioctl_add_mutable_buffer(ioctl, "Sense", sb, sizeof(sb), fu_ata_device_ioctl_sense_cb);
	if (!fu_ioctl_execute(ioctl,
			      SG_IO,
			      (guint8 *)&io_hdr,
			      sizeof(io_hdr),
			      NULL,
			      FU_ATA_DEVICE_IOCTL_TIMEOUT,
			      FU_IOCTL_FLAG_NONE,
			      error))
		return FALSE;
	g_debug("ATA_%u status=0x%x, host_status=0x%x, driver_status=0x%x",
		io_hdr.cmd_len,
		io_hdr.status,
		io_hdr.host_status,
		io_hdr.driver_status);
	fu_dump_raw(G_LOG_DOMAIN, "SB", sb, sizeof(sb));

	/* error check */
	if (io_hdr.status && io_hdr.status != SG_CHECK_CONDITION) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "bad status: 0x%x",
			    io_hdr.status);
		return FALSE;
	}
	if (io_hdr.host_status) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "bad host status: 0x%x",
			    io_hdr.host_status);
		return FALSE;
	}
	if (io_hdr.driver_status && (io_hdr.driver_status != SG_DRIVER_SENSE)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "bad driver status: 0x%x",
			    io_hdr.driver_status);
		return FALSE;
	}

	/* repopulate ata_tf */
	tf->error = sb[8 + 3];
	tf->nsect = sb[8 + 5];
	tf->lbal = sb[8 + 7];
	tf->lbam = sb[8 + 9];
	tf->lbah = sb[8 + 11];
	tf->dev = sb[8 + 12];
	tf->status = sb[8 + 13];
	g_debug("ATA_%u stat=%02x err=%02x nsect=%02x lbal=%02x "
		"lbam=%02x lbah=%02x dev=%02x",
		io_hdr.cmd_len,
		tf->status,
		tf->error,
		tf->nsect,
		tf->lbal,
		tf->lbam,
		tf->lbah,
		tf->dev);

	/* io error */
	if (tf->status & (ATA_STAT_ERR | ATA_STAT_DRQ)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "I/O error, ata_op=0x%02x ata_status=0x%02x ata_error=0x%02x",
			    tf->command,
			    tf->status,
			    tf->error);
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_ata_device_setup(FuDevice *device, GError **error)
{
	FuAtaDevice *self = FU_ATA_DEVICE(device);
	struct ata_tf tf = {0x0};
	guint8 id[FU_ATA_IDENTIFY_SIZE] = {0x0};

	/* get ID block */
	tf.dev = ATA_USING_LBA;
	tf.command = ATA_OP_IDENTIFY;
	tf.nsect = 1; /* 512 bytes */
	if (!fu_ata_device_command(self, &tf, SG_DXFER_FROM_DEV, 1000, id, sizeof(id), error)) {
		g_prefix_error(error, "failed to IDENTIFY: ");
		return FALSE;
	}
	fu_dump_raw(G_LOG_DOMAIN, "IDENTIFY", id, sizeof(id));
	if (!fu_ata_device_parse_id(self, id, sizeof(id), error))
		return FALSE;

	/* success */
	return TRUE;
}

static gboolean
fu_ata_device_activate(FuDevice *device, FuProgress *progress, GError **error)
{
	FuAtaDevice *self = FU_ATA_DEVICE(device);
	struct ata_tf tf = {0x0};

	/* flush cache and put drive in standby to prepare to activate */
	tf.dev = ATA_USING_LBA;
	tf.command = ATA_OP_FLUSH_CACHE;
	if (!fu_ata_device_command(self,
				   &tf,
				   SG_DXFER_NONE,
				   120 * 1000, /* a long time! */
				   NULL,
				   0,
				   error)) {
		g_prefix_error(error, "failed to flush cache immediate: ");
		return FALSE;
	}
	tf.command = ATA_OP_STANDBY_IMMEDIATE;
	if (!fu_ata_device_command(self,
				   &tf,
				   SG_DXFER_NONE,
				   120 * 1000, /* a long time! */
				   NULL,
				   0,
				   error)) {
		g_prefix_error(error, "failed to standby immediate: ");
		return FALSE;
	}

	/* load the new firmware */
	tf.dev = 0xa0 | ATA_USING_LBA;
	tf.command = ATA_OP_DOWNLOAD_MICROCODE;
	tf.feat = ATA_SUBCMD_MICROCODE_ACTIVATE;
	if (!fu_ata_device_command(self,
				   &tf,
				   SG_DXFER_NONE,
				   120 * 1000, /* a long time! */
				   NULL,
				   0,
				   error)) {
		g_prefix_error(error, "failed to activate firmware: ");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_ata_device_fw_download(FuAtaDevice *self,
			  guint32 idx,
			  guint32 addr,
			  const guint8 *data,
			  guint32 data_sz,
			  GError **error)
{
	struct ata_tf tf = {0x0};
	guint32 block_count = data_sz / FU_ATA_BLOCK_SIZE;
	guint32 buffer_offset = addr / FU_ATA_BLOCK_SIZE;

	/* write block */
	tf.dev = 0xa0 | ATA_USING_LBA;
	tf.command = ATA_OP_DOWNLOAD_MICROCODE;
	tf.feat = self->transfer_mode;
	tf.nsect = block_count & 0xff;
	tf.lbal = block_count >> 8;
	tf.lbam = buffer_offset & 0xff;
	tf.lbah = buffer_offset >> 8;
	if (!fu_ata_device_command(self,
				   &tf,
				   SG_DXFER_TO_DEV,
				   120 * 1000, /* a long time! */
				   (guint8 *)data,
				   data_sz,
				   error)) {
		g_prefix_error(error, "failed to write firmware @0x%0x: ", (guint)addr);
		return FALSE;
	}

	/* check drive status */
	if (tf.nsect == 0x0)
		return TRUE;

	/* drive wants more data, or thinks it is all done */
	if (tf.nsect == 0x1 || tf.nsect == 0x2)
		return TRUE;

	/* the offset was set up incorrectly */
	if (tf.nsect == 0x4) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "alignment error");
		return FALSE;
	}

	/* other error */
	g_set_error(error,
		    FWUPD_ERROR,
		    FWUPD_ERROR_INVALID_DATA,
		    "unknown return code 0x%02x",
		    tf.nsect);
	return FALSE;
}

static gboolean
fu_ata_device_write_firmware(FuDevice *device,
			     FuFirmware *firmware,
			     FuProgress *progress,
			     FwupdInstallFlags flags,
			     GError **error)
{
	FuAtaDevice *self = FU_ATA_DEVICE(device);
	gsize streamsz = 0;
	guint32 chunksz = (guint32)self->transfer_blocks * FU_ATA_BLOCK_SIZE;
	guint max_size = 0xffff * FU_ATA_BLOCK_SIZE;
	g_autoptr(GInputStream) stream = NULL;
	g_autoptr(FuChunkArray) chunks = NULL;

	/* get default image */
	stream = fu_firmware_get_stream(firmware, error);
	if (stream == NULL)
		return FALSE;

	/* only one block allowed */
	if (self->transfer_mode == ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNK)
		max_size = 0xffff;

	/* check is valid */
	if (!fu_input_stream_size(stream, &streamsz, error))
		return FALSE;
	if (streamsz > max_size) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "firmware is too large, maximum size is %u",
			    max_size);
		return FALSE;
	}
	if (streamsz % FU_ATA_BLOCK_SIZE != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "firmware is not multiple of block size %i",
			    FU_ATA_BLOCK_SIZE);
		return FALSE;
	}

	/* write each block */
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_WRITE);
	chunks = fu_chunk_array_new_from_stream(stream,
						FU_CHUNK_ADDR_OFFSET_NONE,
						FU_CHUNK_PAGESZ_NONE,
						chunksz,
						error);
	if (chunks == NULL)
		return FALSE;
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_set_steps(progress, fu_chunk_array_length(chunks));
	for (guint i = 0; i < fu_chunk_array_length(chunks); i++) {
		g_autoptr(FuChunk) chk = NULL;

		/* prepare chunk */
		chk = fu_chunk_array_index(chunks, i, error);
		if (chk == NULL)
			return FALSE;
		if (!fu_ata_device_fw_download(self,
					       fu_chunk_get_idx(chk),
					       fu_chunk_get_address(chk),
					       fu_chunk_get_data(chk),
					       fu_chunk_get_data_sz(chk),
					       error)) {
			g_prefix_error(error, "failed to write chunk %u: ", i);
			return FALSE;
		}
		fu_progress_step_done(progress);
	}

	/* success! */
	fu_device_add_flag(device, FWUPD_DEVICE_FLAG_NEEDS_ACTIVATION);
	return TRUE;
}

static gboolean
fu_ata_device_set_quirk_kv(FuDevice *device, const gchar *key, const gchar *value, GError **error)
{
	FuAtaDevice *self = FU_ATA_DEVICE(device);
	guint64 tmp = 0;

	if (g_strcmp0(key, "AtaTransferMode") == 0) {
		if (!fu_strtoull(value, &tmp, 0, G_MAXUINT8, FU_INTEGER_BASE_AUTO, error))
			return FALSE;
		if (tmp != ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS_ACTIVATE &&
		    tmp != ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS &&
		    tmp != ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNK) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_NOT_SUPPORTED,
					    "AtaTransferMode only supports "
					    "values 0x3, 0x7 or 0xe");
			return FALSE;
		}
		self->transfer_mode = (guint8)tmp;
		return TRUE;
	}
	if (g_strcmp0(key, "AtaTransferBlocks") == 0) {
		if (!fu_strtoull(value, &tmp, 0, G_MAXUINT16, FU_INTEGER_BASE_AUTO, error))
			return FALSE;
		self->transfer_blocks = (guint16)tmp;
		return TRUE;
	}
	g_set_error_literal(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "quirk key not supported");
	return FALSE;
}

static void
fu_ata_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_flag(progress, FU_PROGRESS_FLAG_GUESSED);
	fu_progress_add_step(progress, FWUPD_STATUS_DECOMPRESSING, 0, "prepare-fw");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "detach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 98, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "attach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 2, "reload");
}

static void
fu_ata_device_init(FuAtaDevice *self)
{
	/* we chose this default as _DOWNLOAD_CHUNKS_ACTIVATE applies the
	 * firmware straight away and the kernel might not like the unexpected
	 * ATA restart and panic */
	self->transfer_mode = ATA_SUBCMD_MICROCODE_DOWNLOAD_CHUNKS;
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_REQUIRE_AC);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_INHERIT_ACTIVATION);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_MD_SET_SIGNED);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_MD_SET_FLAGS);
	fu_device_set_summary(FU_DEVICE(self), "ATA drive");
	fu_device_add_icon(FU_DEVICE(self), FU_DEVICE_ICON_DRIVE_HARDDISK);
	fu_device_add_protocol(FU_DEVICE(self), "org.t13.ata");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PLAIN);
	fu_udev_device_add_open_flag(FU_UDEV_DEVICE(self), FU_IO_CHANNEL_OPEN_FLAG_READ);
}

static void
fu_ata_device_class_init(FuAtaDeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->to_string = fu_ata_device_to_string;
	device_class->set_quirk_kv = fu_ata_device_set_quirk_kv;
	device_class->setup = fu_ata_device_setup;
	device_class->activate = fu_ata_device_activate;
	device_class->write_firmware = fu_ata_device_write_firmware;
	device_class->probe = fu_ata_device_probe;
	device_class->set_progress = fu_ata_device_set_progress;
}

FuAtaDevice *
fu_ata_device_new_from_blob(FuContext *ctx, const guint8 *buf, gsize sz, GError **error)
{
	g_autoptr(FuAtaDevice) self = NULL;

	self = g_object_new(FU_TYPE_ATA_DEVICE, "context", ctx, NULL);
	if (!fu_ata_device_parse_id(self, buf, sz, error))
		return NULL;
	return g_steal_pointer(&self);
}
