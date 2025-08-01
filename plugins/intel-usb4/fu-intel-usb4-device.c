/*
 * Copyright 2022 Richard Hughes <richard@hughsie.com>
 * Copyright 2021 Intel Corporation.
 * Copyright 2021 Dell Inc.
 * All rights reserved.
 *
 * This software and associated documentation (if any) is furnished
 * under a license and may only be used or copied in accordance
 * with the terms of the license.
 *
 * This file is provided under a dual MIT/LGPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 * Dell Chooses the MIT license part of Dual MIT/LGPLv2 license agreement.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
 */

#include "config.h"

#include "fu-intel-usb4-device.h"
#include "fu-intel-usb4-struct.h"

#define GR_USB_INTERFACE_NUMBER 0x0
#define GR_USB_BLOCK_SIZE	64

/* bmRequest type */
#define USB_REQ_TYPE_GET_MMIO 0xc0 /* bm Request type */
#define USB_REQ_TYPE_SET_MMIO 0x40 /* bm Request type */

/* bRequest */
#define REQ_HUB_GET_MMIO 64
#define REQ_HUB_SET_MMIO 65

/* wValue*/
#define MBOX_ACCESS (1 << 10)

/* wIndex, mailbox register offset */
/* First 16 registers are Data[0]-Data[15] registers */
#define MBOX_REG_METADATA 16
#define MBOX_REG	  17 /* no name? */

/* mask for the MBOX_REG register that has no name */
#define MBOX_ERROR   (1 << 6) /* of the u8 status field */
#define MBOX_OPVALID (1 << 7) /* of the u8 status field */

#define MBOX_TIMEOUT 3000

/* NVM metadata offset and length fields are in dword units */
/* note that these won't work for DROM read */
#define NVM_OFFSET_TO_METADATA(p) ((((p) / 4) & 0x3fffff) << 2) /* bits 23:2  */
#define NVM_LENGTH_TO_METADATA(p) ((((p) / 4) & 0xf) << 24)	/* bits 27:24 */

/* Default length for NVM READ */
#define NVM_READ_LENGTH 0x224

#define FU_INTEL_USB4_DEVICE_REMOVE_DELAY 60000 /* ms */

struct _FuIntelUsb4Device {
	FuUsbDevice parent_instance;
	guint blocksz;
	guint8 intf_nr;
	/* from DROM */
	guint16 nvm_vendor_id;
	guint16 nvm_model_id;
	/* from DIGITAL */
	guint16 nvm_device_id;
};

G_DEFINE_TYPE(FuIntelUsb4Device, fu_intel_usb4_device, FU_TYPE_USB_DEVICE)

/* wIndex contains the hub register offset, value BIT[10] is "access to
 * mailbox", rest of values are vendor specific or rsvd  */
static gboolean
fu_intel_usb4_device_get_mmio(FuIntelUsb4Device *self,
			      guint16 mbox_reg,
			      guint8 *buf,
			      gsize bufsz,
			      GError **error)
{
	if (!fu_usb_device_control_transfer(FU_USB_DEVICE(self),
					    FU_USB_DIRECTION_DEVICE_TO_HOST,
					    FU_USB_REQUEST_TYPE_VENDOR,
					    FU_USB_RECIPIENT_DEVICE,
					    REQ_HUB_GET_MMIO, /* request */
					    MBOX_ACCESS,      /* value */
					    mbox_reg,	      /* index */
					    buf,
					    bufsz,
					    NULL, /* actual length */
					    MBOX_TIMEOUT,
					    NULL,
					    error)) {
		g_prefix_error(error,
			       "GET_MMIO failed to set control on mbox register index [0x%x]: ",
			       mbox_reg);
		return FALSE;
	}
	/* verify status for specific hub mailbox register */
	if (mbox_reg == MBOX_REG) {
		g_autoptr(GByteArray) st_regex = NULL;

		st_regex = fu_struct_intel_usb4_mbox_parse(buf, bufsz, 0x0, error);
		if (st_regex == NULL)
			return FALSE;

		/* error status bit */
		if (fu_struct_intel_usb4_mbox_get_status(st_regex) & MBOX_ERROR) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "GET_MMIO opcode [0x%x] nonzero error bit in status [0x%x]",
				    fu_struct_intel_usb4_mbox_get_opcode(st_regex),
				    fu_struct_intel_usb4_mbox_get_status(st_regex));
			return FALSE;
		}

		/* operation valid (OV) bit should be 0'b */
		if (fu_struct_intel_usb4_mbox_get_status(st_regex) & MBOX_OPVALID) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "GET_MMIO opcode [0x%x] nonzero OV bit in status [0x%x]",
				    fu_struct_intel_usb4_mbox_get_opcode(st_regex),
				    fu_struct_intel_usb4_mbox_get_status(st_regex));
			return FALSE;
		}
	}
	return TRUE;
}

static gboolean
fu_intel_usb4_device_set_mmio(FuIntelUsb4Device *self,
			      guint16 mbox_reg,
			      guint8 *buf,
			      gsize bufsz,
			      GError **error)
{
	if (!fu_usb_device_control_transfer(FU_USB_DEVICE(self),
					    FU_USB_DIRECTION_HOST_TO_DEVICE,
					    FU_USB_REQUEST_TYPE_VENDOR,
					    FU_USB_RECIPIENT_DEVICE,
					    REQ_HUB_SET_MMIO, /* request */
					    MBOX_ACCESS,      /* value */
					    mbox_reg,	      /* index */
					    buf,
					    bufsz,
					    NULL, /* actual length */
					    MBOX_TIMEOUT,
					    NULL,
					    error)) {
		g_prefix_error(error, "failed to set mmio 0x%x: ", mbox_reg);
		return FALSE;
	}
	return TRUE;
}

/*
 * Read up to 64 bytes of data from the mbox data registers to a buffer.
 * The mailbox can hold 64 bytes of data in 16 doubleword data registers.
 * To get data from NVM or DROM to mbox registers issue a NVM Read or DROM
 * read operation before reading the mbox data registers.
 */
static gboolean
fu_intel_usb4_device_mbox_data_read(FuIntelUsb4Device *self,
				    guint8 *buf,
				    guint8 bufsz,
				    GError **error)
{
	guint8 *ptr = buf;

	if (bufsz > 64 || bufsz % 4) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "invalid firmware data read length %u",
			    bufsz);
		return FALSE;
	}
	/* read 4 bytes per iteration */
	for (gint i = 0; i < bufsz / 4; i++) {
		if (!fu_intel_usb4_device_get_mmio(self, i, ptr, 0x4, error)) {
			g_prefix_error(error, "failed to read mbox data registers: ");
			return FALSE;
		}
		ptr += 4;
	}
	return TRUE;
}

/*
 * The mailbox can hold 64 bytes in 16 doubleword data registers.
 * A NVM write operation writes data from these registers to NVM
 * at the set offset
 */
static gboolean
fu_intel_usb4_device_mbox_data_write(FuIntelUsb4Device *self,
				     const guint8 *buf,
				     guint8 bufsz,
				     GError **error)
{
	guint8 *ptr = (guint8 *)buf;

	if (bufsz > 64 || bufsz % 4) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "invalid firmware data write length %u",
			    bufsz);
		return FALSE;
	}

	/* writes 4 bytes per iteration */
	for (gint i = 0; i < bufsz / 4; i++) {
		if (!fu_intel_usb4_device_set_mmio(self, i, ptr, 0x4, error))
			return FALSE;
		ptr += 4;
	}
	return TRUE;
}

static gboolean
fu_intel_usb4_device_operation(FuIntelUsb4Device *self,
			       FuIntelUsb4Opcode opcode,
			       guint8 *buf,
			       gsize bufsz,
			       GError **error)
{
	gint max_tries = 100;
	g_autoptr(GByteArray) st_regex = fu_struct_intel_usb4_mbox_new();

	/* Write metadata register for operations that use it */
	switch (opcode) {
	case FU_INTEL_USB4_OPCODE_NVM_WRITE:
	case FU_INTEL_USB4_OPCODE_NVM_AUTH_WRITE:
		break;
	case FU_INTEL_USB4_OPCODE_NVM_READ:
	case FU_INTEL_USB4_OPCODE_NVM_SET_OFFSET:
	case FU_INTEL_USB4_OPCODE_DROM_READ:
		if (buf == NULL) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "hub opcode 0x%x requires metadata",
				    opcode);
			return FALSE;
		}
		if (!fu_intel_usb4_device_set_mmio(self, MBOX_REG_METADATA, buf, bufsz, error)) {
			g_autofree gchar *bufstr = fu_strsafe((const gchar *)buf, bufsz);
			g_prefix_error(error, "failed to write metadata %s: ", bufstr);
			return FALSE;
		}
		break;
	default:
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "invalid hub opcode: 0x%x",
			    opcode);
		return FALSE;
	}

	/* write the operation and poll completion or error */
	fu_struct_intel_usb4_mbox_set_opcode(st_regex, opcode);
	fu_struct_intel_usb4_mbox_set_status(st_regex, MBOX_OPVALID);
	if (!fu_intel_usb4_device_set_mmio(self, MBOX_REG, st_regex->data, st_regex->len, error))
		return FALSE;

	/* leave early as successful USB4 AUTH resets the device immediately */
	if (opcode == FU_INTEL_USB4_OPCODE_NVM_AUTH_WRITE)
		return TRUE;

	for (gint i = 0; i <= max_tries; i++) {
		g_autoptr(GError) error_local = NULL;
		if (fu_intel_usb4_device_get_mmio(self,
						  MBOX_REG,
						  st_regex->data,
						  st_regex->len,
						  &error_local))
			return TRUE;
		if (i == max_tries) {
			g_propagate_prefixed_error(error,
						   g_steal_pointer(&error_local),
						   "maximum tries exceeded: ");
		}
		fu_device_sleep(FU_DEVICE(self), 10); /* ms */
	}
	return FALSE;
}

static gboolean
fu_intel_usb4_device_nvm_read(FuIntelUsb4Device *self,
			      guint8 *buf,
			      gsize bufsz,
			      gsize nvm_addr,
			      GError **error)
{
	g_autoptr(GPtrArray) chunks = NULL;

	chunks = fu_chunk_array_mutable_new(buf, bufsz, nvm_addr, 0x0, 64);
	for (guint i = 0; i < chunks->len; i++) {
		FuChunk *chk = g_ptr_array_index(chunks, i);
		g_autoptr(FuStructIntelUsb4MetadataNvmRead) st =
		    fu_struct_intel_usb4_metadata_nvm_read_new();

		/* ask hub to read up to 64 bytes from NVM to mbox data regs */
		fu_struct_intel_usb4_metadata_nvm_read_set_address(
		    st,
		    NVM_OFFSET_TO_METADATA(fu_chunk_get_address(chk)));
		fu_struct_intel_usb4_metadata_nvm_read_set_length(st,
								  fu_chunk_get_data_sz(chk) / 4);
		if (!fu_intel_usb4_device_operation(self,
						    FU_INTEL_USB4_OPCODE_NVM_READ,
						    st->data,
						    st->len,
						    error)) {
			g_prefix_error(error, "hub NVM read error: ");
			return FALSE;
		}

		/* read the data from mbox data regs */
		if (!fu_intel_usb4_device_mbox_data_read(self,
							 fu_chunk_get_data_out(chk),
							 fu_chunk_get_data_sz(chk),
							 error)) {
			g_prefix_error(error, "hub firmware mbox data read error: ");
			return FALSE;
		}
	}

	/* success */
	return TRUE;
}

static gboolean
fu_intel_usb4_device_nvm_write(FuIntelUsb4Device *self,
			       GBytes *blob,
			       guint32 nvm_addr,
			       FuProgress *progress,
			       GError **error)
{
	guint8 metadata[4] = {0};
	g_autoptr(FuChunkArray) chunks = NULL;

	if (nvm_addr % 4 != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "Invalid NVM write offset 0x%x, must be DW aligned: ",
			    nvm_addr);
		return FALSE;
	}
	if (g_bytes_get_size(blob) < 64 || g_bytes_get_size(blob) % 64) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "Invalid NVM length 0x%x, must be 64 byte aligned: ",
			    (guint)g_bytes_get_size(blob));
		return FALSE;
	}

	/* set initial offset, must be DW aligned */
	fu_memwrite_uint32(metadata, NVM_OFFSET_TO_METADATA(nvm_addr), G_LITTLE_ENDIAN);
	if (!fu_intel_usb4_device_operation(self,
					    FU_INTEL_USB4_OPCODE_NVM_SET_OFFSET,
					    metadata,
					    sizeof(metadata),
					    error)) {
		g_prefix_error(error, "hub NVM set offset error: ");
		return FALSE;
	}

	/* write data in 64 byte blocks */
	chunks = fu_chunk_array_new_from_bytes(blob,
					       FU_CHUNK_ADDR_OFFSET_NONE,
					       FU_CHUNK_PAGESZ_NONE,
					       64);
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_set_steps(progress, fu_chunk_array_length(chunks));
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_WRITE);
	for (guint i = 0; i < fu_chunk_array_length(chunks); i++) {
		g_autoptr(FuChunk) chk = NULL;

		/* prepare chunk */
		chk = fu_chunk_array_index(chunks, i, error);
		if (chk == NULL)
			return FALSE;

		/* write data to mbox data regs */
		if (!fu_intel_usb4_device_mbox_data_write(self,
							  fu_chunk_get_data(chk),
							  fu_chunk_get_data_sz(chk),
							  error)) {
			g_prefix_error(error, "hub mbox data write error: ");
			return FALSE;
		}
		/* ask hub to write 64 bytes from data regs to NVM */
		if (!fu_intel_usb4_device_operation(self,
						    FU_INTEL_USB4_OPCODE_NVM_WRITE,
						    NULL,
						    0,
						    error)) {
			g_prefix_error(error, "hub NVM write operation error: ");
			return FALSE;
		}

		/* done */
		fu_progress_step_done(progress);
	}

	/* success */
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_BUSY);
	return TRUE;
}

static gboolean
fu_intel_usb4_device_activate(FuDevice *device, FuProgress *progress, GError **error)
{
	FuIntelUsb4Device *self = FU_INTEL_USB4_DEVICE(device);
	g_autoptr(FuDeviceLocker) locker = fu_device_locker_new(device, error);
	if (locker == NULL)
		return FALSE;

	if (!fu_intel_usb4_device_operation(self,
					    FU_INTEL_USB4_OPCODE_NVM_AUTH_WRITE,
					    NULL,
					    0,
					    error)) {
		g_prefix_error(error, "NVM authenticate failed: ");
		fu_device_set_update_state(device, FWUPD_UPDATE_STATE_FAILED);
		return FALSE;
	}
	fu_device_set_update_state(device, FWUPD_UPDATE_STATE_SUCCESS);
	return TRUE;
}

static FuFirmware *
fu_intel_usb4_device_prepare_firmware(FuDevice *device,
				      GInputStream *stream,
				      FuProgress *progress,
				      FuFirmwareParseFlags flags,
				      GError **error)
{
	FuIntelUsb4Device *self = FU_INTEL_USB4_DEVICE(device);
	guint16 fw_vendor_id;
	guint16 fw_model_id;
	g_autoptr(FuFirmware) firmware = fu_intel_thunderbolt_firmware_new();

	/* get vid:pid:rev */
	if (!fu_firmware_parse_stream(firmware, stream, 0x0, flags, error))
		return NULL;

	/* check is compatible */
	fw_vendor_id = fu_intel_thunderbolt_nvm_get_vendor_id(FU_INTEL_THUNDERBOLT_NVM(firmware));
	fw_model_id = fu_intel_thunderbolt_nvm_get_model_id(FU_INTEL_THUNDERBOLT_NVM(firmware));
	if (self->nvm_vendor_id != fw_vendor_id || self->nvm_model_id != fw_model_id) {
		if ((flags & FU_FIRMWARE_PARSE_FLAG_IGNORE_VID_PID) == 0) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "firmware 0x%04x:0x%04x does not match device 0x%04x:0x%04x",
				    fw_vendor_id,
				    fw_model_id,
				    self->nvm_vendor_id,
				    self->nvm_model_id);
			return NULL;
		}
		g_warning("firmware 0x%04x:0x%04x does not match device 0x%04x:0x%04x",
			  fw_vendor_id,
			  fw_model_id,
			  self->nvm_vendor_id,
			  self->nvm_model_id);
	}

	/* success */
	return g_steal_pointer(&firmware);
}

static gboolean
fu_intel_usb4_device_write_firmware(FuDevice *device,
				    FuFirmware *firmware,
				    FuProgress *progress,
				    FwupdInstallFlags flags,
				    GError **error)
{
	FuIntelUsb4Device *self = FU_INTEL_USB4_DEVICE(device);
	g_autoptr(GBytes) fw_image = NULL;

	g_return_val_if_fail(device != NULL, FALSE);
	g_return_val_if_fail(FU_IS_FIRMWARE(firmware), FALSE);

	/* get payload */
	fw_image = fu_firmware_get_image_by_id_bytes(firmware, FU_FIRMWARE_ID_PAYLOAD, error);
	if (fw_image == NULL)
		return FALSE;

	/* firmware install */
	if (!fu_intel_usb4_device_nvm_write(self, fw_image, 0, progress, error))
		return FALSE;

	/* success, but needs activation */
	if (fu_device_has_private_flag(device, FU_DEVICE_PRIVATE_FLAG_SKIPS_RESTART)) {
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_NEEDS_ACTIVATION);
		fu_device_set_version(device, fu_firmware_get_version(firmware));
		return TRUE;
	}

	/* activate, wait for replug */
	if (!fu_intel_usb4_device_operation(self,
					    FU_INTEL_USB4_OPCODE_NVM_AUTH_WRITE,
					    NULL,
					    0,
					    error)) {
		g_prefix_error(error, "NVM authenticate failed: ");
		return FALSE;
	}
	fu_device_add_flag(device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);

	/* success */
	return TRUE;
}

static gboolean
fu_intel_usb4_device_setup(FuDevice *device, GError **error)
{
	FuIntelUsb4Device *self = FU_INTEL_USB4_DEVICE(device);
	guint8 buf[NVM_READ_LENGTH] = {0x0};
	g_autofree gchar *name = NULL;
	g_autoptr(FuFirmware) fw = fu_intel_thunderbolt_nvm_new();
	g_autoptr(GBytes) blob = NULL;

	/* FuUsbDevice->setup */
	if (!FU_DEVICE_CLASS(fu_intel_usb4_device_parent_class)->setup(device, error))
		return FALSE;

	/* read from device and parse firmware */
	if (!fu_intel_usb4_device_nvm_read(self, buf, sizeof(buf), 0, error)) {
		g_prefix_error(error, "NVM read error: ");
		return FALSE;
	}
	blob = g_bytes_new(buf, sizeof(buf));
	if (!fu_firmware_parse_bytes(fw, blob, 0x0, FU_FIRMWARE_PARSE_FLAG_NONE, error)) {
		g_prefix_error(error, "NVM parse error: ");
		return FALSE;
	}
	self->nvm_vendor_id = fu_intel_thunderbolt_nvm_get_vendor_id(FU_INTEL_THUNDERBOLT_NVM(fw));
	self->nvm_model_id = fu_intel_thunderbolt_nvm_get_model_id(FU_INTEL_THUNDERBOLT_NVM(fw));
	self->nvm_device_id = fu_intel_thunderbolt_nvm_get_device_id(FU_INTEL_THUNDERBOLT_NVM(fw));

	name = g_strdup_printf("TBT-%04x%04x", self->nvm_vendor_id, self->nvm_model_id);
	fu_device_add_instance_id(device, name);
	fu_device_set_version(device, fu_firmware_get_version(fw));
	return TRUE;
}

static void
fu_intel_usb4_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuIntelUsb4Device *self = FU_INTEL_USB4_DEVICE(device);
	fwupd_codec_string_append_hex(str, idt, "NvmVendorId", self->nvm_vendor_id);
	fwupd_codec_string_append_hex(str, idt, "NvmModelId", self->nvm_model_id);
	fwupd_codec_string_append_hex(str, idt, "NvmDeviceId", self->nvm_device_id);
}

static void
fu_intel_usb4_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DECOMPRESSING, 0, "prepare-fw");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 0, "detach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 78, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 22, "attach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 0, "reload");
}

static void
fu_intel_usb4_device_init(FuIntelUsb4Device *self)
{
	self->intf_nr = GR_USB_INTERFACE_NUMBER;
	self->blocksz = GR_USB_BLOCK_SIZE;
	fu_device_add_protocol(FU_DEVICE(self), "com.intel.thunderbolt");
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_SIGNED_PAYLOAD);
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PAIR);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_INHERIT_ACTIVATION);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_MD_SET_NAME_CATEGORY);
	fu_device_add_private_flag(FU_DEVICE(self), FU_DEVICE_PRIVATE_FLAG_NO_GENERIC_GUIDS);
	fu_device_set_remove_delay(FU_DEVICE(self), FU_INTEL_USB4_DEVICE_REMOVE_DELAY);
}

static void
fu_intel_usb4_device_class_init(FuIntelUsb4DeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->to_string = fu_intel_usb4_device_to_string;
	device_class->setup = fu_intel_usb4_device_setup;
	device_class->prepare_firmware = fu_intel_usb4_device_prepare_firmware;
	device_class->write_firmware = fu_intel_usb4_device_write_firmware;
	device_class->activate = fu_intel_usb4_device_activate;
	device_class->set_progress = fu_intel_usb4_device_set_progress;
}
