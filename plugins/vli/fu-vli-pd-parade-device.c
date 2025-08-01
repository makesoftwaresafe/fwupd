/*
 * Copyright 2015 VIA Corporation
 * Copyright 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-vli-pd-device.h"
#include "fu-vli-pd-parade-device.h"
#include "fu-vli-struct.h"

struct _FuVliPdParadeDevice {
	FuUsbDevice parent_instance;
	FuVliDeviceKind device_kind;
	guint8 page2; /* base address */
	guint8 page7; /* base address */
};

G_DEFINE_TYPE(FuVliPdParadeDevice, fu_vli_pd_parade_device, FU_TYPE_USB_DEVICE)

#define FU_VLI_PD_PARADE_I2C_CMD_WRITE 0xa6
#define FU_VLI_PD_PARADE_I2C_CMD_READ  0xa5

static void
fu_vli_pd_parade_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuVliPdParadeDevice *self = FU_VLI_PD_PARADE_DEVICE(device);
	fwupd_codec_string_append(str,
				  idt,
				  "DeviceKind",
				  fu_vli_device_kind_to_string(self->device_kind));
	fwupd_codec_string_append_hex(str, idt, "Page2", self->page2);
	fwupd_codec_string_append_hex(str, idt, "Page7", self->page7);
}

static gboolean
fu_vli_pd_parade_device_i2c_read(FuVliPdParadeDevice *self,
				 guint8 page2,
				 guint8 reg_offset, /* customers addr offset */
				 guint8 *buf,
				 gsize bufsz,
				 GError **error)
{
	guint16 value;

	/* sanity check */
	if (bufsz > 0x40) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE, "request too large");
		return FALSE;
	}

	/* VL103 FW only Use bits[7:1], so divide by 2 */
	value = ((guint16)reg_offset << 8) | (page2 >> 1);
	if (!fu_usb_device_control_transfer(FU_USB_DEVICE(self),
					    FU_USB_DIRECTION_DEVICE_TO_HOST,
					    FU_USB_REQUEST_TYPE_VENDOR,
					    FU_USB_RECIPIENT_DEVICE,
					    FU_VLI_PD_PARADE_I2C_CMD_READ,
					    value,
					    0x0,
					    buf,
					    bufsz,
					    NULL,
					    FU_VLI_DEVICE_TIMEOUT,
					    NULL,
					    error)) {
		g_prefix_error(error, "failed to read 0x%x:0x%x: ", page2, reg_offset);
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_i2c_write(FuVliPdParadeDevice *self,
				  guint8 page2,
				  guint8 reg_offset, /* customers addr offset */
				  guint8 val,	     /* only one byte supported */
				  GError **error)
{
	guint16 value;
	guint16 index;
	guint8 buf[2] = {0x0}; /* apparently unused... */

	/* VL103 FW only Use bits[7:1], so divide by 2 */
	value = ((guint16)reg_offset << 8) | (page2 >> 1);
	index = (guint16)val << 8;
	if (!fu_usb_device_control_transfer(FU_USB_DEVICE(self),
					    FU_USB_DIRECTION_HOST_TO_DEVICE,
					    FU_USB_REQUEST_TYPE_VENDOR,
					    FU_USB_RECIPIENT_DEVICE,
					    FU_VLI_PD_PARADE_I2C_CMD_WRITE,
					    value,
					    index,
					    buf,
					    0x0,
					    NULL,
					    FU_VLI_DEVICE_TIMEOUT,
					    NULL,
					    error)) {
		g_prefix_error(error, "failed to write 0x%x:0x%x: ", page2, reg_offset);
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_start_mcu(FuVliPdParadeDevice *self, GError **error)
{
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xBC, 0x00, error)) {
		g_prefix_error(error, "failed to start MCU: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_stop_mcu(FuVliPdParadeDevice *self, GError **error)
{
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xBC, 0xC0, error)) {
		g_prefix_error(error, "failed to stop MCU: ");
		return FALSE;
	}
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xBC, 0x40, error)) {
		g_prefix_error(error, "failed to stop MCU 2nd: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_set_offset(FuVliPdParadeDevice *self, guint16 addr, GError **error)
{
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x8E, addr >> 8, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x8F, addr & 0xff, error))
		return FALSE;
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_read_fw_ver(FuVliPdParadeDevice *self, GError **error)
{
	guint8 buf[0x20] = {0x0};
	g_autofree gchar *version_str = NULL;

	/* stop MCU */
	if (!fu_vli_pd_parade_device_stop_mcu(self, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_set_offset(self, 0x0, error))
		return FALSE;
	fu_device_sleep(FU_DEVICE(self), 10); /* ms */
	if (!fu_vli_pd_parade_device_i2c_read(self, self->page7, 0x02, buf, 0x1, error))
		return FALSE;
	if (buf[0] != 0x01 && buf[0] != 0x02) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "not supported on this device: buffer was 0x%02x",
			    buf[0]);
		return FALSE;
	}

	g_debug("getting FW%X version", buf[0]);
	if (!fu_vli_pd_parade_device_set_offset(self, 0x5000 | buf[0], error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_read(self, self->page7, 0x00, buf, sizeof(buf), error))
		return FALSE;

	/* start MCU */
	if (!fu_vli_pd_parade_device_start_mcu(self, error))
		return FALSE;

	/* format version triplet */
	version_str = g_strdup_printf("%u.%u.%u", buf[0], buf[1], buf[2]);
	fu_device_set_version(FU_DEVICE(self), version_str);
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_set_wp(FuVliPdParadeDevice *self, gboolean val, GError **error)
{
	return fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xB3, val ? 0x10 : 0x00, error);
}

static gboolean
fu_vli_pd_parade_device_write_enable(FuVliPdParadeDevice *self, GError **error)
{
	/* Set_WP_High, SPI_WEN_06, Len_00, Trigger_Write, Set_WP_Low */
	if (!fu_vli_pd_parade_device_set_wp(self, TRUE, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, 0x06, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x92, 0x00, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x93, 0x05, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_set_wp(self, FALSE, error))
		return FALSE;
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_write_disable(FuVliPdParadeDevice *self, GError **error)
{
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xDA, 0x00, error))
		return FALSE;
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_write_status(FuVliPdParadeDevice *self,
				     guint8 target_status,
				     GError **error)
{
	/* Set_WP_High, SPI_WSTS_01, Target_Status, Len_01, Trigger_Write, Set_WP_Low */
	if (!fu_vli_pd_parade_device_set_wp(self, TRUE, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, 0x01, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, target_status, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x92, 0x01, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x93, 0x05, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_set_wp(self, FALSE, error))
		return FALSE;
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_wait_ready(FuVliPdParadeDevice *self, GError **error)
{
	gboolean ret = FALSE;
	guint limit = 100;
	guint8 buf = 0x0;

	/* wait for SPI ROM */
	for (guint wait_cnt1 = 0; wait_cnt1 < limit; wait_cnt1++) {
		buf = 0xFF;
		if (!fu_vli_pd_parade_device_i2c_read(self,
						      self->page2,
						      0x9E,
						      &buf,
						      sizeof(buf),
						      error))
			return FALSE;
		/* busy status:
		 * bit[1,0]:Byte_Program
		 * bit[3,2]:Sector Erase
		 * bit[5,4]:Chip Erase */
		if ((buf & 0x0C) == 0) {
			ret = TRUE;
			break;
		}
	}
	if (!ret) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "failed to wait for SPI not BUSY");
		return FALSE;
	}

	/* wait for SPI ROM status clear */
	ret = FALSE;
	for (guint wait_cnt1 = 0; wait_cnt1 < limit; wait_cnt1++) {
		gboolean ret2 = FALSE;

		/* SPI_RSTS_05, Len_01, Trigger_Read */
		if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, 0x05, error))
			return FALSE;
		if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x92, 0x00, error))
			return FALSE;
		if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x93, 0x01, error))
			return FALSE;

		/* wait for cmd done */
		for (guint wait_cnt2 = 0; wait_cnt2 < limit; wait_cnt2++) {
			buf = 0xFF;
			if (!fu_vli_pd_parade_device_i2c_read(self,
							      self->page2,
							      0x93,
							      &buf,
							      sizeof(buf),
							      error))
				return FALSE;
			if ((buf & 0x01) == 0) {
				ret2 = TRUE;
				break;
			}
		}
		if (!ret2) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "failed to wait for SPI CMD done");
			return FALSE;
		}

		/* Wait_SPI_STS_00 */
		buf = 0xFF;
		if (!fu_vli_pd_parade_device_i2c_read(self,
						      self->page2,
						      0x91,
						      &buf,
						      sizeof(buf),
						      error))
			return FALSE;
		if ((buf & 0x01) == 0) {
			ret = TRUE;
			break;
		}
	}
	if (!ret) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "failed to wait for SPI status clear");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_sector_erase(FuVliPdParadeDevice *self, guint16 addr, GError **error)
{
	/* SPI_SE_20, SPI_Adr_H, SPI_Adr_M, SPI_Adr_L, Len_03, Trigger_Write */
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, 0x20, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, addr >> 8, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, addr & 0xff, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x90, 0x00, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x92, 0x03, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x93, 0x05, error))
		return FALSE;
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_enable_mapping(FuVliPdParadeDevice *self, GError **error)
{
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xDA, 0xAA, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xDA, 0x55, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xDA, 0x50, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xDA, 0x41, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xDA, 0x52, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0xDA, 0x44, error))
		return FALSE;
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_block_erase(FuVliPdParadeDevice *self, guint8 block_idx, GError **error)
{
	/* erase */
	for (guint idx = 0x00; idx < 0x100; idx += 0x10) {
		if (!fu_vli_pd_parade_device_write_enable(self, error))
			return FALSE;
		if (!fu_vli_pd_parade_device_set_wp(self, TRUE, error))
			return FALSE;
		if (!fu_vli_pd_parade_device_sector_erase(self,
							  ((guint16)block_idx << 8) | idx,
							  error))
			return FALSE;
		if (!fu_vli_pd_parade_device_wait_ready(self, error))
			return FALSE;
		if (!fu_vli_pd_parade_device_set_wp(self, FALSE, error))
			return FALSE;
	}

	/* verify */
	for (guint idx = 0; idx < 0x100; idx += 0x10) {
		guint8 buf[0x20] = {0xff};
		if (!fu_vli_pd_parade_device_set_offset(self, (block_idx << 8) | idx, error))
			return FALSE;
		if (!fu_vli_pd_parade_device_i2c_read(self, self->page7, 0, buf, 0x20, error))
			return FALSE;
		for (guint idx2 = 0; idx2 < 0x20; idx2++) {
			if (buf[idx2] != 0xFF) {
				guint32 addr = (block_idx << 16) + (idx << 8);
				g_set_error(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_INTERNAL,
					    "Erase failed @0x%x",
					    addr);
				return FALSE;
			}
		}
	}

	/* success */
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_block_write(FuVliPdParadeDevice *self,
				    guint8 block_idx,
				    const guint8 *txbuf,
				    GError **error)
{
	for (guint idx = 0; idx < 0x100; idx++) {
		if (!fu_vli_pd_parade_device_set_offset(self, (block_idx << 8) | idx, error))
			return FALSE;
		for (guint idx2 = 0; idx2 < 0x100; idx2++) {
			guint32 buf_offset = (idx << 8) + idx2;
			if (!fu_vli_pd_parade_device_i2c_write(self,
							       self->page7,
							       (guint8)idx2,
							       txbuf[buf_offset],
							       error))
				return FALSE;
		}
	}

	/* success */
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_block_read(FuVliPdParadeDevice *self,
				   guint8 block_idx,
				   guint8 *buf,
				   gsize bufsz,
				   GError **error)
{
	for (guint idx = 0; idx < 0x100; idx++) {
		if (!fu_vli_pd_parade_device_set_offset(self, (block_idx << 8) | idx, error))
			return FALSE;
		for (guint idx2 = 0; idx2 < 0x100; idx2 += 0x20) {
			guint buf_offset = (idx << 8) + idx2;
			if (!fu_vli_pd_parade_device_i2c_read(self,
							      self->page7,
							      idx2,
							      buf + buf_offset,
							      0x20,
							      error))
				return FALSE;
		}
	}
	return TRUE;
}

static gboolean
fu_vli_pd_parade_device_write_firmware(FuDevice *device,
				       FuFirmware *firmware,
				       FuProgress *progress,
				       FwupdInstallFlags flags,
				       GError **error)
{
	FuVliPdParadeDevice *self = FU_VLI_PD_PARADE_DEVICE(device);
	FuVliPdDevice *parent = FU_VLI_PD_DEVICE(fu_device_get_parent(device));
	guint8 buf[0x20] = {0};
	guint block_idx_tmp;
	g_autoptr(FuDeviceLocker) locker = NULL;
	g_autoptr(GByteArray) buf_verify = NULL;
	g_autoptr(GBytes) fw = NULL;
	g_autoptr(GBytes) fw_verify = NULL;
	g_autoptr(FuChunk) chk0 = NULL;
	g_autoptr(FuChunkArray) blocks = NULL;

	/* progress */
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_flag(progress, FU_PROGRESS_FLAG_GUESSED);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_ERASE, 19, NULL);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 45, NULL);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_VERIFY, 36, NULL);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1, NULL);

	/* simple image */
	fw = fu_firmware_get_bytes(firmware, error);
	if (fw == NULL)
		return FALSE;

	/* open device */
	locker = fu_device_locker_new(parent, error);
	if (locker == NULL)
		return FALSE;

	/*  stop MPU and reset SPI */
	if (!fu_vli_pd_parade_device_stop_mcu(self, error))
		return FALSE;

	/*  64K block erase */
	if (!fu_vli_pd_parade_device_write_enable(self, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_write_status(self, 0x00, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_wait_ready(self, error))
		return FALSE;
	blocks = fu_chunk_array_new_from_bytes(fw,
					       FU_CHUNK_ADDR_OFFSET_NONE,
					       FU_CHUNK_PAGESZ_NONE,
					       0x10000);
	for (guint i = 1; i < fu_chunk_array_length(blocks); i++) {
		g_autoptr(FuChunk) chk = fu_chunk_array_index(blocks, i, error);
		if (chk == NULL)
			return FALSE;
		if (!fu_vli_pd_parade_device_block_erase(self, fu_chunk_get_idx(chk), error))
			return FALSE;
		fu_progress_set_percentage_full(fu_progress_get_child(progress),
						i + 1,
						fu_chunk_array_length(blocks));
	}
	fu_progress_step_done(progress);

	/*  load F/W to SPI ROM */
	if (!fu_vli_pd_parade_device_enable_mapping(self, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x82, 0x20, error))
		return FALSE;	      /* Reset_CLT2SPI_Interface */
	fu_device_sleep(device, 100); /* ms */
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page2, 0x82, 0x00, error))
		return FALSE;

	/* write blocks */
	for (guint i = 1; i < fu_chunk_array_length(blocks); i++) {
		g_autoptr(FuChunk) chk = fu_chunk_array_index(blocks, i, error);
		if (chk == NULL)
			return FALSE;
		if (!fu_vli_pd_parade_device_block_write(self,
							 fu_chunk_get_idx(chk),
							 fu_chunk_get_data(chk),
							 error))
			return FALSE;
		fu_progress_set_percentage_full(fu_progress_get_child(progress),
						i + 1,
						fu_chunk_array_length(blocks));
	}
	if (!fu_vli_pd_parade_device_write_disable(self, error))
		return FALSE;
	fu_progress_step_done(progress);

	/* add the new boot config into the verify buffer */
	buf_verify = g_byte_array_sized_new(g_bytes_get_size(fw));
	chk0 = fu_chunk_array_index(blocks, 0, error);
	if (chk0 == NULL)
		return FALSE;
	g_byte_array_append(buf_verify, fu_chunk_get_data(chk0), fu_chunk_get_data_sz(chk0));

	/*  verify SPI ROM, ignoring the boot config */
	for (guint i = 1; i < fu_chunk_array_length(blocks); i++) {
		g_autofree guint8 *vbuf = NULL;
		g_autoptr(FuChunk) chk = NULL;

		chk = fu_chunk_array_index(blocks, i, error);
		if (chk == NULL)
			return FALSE;
		vbuf = g_malloc0(fu_chunk_get_data_sz(chk));
		if (!fu_vli_pd_parade_device_block_read(self,
							fu_chunk_get_idx(chk),
							vbuf,
							fu_chunk_get_data_sz(chk),
							error))
			return FALSE;
		g_byte_array_append(buf_verify, vbuf, fu_chunk_get_data_sz(chk));
		fu_progress_set_percentage_full(fu_progress_get_child(progress),
						i + 1,
						fu_chunk_array_length(blocks));
	}
	fw_verify = g_bytes_new(buf_verify->data, buf_verify->len);
	if (!fu_bytes_compare(fw, fw_verify, error))
		return FALSE;
	fu_progress_step_done(progress);

	/*  save boot config into Block_0 */
	if (!fu_vli_pd_parade_device_write_enable(self, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_set_wp(self, TRUE, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_sector_erase(self, 0x0, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_wait_ready(self, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_set_wp(self, FALSE, error))
		return FALSE;

	/* Page_HW_Write_Disable */
	if (!fu_vli_pd_parade_device_enable_mapping(self, error))
		return FALSE;

	block_idx_tmp = 1;
	if (!fu_vli_pd_parade_device_set_offset(self, 0x0, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page7, 0x00, 0x55, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self, self->page7, 0x01, 0xAA, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self,
					       self->page7,
					       0x02,
					       (guint8)block_idx_tmp,
					       error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_write(self,
					       self->page7,
					       0x03,
					       (guint8)(0x01 - block_idx_tmp),
					       error))
		return FALSE;
	if (!fu_vli_pd_parade_device_write_disable(self, error))
		return FALSE;

	/*  check boot config data */
	if (!fu_vli_pd_parade_device_set_offset(self, 0x0, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_i2c_read(self, self->page7, 0, buf, sizeof(buf), error))
		return FALSE;
	if (buf[0] != 0x55 || buf[1] != 0xAA || buf[2] != block_idx_tmp ||
	    buf[3] != 0x01 - block_idx_tmp) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "boot config data error");
		return FALSE;
	}

	/*  enable write protection */
	if (!fu_vli_pd_parade_device_write_enable(self, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_write_status(self, 0x8C, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_wait_ready(self, error))
		return FALSE;
	if (!fu_vli_pd_parade_device_write_disable(self, error))
		return FALSE;
	fu_progress_step_done(progress);

	/* success */
	return TRUE;
}

static GBytes *
fu_vli_pd_parade_device_dump_firmware(FuDevice *device, FuProgress *progress, GError **error)
{
	FuVliPdDevice *parent = FU_VLI_PD_DEVICE(fu_device_get_parent(device));
	FuVliPdParadeDevice *self = FU_VLI_PD_PARADE_DEVICE(device);
	g_autoptr(FuDeviceLocker) locker = NULL;
	g_autoptr(GByteArray) fw = g_byte_array_new();
	g_autoptr(GPtrArray) blocks = NULL;

	/* open device */
	locker = fu_device_locker_new(parent, error);
	if (locker == NULL)
		return NULL;

	/*  stop MPU and reset SPI */
	if (!fu_vli_pd_parade_device_stop_mcu(self, error))
		return NULL;

	/* read */
	fu_progress_set_status(progress, FWUPD_STATUS_DEVICE_VERIFY);
	fu_byte_array_set_size(fw, fu_device_get_firmware_size_max(device), 0x00);
	blocks = fu_chunk_array_mutable_new(fw->data, fw->len, 0x0, 0x0, 0x10000);
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_set_steps(progress, blocks->len);
	for (guint i = 0; i < blocks->len; i++) {
		FuChunk *chk = g_ptr_array_index(blocks, i);
		if (!fu_vli_pd_parade_device_block_read(self,
							fu_chunk_get_idx(chk),
							fu_chunk_get_data_out(chk),
							fu_chunk_get_data_sz(chk),
							error))
			return NULL;
		fu_progress_step_done(progress);
	}
	return g_bytes_new(fw->data, fw->len);
}

static gboolean
fu_vli_pd_parade_device_probe(FuDevice *device, GError **error)
{
	FuVliPdParadeDevice *self = FU_VLI_PD_PARADE_DEVICE(device);

	/* get version */
	if (!fu_vli_pd_parade_device_read_fw_ver(self, error))
		return FALSE;

	/* use header to populate device info */
	fu_device_add_instance_str(device, "I2C", fu_vli_device_kind_to_string(self->device_kind));
	return fu_device_build_instance_id(device, error, "USB", "VID", "PID", "I2C", NULL);
}

static void
fu_vli_pd_parade_device_set_progress(FuDevice *self, FuProgress *progress)
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
fu_vli_pd_parade_device_init(FuVliPdParadeDevice *self)
{
	self->device_kind = FU_VLI_DEVICE_KIND_PS186;
	self->page2 = 0x14;
	self->page7 = 0x1E;
	fu_device_add_icon(FU_DEVICE(self), FU_DEVICE_ICON_VIDEO_DISPLAY);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_CAN_VERIFY_IMAGE);
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_TRIPLET);
	fu_device_add_protocol(FU_DEVICE(self), "com.vli.i2c");
	fu_device_set_install_duration(FU_DEVICE(self), 15); /* seconds */
	fu_device_set_logical_id(FU_DEVICE(self), "PS186");
	fu_device_set_summary(FU_DEVICE(self), "DisplayPort 1.4a to HDMI 2.0b protocol converter");
	fu_device_set_firmware_size(FU_DEVICE(self), 0x40000);
}

static void
fu_vli_pd_parade_device_class_init(FuVliPdParadeDeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->to_string = fu_vli_pd_parade_device_to_string;
	device_class->probe = fu_vli_pd_parade_device_probe;
	device_class->dump_firmware = fu_vli_pd_parade_device_dump_firmware;
	device_class->write_firmware = fu_vli_pd_parade_device_write_firmware;
	device_class->set_progress = fu_vli_pd_parade_device_set_progress;
}

FuDevice *
fu_vli_pd_parade_device_new(FuVliDevice *parent)
{
	FuVliPdParadeDevice *self =
	    g_object_new(FU_TYPE_VLI_PD_PARADE_DEVICE, "parent", parent, NULL);
	return FU_DEVICE(self);
}
