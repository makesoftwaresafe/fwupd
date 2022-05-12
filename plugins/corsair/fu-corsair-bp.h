/*
 * Copyright (C) 2021 Andrii Dushko <andrii.dushko@developex.net>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#include "fu-corsair-common.h"

#define FU_TYPE_CORSAIR_BP (fu_corsair_bp_get_type())
G_DECLARE_FINAL_TYPE(FuCorsairBp, fu_corsair_bp, FU, CORSAIR_BP, GObject)

struct _FuCorsairBpClass {
	GObjectClass parent_class;
};

gboolean
fu_corsair_bp_get_property(FuCorsairBp *self,
			   FuCorsairBpProperty property,
			   guint32 *value,
			   GError **error);

gboolean
fu_corsair_bp_set_mode(FuCorsairBp *self, FuCorsairDeviceMode mode, GError **error);
gboolean
fu_corsair_bp_attach_legacy(FuCorsairBp *self, GError **error);

gboolean
fu_corsair_bp_write_firmware(FuCorsairBp *self,
			     FuFirmware *firmware,
			     FuProgress *progress,
			     GError **error);
gboolean
fu_corsair_bp_activate_firmware(FuCorsairBp *self, FuFirmware *firmware, GError **error);

void
fu_corsair_bp_set_cmd_size(FuCorsairBp *self, guint16 write_size, guint16 read_size);
void
fu_corsair_bp_set_is_subdevice(FuCorsairBp *self, gboolean is_subdevice);

FuCorsairBp *
fu_corsair_bp_new(GUsbDevice *usb_device, gboolean is_subdevice, guint8 epin, guint8 epout);
FuCorsairBp *
fu_corsair_bp_clone(FuCorsairBp *self);
