/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_HAILUCK_KBD_FIRMWARE (fu_hailuck_kbd_firmware_get_type())
G_DECLARE_FINAL_TYPE(FuHailuckKbdFirmware,
		     fu_hailuck_kbd_firmware,
		     FU,
		     HAILUCK_KBD_FIRMWARE,
		     FuIhexFirmware)
