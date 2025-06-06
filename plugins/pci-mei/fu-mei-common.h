/*
 * Copyright 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "fu-mei-struct.h"

typedef struct {
	guint8 platform;
	guint8 major;
	guint8 minor;
	guint8 hotfix;
	guint16 buildno;
} FuMeiVersion;

FuMeiIssue
fu_mei_common_is_csme_vulnerable(FuMeiVersion *vers);
FuMeiIssue
fu_mei_common_is_txe_vulnerable(FuMeiVersion *vers);
FuMeiIssue
fu_mei_common_is_sps_vulnerable(FuMeiVersion *vers);
