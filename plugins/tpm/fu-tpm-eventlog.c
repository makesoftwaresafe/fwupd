/*
 * Copyright 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define G_LOG_DOMAIN "FuTpmEventlog"

#include "config.h"

#include <glib/gi18n.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fu-tpm-eventlog-parser.h"

static gint
fu_tpm_eventlog_sort_cb(gconstpointer a, gconstpointer b)
{
	FuTpmEventlogItem *item_a = *((FuTpmEventlogItem **)a);
	FuTpmEventlogItem *item_b = *((FuTpmEventlogItem **)b);
	if (item_a->pcr > item_b->pcr)
		return 1;
	if (item_a->pcr < item_b->pcr)
		return -1;
	return 0;
}

static gboolean
fu_tpm_eventlog_process(const gchar *fn, gint pcr, GError **error)
{
	gsize bufsz = 0;
	g_autofree guint8 *buf = NULL;
	g_autoptr(GPtrArray) items = NULL;
	g_autoptr(GString) str = g_string_new(NULL);
	gint max_pcr = 0;

	/* parse this */
	if (!g_file_get_contents(fn, (gchar **)&buf, &bufsz, error))
		return FALSE;
	items = fu_tpm_eventlog_parser_new(buf, bufsz, FU_TPM_EVENTLOG_PARSER_FLAG_ALL_PCRS, error);
	if (items == NULL)
		return FALSE;
	g_ptr_array_sort(items, fu_tpm_eventlog_sort_cb);

	for (guint i = 0; i < items->len; i++) {
		FuTpmEventlogItem *item = g_ptr_array_index(items, i);
		if (item->pcr > max_pcr)
			max_pcr = item->pcr;
		if (pcr >= 0 && item->pcr != pcr)
			continue;
		fu_tpm_eventlog_item_to_string(item, 0, str);
		g_string_append(str, "\n");
	}
	if (pcr > max_pcr) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "invalid PCR specified: %d",
			    pcr);
		return FALSE;
	}
	fwupd_codec_string_append(str, 0, "Reconstructed PCRs", "");
	for (guint8 i = 0; i <= max_pcr; i++) {
		g_autoptr(GPtrArray) pcrs = fu_tpm_eventlog_calc_checksums(items, i, NULL);
		if (pcrs == NULL)
			continue;
		for (guint j = 0; j < pcrs->len; j++) {
			const gchar *csum = g_ptr_array_index(pcrs, j);
			g_autofree gchar *title = NULL;
			g_autofree gchar *pretty = NULL;
			if (pcr >= 0 && i != (guint)pcr)
				continue;
			title = g_strdup_printf("PCR %x", i);
			pretty = fwupd_checksum_format_for_display(csum);
			fwupd_codec_string_append(str, 1, title, pretty);
		}
	}

	/* success */
	g_print("%s", str->str);
	return TRUE;
}

int
main(int argc, char *argv[])
{
	const gchar *fn;
	gboolean verbose = FALSE;
	gboolean interactive = isatty(fileno(stdout)) != 0;
	gint pcr = -1;
	g_autoptr(GError) error = NULL;
	g_autoptr(GOptionContext) context = g_option_context_new(NULL);
	const GOptionEntry options[] = {{"verbose",
					 'v',
					 0,
					 G_OPTION_ARG_NONE,
					 &verbose,
					 /* TRANSLATORS: command line option */
					 N_("Show extra debugging information"),
					 NULL},
					{"pcr",
					 'p',
					 0,
					 G_OPTION_ARG_INT,
					 &pcr,
					 /* TRANSLATORS: command line option */
					 N_("Only show single PCR value"),
					 NULL},
					{NULL}};

	setlocale(LC_ALL, "");
	bindtextdomain(GETTEXT_PACKAGE, FWUPD_LOCALEDIR);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
	textdomain(GETTEXT_PACKAGE);

#ifdef HAVE_GETUID
	/* ensure root user */
	if (argc < 2 && interactive && (getuid() != 0 || geteuid() != 0))
		/* TRANSLATORS: we're poking around as a power user */
		g_printerr("%s\n", _("This program may only work correctly as root"));
#endif

	/* TRANSLATORS: program name */
	g_set_application_name(_("fwupd TPM event log utility"));
	g_option_context_add_main_entries(context, options, NULL);
	g_option_context_set_description(context,
					 /* TRANSLATORS: CLI description */
					 _("This tool will read and parse the TPM event log "
					   "from the system firmware."));
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		/* TRANSLATORS: the user didn't read the man page */
		g_print("%s: %s\n", _("Failed to parse arguments"), error->message);
		return EXIT_FAILURE;
	}

	/* set verbose? */
	if (verbose) {
		(void)g_setenv("G_MESSAGES_DEBUG", "all", FALSE);
		(void)g_setenv("FWUPD_TPM_EVENTLOG_VERBOSE", "1", FALSE);
	}

	/* allow user to chose a local file */
	fn = argc <= 1 ? "/sys/kernel/security/tpm0/binary_bios_measurements" : argv[1];
	if (!fu_tpm_eventlog_process(fn, pcr, &error)) {
		/* TRANSLATORS: failed to read measurements file */
		g_printerr("%s: %s\n", _("Failed to parse file"), error->message);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
