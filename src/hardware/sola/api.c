/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2020 riktw <rik@justanotherelectronicsblog.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include "protocol.h"

#define SERIALCOMM "115200/8n1"

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
	SR_CONF_SERIALCOMM,
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
};

static const uint32_t devopts[] = {
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_EXTERNAL_CLOCK | SR_CONF_SET,
	SR_CONF_RLE | SR_CONF_GET | SR_CONF_SET,
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,
	SR_TRIGGER_ONE,
};

/* Channels are numbered 0-31 (on the PCB silkscreen). */
SR_PRIV const char *sols_channel_names[] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
	"13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23",
	"24", "25", "26", "27", "28", "29", "30", "31",
};

/* Default supported samplerates, can be overridden by device metadata. */
static const uint64_t samplerates[] = {
	SR_HZ(10),
	SR_MHZ(100),
	SR_HZ(1),
};

#define RESPONSE_DELAY_US (20 * 1000)

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	struct sr_config *src;
	struct sr_dev_inst *sdi;
	struct sr_serial_dev_inst *serial;
	GSList *l;
	int num_read;
	const char *conn, *serialcomm;
	char buf[4] = { 0, 0, 0, 0 };

	conn = serialcomm = NULL;
	for (l = options; l; l = l->next) {
		src = l->data;
		switch (src->key) {
		case SR_CONF_CONN:
			conn = g_variant_get_string(src->data, NULL);
			break;
		case SR_CONF_SERIALCOMM:
			serialcomm = g_variant_get_string(src->data, NULL);
			break;
		}
	}
	if (!conn)
		return NULL;

	if (!serialcomm)
		serialcomm = SERIALCOMM;

	serial = sr_serial_dev_inst_new(conn, serialcomm);

	/* The discovery procedure is like this: first send the Reset
	 * command (0x00) 5 times, since the device could be anywhere
	 * in a 5-byte command. Then send the ID command (0x02).
	 * If the device responds with 4 bytes ("sols1" or "SLA1"), we
	 * have a match.
	 */
	sr_info("Probing %s.", conn);
	if (serial_open(serial, SERIAL_RDWR) != SR_OK)
		return NULL;

	if (sols_send_reset(serial) != SR_OK) {
		serial_close(serial);
		sr_err("Could not use port %s. Quitting.", conn);
		return NULL;
	}
	sols_send_shortcommand(serial, CMD_ID);

	g_usleep(RESPONSE_DELAY_US);

	if (serial_has_receive_data(serial) == 0) {
		sr_dbg("Didn't get any ID reply.");
		return NULL;
	}

	num_read = serial_read_blocking(serial, buf, 4, serial_timeout(serial, 4));
	if (num_read < 0) {
		sr_err("Getting ID reply failed (%d).", num_read);
		return NULL;
	}

	if (strncmp(buf, "1SLO", 4) && strncmp(buf, "1ALS", 4)) {
		GString *id = sr_hexdump_new((uint8_t *)buf, num_read);

		sr_err("Invalid ID reply (got %s).", id->str);

		sr_hexdump_free(id);
		return NULL;
	}

	sols_send_shortcommand(serial, CMD_METADATA);

	g_usleep(RESPONSE_DELAY_US);

	if (serial_has_receive_data(serial) != 0) {
		/* Got metadata. */
		sdi = sols_get_metadata(serial);
	} else {
      sr_dbg("Didn't get any metadata reply.");
      return NULL;
	}
	/* Configure samplerate and divider. */
	if (sols_set_samplerate(sdi, DEFAULT_SAMPLERATE) != SR_OK)
		sr_dbg("Failed to set default samplerate (%"PRIu64").",
				DEFAULT_SAMPLERATE);
	sdi->inst_type = SR_INST_SERIAL;
	sdi->conn = serial;

	serial_close(serial);

	return std_scan_complete(di, g_slist_append(NULL, sdi));
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;

	(void)cg;

	if (!sdi)
		return SR_ERR_ARG;

	devc = sdi->priv;

	switch (key) {
	case SR_CONF_SAMPLERATE:
		*data = g_variant_new_uint64(devc->cur_samplerate);
		break;
	case SR_CONF_CAPTURE_RATIO:
		*data = g_variant_new_uint64(devc->capture_ratio);
		break;
	case SR_CONF_LIMIT_SAMPLES:
		*data = g_variant_new_uint64(devc->limit_samples);
		break;
	case SR_CONF_RLE:
		*data = g_variant_new_boolean(devc->capture_flags & CAPTURE_FLAG_RLE ? TRUE : FALSE);
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;
	uint64_t tmp_u64;

	(void)cg;

	devc = sdi->priv;

	switch (key) {
	case SR_CONF_SAMPLERATE:
		tmp_u64 = g_variant_get_uint64(data);
		if (tmp_u64 < samplerates[0] || tmp_u64 > samplerates[1])
			return SR_ERR_SAMPLERATE;
		return sols_set_samplerate(sdi, g_variant_get_uint64(data));
	case SR_CONF_LIMIT_SAMPLES:
		tmp_u64 = g_variant_get_uint64(data);
		if (tmp_u64 < MIN_NUM_SAMPLES)
			return SR_ERR;
		devc->limit_samples = tmp_u64;
		break;
	case SR_CONF_CAPTURE_RATIO:
		devc->capture_ratio = g_variant_get_uint64(data);
		break;
	case SR_CONF_EXTERNAL_CLOCK:
		if (g_variant_get_boolean(data)) {
			sr_info("Enabling external clock.");
			devc->capture_flags |= CAPTURE_FLAG_CLOCK_EXTERNAL;
		} else {
			sr_info("Disabled external clock.");
			devc->capture_flags &= ~CAPTURE_FLAG_CLOCK_EXTERNAL;
		}
		break;
	case SR_CONF_RLE:
		if (g_variant_get_boolean(data)) {
			sr_info("Enabling RLE.");
			devc->capture_flags |= CAPTURE_FLAG_RLE;
		} else {
			sr_info("Disabling RLE.");
			devc->capture_flags &= ~CAPTURE_FLAG_RLE;
		}
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;
	int num_sols_changrp, i;

	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
	case SR_CONF_SAMPLERATE:
		*data = std_gvar_samplerates_steps(ARRAY_AND_SIZE(samplerates));
		break;
	case SR_CONF_TRIGGER_MATCH:
		*data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
		break;
	case SR_CONF_LIMIT_SAMPLES:
		if (!sdi)
			return SR_ERR_ARG;
		devc = sdi->priv;
		if (devc->capture_flags & CAPTURE_FLAG_RLE)
			return SR_ERR_NA;
		if (devc->max_samples == 0)
			/* Device didn't specify sample memory size in metadata. */
			return SR_ERR_NA;
		/*
		 * Channel groups are turned off if no channels in that group are
		 * enabled, making more room for samples for the enabled group.
		*/
		sols_channel_mask(sdi);
		num_sols_changrp = 0;
		for (i = 0; i < 4; i++) {
			if (devc->channel_mask & (0xff << (i * 8)))
				num_sols_changrp++;
		}

		*data = std_gvar_tuple_u64(MIN_NUM_SAMPLES,
			(num_sols_changrp) ? devc->max_samples / num_sols_changrp : MIN_NUM_SAMPLES);
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int set_basic_trigger(const struct sr_dev_inst *sdi, int stage)
{
	struct dev_context *devc;
	struct sr_serial_dev_inst *serial;
	uint8_t cmd, arg[4];

	devc = sdi->priv;
	serial = sdi->conn;

	cmd = CMD_SET_BASIC_TRIGGER_MASK0 + stage * 4;
	arg[0] = devc->trigger_mask[stage] & 0xff;
	arg[1] = (devc->trigger_mask[stage] >> 8) & 0xff;
	arg[2] = (devc->trigger_mask[stage] >> 16) & 0xff;
	arg[3] = (devc->trigger_mask[stage] >> 24) & 0xff;
	if (sols_send_longcommand(serial, cmd, arg) != SR_OK)
		return SR_ERR;

	cmd = CMD_SET_BASIC_TRIGGER_VALUE0 + stage * 4;
	arg[0] = devc->trigger_value[stage] & 0xff;
	arg[1] = (devc->trigger_value[stage] >> 8) & 0xff;
	arg[2] = (devc->trigger_value[stage] >> 16) & 0xff;
	arg[3] = (devc->trigger_value[stage] >> 24) & 0xff;
	if (sols_send_longcommand(serial, cmd, arg) != SR_OK)
		return SR_ERR;

	cmd = CMD_SET_BASIC_TRIGGER_CONFIG0 + stage * 4;
	arg[0] = arg[1] = arg[3] = 0x00;
	arg[2] = stage;
	if (stage == devc->num_stages)
		/* Last stage, fire when this one matches. */
		arg[3] |= TRIGGER_START;
	if (sols_send_longcommand(serial, cmd, arg) != SR_OK)
		return SR_ERR;

	return SR_OK;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_serial_dev_inst *serial;
	uint32_t samplecount, readcount, delaycount;
	uint8_t sols_changrp_mask, arg[4];
	int num_sols_changrp;
	int ret, i;

	devc = sdi->priv;
	serial = sdi->conn;

	sols_channel_mask(sdi);

	num_sols_changrp = 0;
	sols_changrp_mask = 0;
	for (i = 0; i < 4; i++) {
		if (devc->channel_mask & (0xff << (i * 8))) {
			sols_changrp_mask |= (1 << i);
			num_sols_changrp++;
		}
	}

	/*
	 * Limit readcount to prevent reading past the end of the hardware
	 * buffer. Rather read too many samples than too few.
	 */
	samplecount = MIN(devc->max_samples / num_sols_changrp, devc->limit_samples);
	readcount = (samplecount + 3) / 4;

	/* Basic triggers. */
	if (sols_convert_trigger(sdi) != SR_OK) {
		sr_err("Failed to configure channels.");
		return SR_ERR;
	}
	if (devc->num_stages > 0) {
		/*
		 * According to http://mygizmos.org/sols/Logic-Sniffer-FPGA-Spec.pdf
		 * reset command must be send prior each arm command
		 */
		sr_dbg("Send reset command before trigger configure");
		if (sols_send_reset(serial) != SR_OK)
			return SR_ERR;

		delaycount = readcount * (1 - devc->capture_ratio / 100.0);
		devc->trigger_at_smpl = (readcount - delaycount) * 4 - devc->num_stages;
		for (i = 0; i <= devc->num_stages; i++) {
			sr_dbg("Setting sols stage %d trigger.", i);
			if ((ret = set_basic_trigger(sdi, i)) != SR_OK)
				return ret;
		}
	} else {
		/* No triggers configured, force trigger on first stage. */
		sr_dbg("Forcing trigger at stage 0.");
		if ((ret = set_basic_trigger(sdi, 0)) != SR_OK)
			return ret;
		delaycount = readcount;
	}

	/* Samplerate. */
	sr_dbg("Setting samplerate to %" PRIu64 "Hz (divider %u)",
			devc->cur_samplerate, devc->cur_samplerate_divider);
	arg[0] = devc->cur_samplerate_divider & 0xff;
	arg[1] = (devc->cur_samplerate_divider & 0xff00) >> 8;
	arg[2] = (devc->cur_samplerate_divider & 0xff0000) >> 16;
	arg[3] = 0x00;
	if (sols_send_longcommand(serial, CMD_SET_DIVIDER, arg) != SR_OK)
		return SR_ERR;

	/* Send sample limit and pre/post-trigger capture ratio. */
	sr_dbg("Setting sample limit %d, trigger point at %d",
			(readcount - 1) * 4, (delaycount - 1) * 4);

	if (devc->max_samples > 256 * 1024) {
		arg[0] = ((readcount - 1) & 0xff);
		arg[1] = ((readcount - 1) & 0xff00) >> 8;
		arg[2] = ((readcount - 1) & 0xff0000) >> 16;
		arg[3] = ((readcount - 1) & 0xff000000) >> 24;
		if (sols_send_longcommand(serial, CMD_CAPTURE_READCOUNT, arg) != SR_OK)
			return SR_ERR;
		arg[0] = ((delaycount - 1) & 0xff);
		arg[1] = ((delaycount - 1) & 0xff00) >> 8;
		arg[2] = ((delaycount - 1) & 0xff0000) >> 16;
		arg[3] = ((delaycount - 1) & 0xff000000) >> 24;
		if (sols_send_longcommand(serial, CMD_CAPTURE_DELAYCOUNT, arg) != SR_OK)
			return SR_ERR;
	} else {
		arg[0] = ((readcount - 1) & 0xff);
		arg[1] = ((readcount - 1) & 0xff00) >> 8;
		arg[2] = ((delaycount - 1) & 0xff);
		arg[3] = ((delaycount - 1) & 0xff00) >> 8;
		if (sols_send_longcommand(serial, CMD_CAPTURE_SIZE, arg) != SR_OK)
			return SR_ERR;
	}

	/* Flag register. */
	sr_dbg("Setting RLE %s",
			devc->capture_flags & CAPTURE_FLAG_RLE ? "on" : "off");
	/*
	 * Enable/disable sols channel groups in the flag register according
	 * to the channel mask. 1 means "disable channel".
	 */
	devc->capture_flags |= ~(sols_changrp_mask << 2) & 0x3c;

	/* RLE mode is always zero, for now. */

	arg[0] = devc->capture_flags & 0xff;
	arg[1] = devc->capture_flags >> 8;
	arg[2] = arg[3] = 0x00;
	if (sols_send_longcommand(serial, CMD_SET_FLAGS, arg) != SR_OK)
		return SR_ERR;

	/* Start acquisition on the device. */
	if (sols_send_shortcommand(serial, CMD_ARM_BASIC_TRIGGER) != SR_OK)
		return SR_ERR;

	/* Reset all operational states. */
	devc->rle_count = devc->num_transfers = 0;
	devc->num_samples = devc->num_bytes = 0;
	devc->cnt_bytes = devc->cnt_samples = devc->cnt_samples_rle = 0;
	memset(devc->sample, 0, 4);

	std_session_send_df_header(sdi);

	/* If the device stops sending for longer than it takes to send a byte,
	 * that means it's finished. But wait at least 100 ms to be safe.
	 */
	serial_source_add(sdi->session, serial, G_IO_IN, 100,
			sols_receive_data, (struct sr_dev_inst *)sdi);

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	sols_abort_acquisition(sdi);

	return SR_OK;
}

static struct sr_dev_driver sola_driver_info = {
	.name = "sola",
	.longname = "small open logic analyzer",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = std_serial_dev_open,
	.dev_close = std_serial_dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(sola_driver_info);
