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

SR_PRIV int sols_send_shortcommand(struct sr_serial_dev_inst *serial, uint8_t command)
{
	char buf[1];

	sr_dbg("Sending cmd 0x%.2x.", command);
	buf[0] = command;
	if (serial_write_blocking(serial, buf, 1, serial_timeout(serial, 1)) != 1)
		return SR_ERR;

	if (serial_drain(serial) != SR_OK)
		return SR_ERR;

	return SR_OK;
}

SR_PRIV int sols_send_longcommand(struct sr_serial_dev_inst *serial, uint8_t command, uint8_t *data, uint8_t dataSize)
{
	char buf[dataSize+1];

	sr_dbg("Sending cmd 0x%.2x data 0x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x.", command,
			data[4], data[5], data[6], data[7], data[0], data[1], data[2], data[3]);
	buf[0] = command;
    memcpy(&buf[1], data, dataSize);
	if (serial_write_blocking(serial, buf, dataSize+1, serial_timeout(serial, 1)) != dataSize+1)
		return SR_ERR;

	if (serial_drain(serial) != SR_OK)
		return SR_ERR;

	return SR_OK;
}

SR_PRIV int sols_send_reset(struct sr_serial_dev_inst *serial)
{
	unsigned int i;

	for (i = 0; i < 5; i++) {
		if (sols_send_shortcommand(serial, CMD_RESET) != SR_OK)
			return SR_ERR;
	}

	return SR_OK;
}

/* Configures the channel mask based on which channels are enabled. */
SR_PRIV void sols_channel_mask(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_channel *channel;
	const GSList *l;

	devc = sdi->priv;
    
    for(int i = 0; i < 16; ++i)
    {
      devc->channel_mask[i] = 0;
    }
    
	for (l = sdi->channels; l; l = l->next) {
		channel = l->data;
        uint8_t triggerWord = channel->index / 32;
		if (channel->enabled)
			devc->channel_mask[triggerWord] |= 1 << (channel->index - (32 * triggerWord));
	}
}

SR_PRIV int sols_convert_trigger(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_trigger *trigger;
	struct sr_trigger_stage *stage;
	struct sr_trigger_match *match;
	const GSList *l, *m;
	int i;

	devc = sdi->priv;

	devc->num_stages = 0;
	for (i = 0; i < 16; i++) {
		devc->trigger_mask[i] = 0;
		devc->trigger_value[i] = 0;
	}

	if (!(trigger = sr_session_trigger_get(sdi->session)))
		return SR_OK;

	devc->num_stages = g_slist_length(trigger->stages);
	if (devc->num_stages > NUM_TRIGGER_STAGES) {
		sr_err("This device only supports %d trigger stages.",
				NUM_TRIGGER_STAGES);
		return SR_ERR;
	}

	for (l = trigger->stages; l; l = l->next) {
		stage = l->data;
		for (m = stage->matches; m; m = m->next) {
			match = m->data;
			if (!match->channel->enabled)
				/* Ignore disabled channels with a trigger. */
 				continue;
            uint8_t triggerWord = match->channel->index / 32;
            sr_dbg("trig on channel %i to trigword %i", match->channel->index, triggerWord);
			devc->trigger_mask[triggerWord] |= 1 << (match->channel->index - (32 * triggerWord));
			if (match->match == SR_TRIGGER_ONE)
				devc->trigger_value[triggerWord] |= 1 << (match->channel->index - (32 * triggerWord));
		}
	}

	return SR_OK;
}

SR_PRIV struct dev_context *sols_dev_new(void)
{
	struct dev_context *devc;

	devc = g_malloc0(sizeof(struct dev_context));
	devc->trigger_at_smpl = OLS_NO_TRIGGER;

	return devc;
}

static void sols_channel_new(struct sr_dev_inst *sdi, int num_chan)
{
	struct dev_context *devc = sdi->priv;
	int i;

	for (i = 0; i < num_chan; i++) {
		char channel_name[10];
		sprintf(channel_name, "%d", i);
		sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE, channel_name);
    }

	devc->max_channels = num_chan;
}

SR_PRIV struct sr_dev_inst *sols_get_metadata(struct sr_serial_dev_inst *serial)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	uint32_t tmp_int;
	uint8_t key, type;
	int delay_ms;
	GString *tmp_str, *devname, *version;
	guchar tmp_c;

	sdi = g_malloc0(sizeof(struct sr_dev_inst));
	sdi->status = SR_ST_INACTIVE;
	devc = sols_dev_new();
	sdi->priv = devc;

	devname = g_string_new("");
	version = g_string_new("");

	key = 0xff;
	while (key) {
		delay_ms = serial_timeout(serial, 1);
		if (serial_read_blocking(serial, &key, 1, delay_ms) != 1)
			break;
		if (key == METADATA_TOKEN_END) {
			sr_dbg("Got metadata key 0x00, metadata ends.");
			break;
		}
		type = key >> 5;
		switch (type) {
		case 0:
			/* NULL-terminated string */
			tmp_str = g_string_new("");
			delay_ms = serial_timeout(serial, 1);
			while (serial_read_blocking(serial, &tmp_c, 1, delay_ms) == 1 && tmp_c != '\0')
				g_string_append_c(tmp_str, tmp_c);
			sr_dbg("Got metadata token 0x%.2x value '%s'.", key, tmp_str->str);
			switch (key) {
			case METADATA_TOKEN_DEVICE_NAME:
				/* Device name */
				devname = g_string_append(devname, tmp_str->str);
				break;
			case METADATA_TOKEN_FPGA_VERSION:
				/* FPGA firmware version */
				if (version->len)
					g_string_append(version, ", ");
				g_string_append(version, "FPGA version ");
				g_string_append(version, tmp_str->str);
				break;
			default:
				sr_info("ols: unknown token 0x%.2x: '%s'", key, tmp_str->str);
				break;
			}
			g_string_free(tmp_str, TRUE);
			break;
		case 1:
			/* 32-bit unsigned integer */
			delay_ms = serial_timeout(serial, 4);
			if (serial_read_blocking(serial, &tmp_int, 4, delay_ms) != 4)
				break;
			tmp_int = RB32(&tmp_int);
			sr_dbg("Got metadata token 0x%.2x value 0x%.8x.", key, tmp_int);
			switch (key) {
			case METADATA_TOKEN_NUM_PROBES_LONG:
				/* Number of usable channels */
				sols_channel_new(sdi, tmp_int);
				break;
			case METADATA_TOKEN_SAMPLE_MEMORY_BYTES:
				/* Amount of sample memory available (bytes) */
				devc->max_samples = tmp_int;
				break;
			case METADATA_TOKEN_MAX_SAMPLE_RATE_HZ:
				/* Maximum sample rate (Hz) */
				devc->max_samplerate = tmp_int;
				break;
			case METADATA_TOKEN_PROTOCOL_VERSION_LONG:
				/* protocol version */
				devc->protocol_version = tmp_int;
				break;
			default:
				sr_info("Unknown token 0x%.2x: 0x%.8x.", key, tmp_int);
				break;
			}
			break;
		case 2:
			/* 8-bit unsigned integer */
			delay_ms = serial_timeout(serial, 1);
			if (serial_read_blocking(serial, &tmp_c, 1, delay_ms) != 1)
				break;
			sr_dbg("Got metadata token 0x%.2x value 0x%.2x.", key, tmp_c);
			switch (key) {
			case METADATA_TOKEN_NUM_PROBES_SHORT:
				/* Number of usable channels */
				sols_channel_new(sdi, tmp_c);
				break;
			case METADATA_TOKEN_PROTOCOL_VERSION_SHORT:
				/* protocol version */
				devc->protocol_version = tmp_c;
				break;
			default:
				sr_info("Unknown token 0x%.2x: 0x%.2x.", key, tmp_c);
				break;
			}
			break;
		default:
			/* unknown type */
			break;
		}
	}

	sdi->model = devname->str;
	sdi->version = version->str;
	g_string_free(devname, FALSE);
	g_string_free(version, FALSE);

	return sdi;
}

SR_PRIV int sols_set_samplerate(const struct sr_dev_inst *sdi, const uint64_t samplerate)
{
	struct dev_context *devc;

	devc = sdi->priv;
	if (devc->max_samplerate && samplerate > devc->max_samplerate)
		return SR_ERR_SAMPLERATE;

    devc->cur_samplerate_divider = (CLOCK_RATE / samplerate) - 1;
	/* Calculate actual samplerate used and complain if it is different
	 * from the requested.
	 */
	devc->cur_samplerate = CLOCK_RATE / (devc->cur_samplerate_divider + 1);
	if (devc->cur_samplerate != samplerate)
		sr_info("Can't match samplerate %" PRIu64 ", using %"
		       PRIu64 ".", samplerate, devc->cur_samplerate);

	return SR_OK;
}

SR_PRIV void sols_abort_acquisition(const struct sr_dev_inst *sdi)
{
	struct sr_serial_dev_inst *serial;

	serial = sdi->conn;
	serial_source_remove(sdi->session, serial);

	std_session_send_df_end(sdi);
}

SR_PRIV int sols_receive_data(int fd, int revents, void *cb_data)
{
	struct dev_context *devc;
	struct sr_dev_inst *sdi;
	struct sr_serial_dev_inst *serial;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_logic logic;
	
    int bytesPerSample;
	int num_ols_changrp, offset, j;
	unsigned int i;
	unsigned char byte;
    uint8_t sols_changrp_mask[16];

	(void)fd;

	sdi = cb_data;
	serial = sdi->conn;
	devc = sdi->priv;
    uint32_t sample[devc->max_channels/32];
    bytesPerSample = (devc->max_channels / 8);
    num_ols_changrp = 0;
    for (int n = 0; n < devc->max_channels/32; ++n)
    {
      sols_changrp_mask[n] = 0;
      for (i = 0; i < 4; i++) {
          if (devc->channel_mask[n] & (0xff << (i * 8))) {
              sols_changrp_mask[n] |= (1 << i);
              num_ols_changrp++;
          }
      }
    }
    sr_dbg("num_ols_changrp: %i, bytesPerSample: %i", num_ols_changrp, bytesPerSample);

	if (devc->num_transfers == 0 && revents == 0) {
		/* Ignore timeouts as long as we haven't received anything */
		return TRUE;
	}

	if (devc->num_transfers++ == 0) {
		devc->raw_sample_buf = g_try_malloc(devc->limit_samples * bytesPerSample);
		if (!devc->raw_sample_buf) {
			sr_err("Sample buffer malloc failed.");
			return FALSE;
		}
		/* fill with 1010... for debugging */
		memset(devc->raw_sample_buf, 0x82, devc->limit_samples * bytesPerSample);
	}


	if (revents == G_IO_IN && devc->num_samples < devc->limit_samples) {
		if (serial_read_nonblocking(serial, &byte, 1) != 1)
			return FALSE;
		devc->cnt_bytes++;

		/* Ignore it if we've read enough. */
		if (devc->num_samples >= devc->limit_samples)
			return TRUE;

		devc->sample[devc->num_bytes++] = byte;
		sr_spew("Received byte 0x%.2x.", byte);
		if (devc->num_bytes == num_ols_changrp) {
			devc->cnt_samples++;
			devc->cnt_samples_rle++;
			/*
			 * Got a full sample. Convert from the OLS's little-endian
			 * sample to the local format.
			 */
            for(int n = 0; n < (devc->max_channels/32); ++n) 
            {
              sample[n] = devc->sample[0+(n*4)] | (devc->sample[1+(n*4)] << 8) \
					| (devc->sample[2+(n*4)] << 16) | (devc->sample[3+(n*4)] << 24) ;
              sr_dbg("Received sample 0x%.*x.", 4 * 2, sample[n]);
            }
			
			
			if (devc->capture_flags & CAPTURE_FLAG_RLE) {
				/*
				 * In RLE mode the high bit of the sample is the
				 * "count" flag, meaning this sample is the number
				 * of times the previous sample occurred.
				 */
				if (devc->sample[devc->num_bytes - 1] & 0x80) {
					/* Clear the high bit. */
					//sample &= ~(0x80 << (devc->num_bytes - 1) * 8);
					//devc->rle_count = sample;
					devc->cnt_samples_rle += devc->rle_count;
					sr_dbg("RLE count: %u.", devc->rle_count);
					devc->num_bytes = 0;
					return TRUE;
				}
			}
			devc->num_samples += devc->rle_count + 1;
			if (devc->num_samples > devc->limit_samples) {
				/* Save us from overrunning the buffer. */
				devc->rle_count -= devc->num_samples - devc->limit_samples;
				devc->num_samples = devc->limit_samples;
			}

			if (num_ols_changrp < bytesPerSample) {
				/*
				 * Some channel groups may have been turned
				 * off, to speed up transfer between the
				 * hardware and the PC. Expand that here before
				 * submitting it over the session bus --
				 * whatever is listening on the bus will be
				 * expecting a full 32-bit sample, based on
				 * the number of channels.
				 */
				j = 0;
				memset(devc->tmp_sample, 0, bytesPerSample);
                for (int n = 0; n < devc->max_channels/32; ++n) 
                {
                  for (i = 0; i < 4; i++) {
                      if (devc->channel_mask[n] & (0xff << (i * 8))) {
                          /*
                          * This channel group was
                          * enabled, copy from received
                          * sample.
                          */
                          devc->tmp_sample[(n*4)+i] = devc->sample[j++];
                      }
                  }
                }
				memcpy(devc->sample, devc->tmp_sample, bytesPerSample);
				//sr_spew("Expanded sample: 0x%.8x.", sample);
			}

			/*
			 * the OLS sends its sample buffer backwards.
			 * store it in reverse order here, so we can dump
			 * this on the session bus later.
			 */
			offset = (devc->limit_samples - devc->num_samples) * bytesPerSample;
			for (i = 0; i <= devc->rle_count; i++) {
				memcpy(devc->raw_sample_buf + offset + (i * bytesPerSample),
				       devc->sample, bytesPerSample);
			}
			memset(devc->sample, 0, bytesPerSample);
			devc->num_bytes = 0;
			devc->rle_count = 0;
		}
	} else {
		/*
		 * This is the main loop telling us a timeout was reached, or
		 * we've acquired all the samples we asked for -- we're done.
		 * Send the (properly-ordered) buffer to the frontend.
		 */
		sr_dbg("Received %d bytes, %d samples, %d decompressed samples.",
				devc->cnt_bytes, devc->cnt_samples,
				devc->cnt_samples_rle);
		if (devc->trigger_at_smpl != OLS_NO_TRIGGER) {
			/*
			 * A trigger was set up, so we need to tell the frontend
			 * about it.
			 */
			if (devc->trigger_at_smpl > 0) {
				/* There are pre-trigger samples, send those first. */
				packet.type = SR_DF_LOGIC;
				packet.payload = &logic;
				logic.length = devc->trigger_at_smpl * bytesPerSample;
				logic.unitsize = bytesPerSample;
				logic.data = devc->raw_sample_buf +
					(devc->limit_samples - devc->num_samples) * bytesPerSample;
				sr_session_send(sdi, &packet);
			}

			/* Send the trigger. */
			std_session_send_df_trigger(sdi);
		}

		/* Send post-trigger / all captured samples. */
		int num_pre_trigger_samples = devc->trigger_at_smpl == OLS_NO_TRIGGER
			? 0 : devc->trigger_at_smpl;
		packet.type = SR_DF_LOGIC;
		packet.payload = &logic;
		logic.length = (devc->num_samples - num_pre_trigger_samples) * bytesPerSample;
		logic.unitsize = bytesPerSample;
		logic.data = devc->raw_sample_buf + (num_pre_trigger_samples +
			devc->limit_samples - devc->num_samples) * bytesPerSample;
		sr_session_send(sdi, &packet);

		g_free(devc->raw_sample_buf);

		serial_flush(serial);
		sols_abort_acquisition(sdi);
	}

	return TRUE;
}
