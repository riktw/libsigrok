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

#ifndef LIBSIGROK_HARDWARE_SOLA_PROTOCOL_H
#define LIBSIGROK_HARDWARE_SOLA_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "sola"

#define NUM_TRIGGER_STAGES         1
#define CLOCK_RATE                 SR_MHZ(100)
#define MIN_NUM_SAMPLES            4
#define DEFAULT_SAMPLERATE         SR_KHZ(200)

/* Command opcodes */
#define CMD_RESET                     0x00
#define CMD_ARM_BASIC_TRIGGER         0x01
#define CMD_ID                        0x02
#define CMD_METADATA                  0x04
#define CMD_FINISH_NOW                0x05 
#define CMD_XON                       0x11
#define CMD_XOFF                      0x13
#define CMD_SET_DIVIDER               0x80
#define CMD_CAPTURE_SIZE              0x81
#define CMD_SET_FLAGS                 0x82
#define CMD_CAPTURE_DELAYCOUNT        0x83 /* extension of Pepino */
#define CMD_CAPTURE_READCOUNT         0x84 /* extension of Pepino */
#define CMD_SET_BASIC_TRIGGER_MASK0   0xC0 
#define CMD_SET_BASIC_TRIGGER_VALUE0  0xC1
#define CMD_SET_BASIC_TRIGGER_CONFIG0 0xC2

/* Metadata tokens */
#define METADATA_TOKEN_END                    0x0
#define METADATA_TOKEN_DEVICE_NAME            0x1
#define METADATA_TOKEN_FPGA_VERSION           0x2
#define METADATA_TOKEN_NUM_PROBES_LONG        0x20
#define METADATA_TOKEN_SAMPLE_MEMORY_BYTES    0x21
#define METADATA_TOKEN_MAX_SAMPLE_RATE_HZ     0x23
#define METADATA_TOKEN_PROTOCOL_VERSION_LONG  0x24
#define METADATA_TOKEN_NUM_PROBES_SHORT       0x40
#define METADATA_TOKEN_PROTOCOL_VERSION_SHORT 0x41

/* Basic Trigger Config */
#define TRIGGER_START              (1 << 3)

/* Bit mask used for "set flags" command (0x82) */
/* Take care about bit positions in diagrams, they are inverted. */
#define CAPTURE_FLAG_RLE                 (1 << 8)
#define CAPTURE_FLAG_CLOCK_EXTERNAL      (1 << 6)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_4 (1 << 5)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_3 (1 << 4)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_2 (1 << 3)
#define CAPTURE_FLAG_DISABLE_CHANGROUP_1 (1 << 2)

/* Capture context magic numbers */
#define OLS_NO_TRIGGER (-1)

struct dev_context {
	/* constant device properties: */
	int max_channels;
	uint32_t max_samples;
	uint32_t max_samplerate;
	uint32_t protocol_version;
	uint16_t device_flags;

	/* acquisition-related properties: */
	uint64_t cur_samplerate;
	uint32_t cur_samplerate_divider;
	uint64_t limit_samples;
	uint64_t capture_ratio;
	int trigger_at_smpl;
	uint32_t channel_mask[16];     //32 pits per mask, 16, max of 512 channels seems decent.
	uint32_t trigger_mask[16];     
	uint32_t trigger_value[16];
	int num_stages;
	uint16_t capture_flags;

	unsigned int num_transfers;
	unsigned int num_samples;
	int num_bytes;
	int cnt_bytes;
	int cnt_samples;
	int cnt_samples_rle;

	unsigned int rle_count;
	unsigned char sample[64];    //8 bit per sample, 64 max for 512 channels. 
	unsigned char tmp_sample[64];
	unsigned char *raw_sample_buf;
};

SR_PRIV extern const char *ols_channel_names[];

SR_PRIV int sols_send_shortcommand(struct sr_serial_dev_inst *serial, uint8_t command);
SR_PRIV int sols_send_longcommand(struct sr_serial_dev_inst *serial, uint8_t command, uint8_t *data, uint8_t dataSize);
SR_PRIV int sols_send_reset(struct sr_serial_dev_inst *serial);
SR_PRIV void sols_channel_mask(const struct sr_dev_inst *sdi);
SR_PRIV int sols_convert_trigger(const struct sr_dev_inst *sdi);
SR_PRIV struct dev_context *sols_dev_new(void);
SR_PRIV struct sr_dev_inst *sols_get_metadata(struct sr_serial_dev_inst *serial);
SR_PRIV int sols_set_samplerate(const struct sr_dev_inst *sdi, uint64_t samplerate);
SR_PRIV void sols_abort_acquisition(const struct sr_dev_inst *sdi);
SR_PRIV int sols_receive_data(int fd, int revents, void *cb_data);

#endif
