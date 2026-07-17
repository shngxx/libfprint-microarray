/*
 * MicroarrayTechnology MAFP fingerprint reader driver for libfprint
 * USB ID: 3274:8012
 *
 * Protocol reverse-engineered from MicroarrayFingerprintDevice.dll v9.47.11.214
 * using Ghidra 12.0.4. The device uses the FPC/GROW-family bulk transfer
 * protocol (same packet framing as the R30X hobbyist module series).
 *
 * Endpoints:
 * EP 0x03  OUT bulk  — commands to device
 * EP 0x83  IN  bulk  — responses from device
 * EP 0x82  IN  intr  — finger-detect events (used for waiting)
 *
 * Copyright (C) 2024  <jason@localhost>
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "microarray"

#include "drivers_api.h"

/* --------------------------------------------------------------------------
 * Protocol constants
 * -------------------------------------------------------------------------- */

/* Packet framing */
#define MA_EP_OUT           0x03
#define MA_EP_IN            0x83
#define MA_EP_INTR          0x82
#define MA_HDR_LEN          6       /* EF 01 FF FF FF FF */
#define MA_OVERHEAD         9       /* header + type(1) + length(2) */
#define MA_PKT_CMD          0x01
#define MA_PKT_ACK          0x07
#define MA_TIMEOUT_CMD      5000    /* ms */
#define MA_TIMEOUT_INTR     0       /* 0 = wait forever for finger */

/* FPC command opcodes (first byte of command payload) */
#define MA_CMD_GET_IMAGE    0x01    /* capture image; resp[0]=0 on success  */
#define MA_CMD_GEN_CHAR     0x02    /* extract features into char-buf slot  */
#define MA_CMD_REG_MODEL    0x05    /* merge char-bufs into template        */
#define MA_CMD_STORE_CHAR   0x06    /* save template to FID slot            */
#define MA_CMD_EMPTY        0x0D    /* erase ALL stored templates           */
#define MA_CMD_READ_INDEX   0x1F    /* bitmap of enrolled FID slots         */
#define MA_CMD_SEARCH       0x66    /* verify char-buf against FID          */
#define MA_CMD_DUP_CHECK    0x6F    /* duplicate-finger check               */

/* Enrolment requires this many successful captures before RegModel */
#define MA_ENROLL_SAMPLES   6

/* Device flash FID slots are 0-29 (StoreChar returns 0x18 out of range) */
#define MA_MAX_FID          29

/* Response buffer: max response is ReadIndex = 35 bytes payload + overhead */
#define MA_RESP_PAYLOAD_MAX 35
#define MA_RESP_BUF         (MA_OVERHEAD + MA_RESP_PAYLOAD_MAX + 2)

/* Handshake packet (raw, pre-framed, from Sensor::mfm_handshake) */
static const guint8 MA_HANDSHAKE_PKT[] = {
    0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01,           /* type = command */
    0x00, 0x02,     /* length = 2 */
    0x23,           /* instruction = handshake */
    0xA2            /* checksum */
};
#define MA_HANDSHAKE_PKT_LEN  G_N_ELEMENTS (MA_HANDSHAKE_PKT)
#define MA_HANDSHAKE_RESP_LEN 12

/* --------------------------------------------------------------------------
 * Device structure
 * -------------------------------------------------------------------------- */

struct _FpiDeviceMicroarray
{
  FpDevice       parent;
  FpiSsm        *task_ssm;
  gint           enroll_stage;
  gint           fid;              /* enrolled fingerprint ID slot */
  guint8        *resp_buf;         /* allocated response buffer    */
  gsize          resp_buf_size;
  gboolean       waiting_for_lift; /* TRUE after each successful capture */
  guint          identify_index;
  guint          poll_timeout_id;  /* g_timeout_add source during enroll */
};

G_DECLARE_FINAL_TYPE (FpiDeviceMicroarray, fpi_device_microarray,
                      FPI, DEVICE_MICROARRAY, FpDevice)
G_DEFINE_TYPE (FpiDeviceMicroarray, fpi_device_microarray, FP_TYPE_DEVICE)

/* --------------------------------------------------------------------------
 * Packet helpers
 * -------------------------------------------------------------------------- */

static guint8 *
ma_build_cmd (const guint8 *cmd, gsize cmd_len, gsize *out_len)
{
    gsize total = MA_OVERHEAD + cmd_len + 2; /* 2 checksum bytes */
    guint8 *pkt = g_malloc (total);

    pkt[0] = 0xEF; pkt[1] = 0x01; pkt[2] = 0xFF; pkt[3] = 0xFF; pkt[4] = 0xFF; pkt[5] = 0xFF;
    pkt[6] = MA_PKT_CMD;

    guint16 len = (guint16)(cmd_len + 2);
    pkt[7] = (guint8)(len >> 8);
    pkt[8] = (guint8)(len & 0xFF);

    memcpy (pkt + 9, cmd, cmd_len);

    guint16 csum = 0;
    for (gsize i = 6; i < 9 + cmd_len; i++)
        csum += pkt[i];
    pkt[9 + cmd_len]     = (guint8)(csum >> 8);
    pkt[9 + cmd_len + 1] = (guint8)(csum & 0xFF);

    *out_len = total;
    return pkt;
}

static gboolean
ma_parse_resp (const guint8 *buf, gsize buf_len,
               const guint8 **data_out, gsize *data_len_out,
               GError **error)
{
    if (buf_len < (gsize)(MA_OVERHEAD + 2)) {
        g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "Response too short");
        return FALSE;
    }
    if (buf[0] != 0xEF || buf[1] != 0x01) {
        g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "Bad sync header");
        return FALSE;
    }
    if (buf[6] != MA_PKT_ACK) {
        g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                     "Expected ACK (0x07), got 0x%02x", buf[6]);
        return FALSE;
    }
    guint16 len  = ((guint16)buf[7] << 8) | buf[8];
    gsize expected = (gsize)MA_OVERHEAD + len;
    if (len < 2 || buf_len < expected) {
        g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "Response truncated");
        return FALSE;
    }
    guint16 csum = 0;
    for (gsize i = 6; i < expected - 2; i++)
        csum += buf[i];
    guint16 got = ((guint16)buf[expected - 2] << 8) | buf[expected - 1];
    if (csum != got) {
        g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "Checksum mismatch");
        return FALSE;
    }
    if (data_out)
        *data_out = buf + MA_OVERHEAD;
    if (data_len_out)
        *data_len_out = (gsize)(len - 2);
    return TRUE;
}

/* Extract FID from enrolled print metadata. Defaults must never silently become 0. */
static gboolean
ma_print_get_fid (FpPrint *print, gint *fid_out, GError **error)
{
    g_autoptr(GVariant) data = NULL;
    gint fid = -1;

    if (!print) {
        g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                             "Missing print");
        return FALSE;
    }

    g_object_get (print, "fpi-data", &data, NULL);
    if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(i)"))) {
        g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                             "Print is missing valid FID metadata");
        return FALSE;
    }

    g_variant_get (data, "(i)", &fid);
    if (fid < 0 || fid > MA_MAX_FID) {
        g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                     "FID %d out of range (0-%d)", fid, MA_MAX_FID);
        return FALSE;
    }

    *fid_out = fid;
    return TRUE;
}

static void
ma_cancel_poll_timeout (FpiDeviceMicroarray *self)
{
    if (self->poll_timeout_id != 0) {
        g_source_remove (self->poll_timeout_id);
        self->poll_timeout_id = 0;
    }
}

/* --------------------------------------------------------------------------
 * Init state machine
 * -------------------------------------------------------------------------- */

enum {
    INIT_SEND_HANDSHAKE,
    INIT_RECV_HANDSHAKE,
    INIT_NUM_STATES,
};

static void
init_recv_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }
    if (transfer->actual_length >= 2 && transfer->buffer[0] == 0xEF && transfer->buffer[1] == 0x01) {
        fp_dbg ("Handshake OK");
        fpi_ssm_mark_completed (ssm);
    } else {
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Handshake response invalid"));
    }
}

static void
init_send_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }
    fpi_ssm_next_state (ssm);
}

static void
init_run_state (FpiSsm *ssm, FpDevice *device)
{
    FpiUsbTransfer *transfer;
    switch (fpi_ssm_get_cur_state (ssm)) {
    case INIT_SEND_HANDSHAKE: {
        guint8 *buf = g_memdup2 (MA_HANDSHAKE_PKT, MA_HANDSHAKE_PKT_LEN);
        transfer = fpi_usb_transfer_new (device);
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_bulk_full (transfer, MA_EP_OUT, buf, MA_HANDSHAKE_PKT_LEN, g_free);
        fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, fpi_device_get_cancellable (device), init_send_cb, ssm);
        break;
    }
    case INIT_RECV_HANDSHAKE:
        transfer = fpi_usb_transfer_new (device);
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_bulk (transfer, MA_EP_IN, MA_HANDSHAKE_RESP_LEN);
        fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, fpi_device_get_cancellable (device), init_recv_cb, ssm);
        break;
    default:
        g_assert_not_reached ();
    }
}

static void
init_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    fpi_device_open_complete (device, error);
}

static void
ma_dev_open (FpDevice *device)
{
    GError *error = NULL;
    if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device), 0, 0, &error)) {
        fpi_device_open_complete (device, error);
        return;
    }
    FpiSsm *ssm = fpi_ssm_new (device, init_run_state, INIT_NUM_STATES);
    fpi_ssm_start (ssm, init_ssm_done);
}

static void
ma_dev_close (FpDevice *device)
{
    GError *error = NULL;
    g_usb_device_release_interface (fpi_device_get_usb_device (device), 0, 0, &error);
    fpi_device_close_complete (device, error);
}

/* --------------------------------------------------------------------------
 * Generic command send/receive helpers
 * -------------------------------------------------------------------------- */

static void
cmd_recv_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    GError *parse_error = NULL;

    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }

    if (!ma_parse_resp (transfer->buffer, transfer->actual_length, NULL, NULL, &parse_error)) {
        fpi_ssm_mark_failed (ssm,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                      "%s", parse_error->message));
        g_clear_error (&parse_error);
        return;
    }

    fpi_ssm_next_state (ssm);
}

static void
handshake_recv_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;

    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }

    /* Handshake reply is 12 bytes; Windows driver validates further, we check framing. */
    if (transfer->actual_length < MA_HANDSHAKE_RESP_LEN ||
        transfer->buffer[0] != 0xEF || transfer->buffer[1] != 0x01) {
        fpi_ssm_mark_failed (ssm,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                      "Handshake response invalid"));
        return;
    }

    fpi_ssm_next_state (ssm);
}

static void
cmd_send_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }
    fpi_ssm_next_state (ssm);
}

static void
ma_submit_cmd (FpiSsm *ssm, FpDevice *device, const guint8 *cmd, gsize cmd_len)
{
    gsize pkt_len;
    guint8 *pkt = ma_build_cmd (cmd, cmd_len, &pkt_len);
    FpiUsbTransfer *transfer = fpi_usb_transfer_new (device);
    transfer->ssm = ssm;
    fpi_usb_transfer_fill_bulk_full (transfer, MA_EP_OUT, pkt, pkt_len, g_free);
    fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, fpi_device_get_cancellable (device), cmd_send_cb, ssm);
}

static void
ma_submit_recv (FpiSsm *ssm, FpDevice *device, gsize expect_len)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    FpiUsbTransfer *transfer;

    if (!self->resp_buf || expect_len > self->resp_buf_size) {
        fpi_ssm_mark_failed (ssm,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                      "Receive size %zu exceeds buffer %zu",
                                                      expect_len,
                                                      self->resp_buf ? self->resp_buf_size : 0));
        return;
    }

    memset (self->resp_buf, 0, self->resp_buf_size);
    transfer = fpi_usb_transfer_new (device);
    transfer->ssm = ssm;
    fpi_usb_transfer_fill_bulk_full (transfer, MA_EP_IN, self->resp_buf, expect_len, NULL);
    fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, fpi_device_get_cancellable (device), cmd_recv_cb, ssm);
}

/* --------------------------------------------------------------------------
 * Enroll state machine
 * -------------------------------------------------------------------------- */

enum {
    ENROLL_HANDSHAKE,
    ENROLL_RECV_HANDSHAKE,
    ENROLL_READ_INDEX_PRE,
    ENROLL_RECV_READ_INDEX_PRE,
    ENROLL_EMPTY,
    ENROLL_RECV_EMPTY,
    ENROLL_GET_IMAGE,
    ENROLL_RECV_IMAGE,
    ENROLL_GEN_CHAR,
    ENROLL_RECV_GEN_CHAR,
    ENROLL_REG_MODEL,
    ENROLL_RECV_REG_MODEL,
    ENROLL_STORE_CHAR,
    ENROLL_RECV_STORE_CHAR,
    ENROLL_NUM_STATES,
};

static gboolean
poll_get_image_cb (gpointer user_data)
{
    FpiDeviceMicroarray *self = user_data;

    self->poll_timeout_id = 0;
    if (self->task_ssm)
        fpi_ssm_jump_to_state (self->task_ssm, ENROLL_GET_IMAGE);
    return G_SOURCE_REMOVE;
}

static gint
ma_find_free_fid (const guint8 *resp, gsize resp_len)
{
    /* resp is payload after framing: [0]=status, [1..]=slot bitmap */
    if (resp_len < 5 || resp[0] != 0x00)
        return -1;

    for (int byte = 0; byte < 4; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            int candidate = byte * 8 + bit;
            if (candidate > MA_MAX_FID)
                return -1;
            if (!(resp[1 + byte] & (1 << bit)))
                return candidate;
        }
    }
    return -1;
}

static void
enroll_run_state (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    guint8 cmd[8];

    switch (fpi_ssm_get_cur_state (ssm)) {
    case ENROLL_HANDSHAKE: {
        guint8 *buf = g_memdup2 (MA_HANDSHAKE_PKT, MA_HANDSHAKE_PKT_LEN);
        FpiUsbTransfer *t = fpi_usb_transfer_new (device);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk_full (t, MA_EP_OUT, buf, MA_HANDSHAKE_PKT_LEN, g_free);
        fpi_usb_transfer_submit (t, MA_TIMEOUT_CMD, fpi_device_get_cancellable (device), cmd_send_cb, ssm);
        break;
    }
    case ENROLL_RECV_HANDSHAKE: {
        FpiUsbTransfer *t = fpi_usb_transfer_new (device);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk (t, MA_EP_IN, MA_HANDSHAKE_RESP_LEN);
        fpi_usb_transfer_submit (t, MA_TIMEOUT_CMD, fpi_device_get_cancellable (device),
                                 handshake_recv_cb, ssm);
        break;
    }
    case ENROLL_READ_INDEX_PRE:
        cmd[0] = MA_CMD_READ_INDEX; cmd[1] = 0x00;
        ma_submit_cmd (ssm, device, cmd, 2);
        break;
    case ENROLL_RECV_READ_INDEX_PRE:
        ma_submit_recv (ssm, device, MA_OVERHEAD + MA_RESP_PAYLOAD_MAX + 2);
        break;
    case ENROLL_EMPTY: {
        /* Misnamed historical state: pick a free FID. Never wipe all slots. */
        const guint8 *payload = NULL;
        gsize payload_len = 0;
        GError *error = NULL;

        if (!ma_parse_resp (self->resp_buf, self->resp_buf_size, &payload, &payload_len, &error)) {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "%s", error->message));
            g_clear_error (&error);
            return;
        }

        self->fid = ma_find_free_fid (payload, payload_len);
        if (self->fid >= 0) {
            fp_dbg ("Found free FID slot %d. Proceeding to image capture.", self->fid);
            fpi_ssm_jump_to_state (ssm, ENROLL_GET_IMAGE);
            return;
        }

        fp_dbg ("Storage slots 0-%d full; refusing enroll (will not Empty device).", MA_MAX_FID);
        fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL));
        return;
    }
    case ENROLL_RECV_EMPTY:
        /* Unreachable: Empty is no longer issued during enroll. */
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case ENROLL_GET_IMAGE:
        cmd[0] = MA_CMD_GET_IMAGE;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;
    case ENROLL_RECV_IMAGE:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case ENROLL_GEN_CHAR:
        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            if (self->waiting_for_lift) {
                self->waiting_for_lift = FALSE;
                fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
                fp_dbg ("Finger lifted, waiting for next press");
            }
            ma_cancel_poll_timeout (self);
            self->task_ssm = ssm;
            self->poll_timeout_id = g_timeout_add (100, poll_get_image_cb, self);
            return;
        }
        if (self->waiting_for_lift) {
            ma_cancel_poll_timeout (self);
            self->task_ssm = ssm;
            self->poll_timeout_id = g_timeout_add (100, poll_get_image_cb, self);
            return;
        }
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        cmd[0] = MA_CMD_GEN_CHAR; cmd[1] = (guint8)(self->enroll_stage + 1);
        ma_submit_cmd (ssm, device, cmd, 2);
        break;
    case ENROLL_RECV_GEN_CHAR:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case ENROLL_REG_MODEL:
        if (self->resp_buf[MA_OVERHEAD] == 0x00) {
            self->enroll_stage++;
            fpi_device_enroll_progress (device, self->enroll_stage, NULL, NULL);
        } else {
            fpi_device_enroll_progress (device, self->enroll_stage, NULL, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            self->waiting_for_lift = TRUE;
            fpi_ssm_jump_to_state (ssm, ENROLL_GET_IMAGE);
            return;
        }
        if (self->enroll_stage < MA_ENROLL_SAMPLES) {
            self->waiting_for_lift = TRUE;
            fpi_ssm_jump_to_state (ssm, ENROLL_GET_IMAGE);
            return;
        }
        cmd[0] = MA_CMD_REG_MODEL;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;
    case ENROLL_RECV_REG_MODEL:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case ENROLL_STORE_CHAR:
        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "RegModel failed"));
            return;
        }
        cmd[0] = MA_CMD_STORE_CHAR; cmd[1] = 0x01;
        cmd[2] = (guint8)(self->fid >> 8); cmd[3] = (guint8)(self->fid & 0xFF);
        ma_submit_cmd (ssm, device, cmd, 4);
        break;
    case ENROLL_RECV_STORE_CHAR:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    default:
        g_assert_not_reached ();
    }
}

static void
enroll_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);

    ma_cancel_poll_timeout (self);
    self->task_ssm = NULL;

    if (error) {
        fpi_device_enroll_complete (device, NULL, error);
        return;
    }
    if (self->resp_buf[MA_OVERHEAD] != 0x00) {
        fpi_device_enroll_complete (device, NULL, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "StoreChar failed"));
        return;
    }
    FpPrint *print = NULL;
    fpi_device_get_enroll_data (device, &print);
    fpi_print_set_type (print, FPI_PRINT_RAW);
    fpi_print_set_device_stored (print, TRUE);

    GVariant *data = g_variant_new ("(i)", self->fid);
    g_object_set (print, "fpi-data", data, NULL);

    fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
    fpi_device_enroll_complete (device, g_object_ref (print), NULL);
}

static void
ma_enroll (FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    self->enroll_stage = 0;
    self->fid = -1;
    self->waiting_for_lift = FALSE;
    ma_cancel_poll_timeout (self);
    self->task_ssm = NULL;
    FpiSsm *ssm = fpi_ssm_new (device, enroll_run_state, ENROLL_NUM_STATES);
    self->task_ssm = ssm;
    fpi_ssm_start (ssm, enroll_ssm_done);
}

/* --------------------------------------------------------------------------
 * Verify state machine (Explicit single-finger validation)
 * -------------------------------------------------------------------------- */

enum {
    VERIFY_GET_IMAGE,
    VERIFY_RECV_IMAGE,
    VERIFY_GEN_CHAR,
    VERIFY_RECV_GEN_CHAR,
    VERIFY_SEARCH,
    VERIFY_RECV_SEARCH,
    VERIFY_NUM_STATES,
};

static void
verify_run_state (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    guint8 cmd[8];

    switch (fpi_ssm_get_cur_state (ssm)) {
    case VERIFY_GET_IMAGE:
        cmd[0] = MA_CMD_GET_IMAGE;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;
    case VERIFY_RECV_IMAGE:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case VERIFY_GEN_CHAR:
        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            fpi_ssm_jump_to_state (ssm, VERIFY_GET_IMAGE);
            return;
        }
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        cmd[0] = MA_CMD_GEN_CHAR; cmd[1] = 0x01;
        ma_submit_cmd (ssm, device, cmd, 2);
        break;
    case VERIFY_RECV_GEN_CHAR:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case VERIFY_SEARCH: {
        GError *error = NULL;
        FpPrint *print = NULL;
        gint fid = -1;

        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            fpi_ssm_mark_failed (ssm, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            return;
        }
        fpi_device_get_verify_data (device, &print);
        if (!ma_print_get_fid (print, &fid, &error)) {
            fpi_ssm_mark_failed (ssm, error);
            return;
        }
        self->fid = fid;

        cmd[0] = MA_CMD_SEARCH;
        cmd[1] = (guint8)(self->fid >> 8); cmd[2] = (guint8)(self->fid & 0xFF);
        ma_submit_cmd (ssm, device, cmd, 3);
        break;
    }
    case VERIFY_RECV_SEARCH:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    default:
        g_assert_not_reached ();
    }
}

static void
verify_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);

    if (error) {
        fpi_device_verify_complete (device, error);
        return;
    }

    gboolean matched = (self->resp_buf[MA_OVERHEAD] == 0x00);
    FpiMatchResult result = matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;

    FpPrint *print = NULL;
    if (matched)
        fpi_device_get_verify_data (device, &print);

    fpi_device_verify_report (device, result, print, NULL);
    fpi_device_verify_complete (device, NULL);
}

/* --------------------------------------------------------------------------
 * Identify state machine (Device-wide global search for sudo)
 * -------------------------------------------------------------------------- */

enum {
    IDENTIFY_GET_IMAGE,
    IDENTIFY_RECV_IMAGE,
    IDENTIFY_GEN_CHAR,
    IDENTIFY_RECV_GEN_CHAR,
    IDENTIFY_SEARCH,
    IDENTIFY_RECV_SEARCH,
    IDENTIFY_CHECK_MATCH,
    IDENTIFY_NUM_STATES,
};

static void
identify_run_state (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    guint8 cmd[8];

    switch (fpi_ssm_get_cur_state (ssm)) {
    case IDENTIFY_GET_IMAGE:
        cmd[0] = MA_CMD_GET_IMAGE;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;
    case IDENTIFY_RECV_IMAGE:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case IDENTIFY_GEN_CHAR:
        /* identify_index == 0: first pass after GetImage; later passes re-GenChar only. */
        if (self->identify_index == 0) {
            if (self->resp_buf[MA_OVERHEAD] != 0x00) {
                fp_dbg ("GetImage not ready, retrying");
                fpi_ssm_jump_to_state (ssm, IDENTIFY_GET_IMAGE);
                return;
            }
            fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        }

        cmd[0] = MA_CMD_GEN_CHAR; cmd[1] = 0x01;
        ma_submit_cmd (ssm, device, cmd, 2);
        break;
    case IDENTIFY_RECV_GEN_CHAR:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case IDENTIFY_SEARCH: {
        GError *error = NULL;
        GPtrArray *prints = NULL;
        FpPrint *print;
        gint fid = -1;

        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            fpi_ssm_mark_failed (ssm, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            return;
        }

        fpi_device_get_identify_data (device, &prints);
        if (!prints || self->identify_index >= prints->len) {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "No templates to check"));
            return;
        }

        /* Skip prints with missing/invalid FID rather than defaulting to slot 0. */
        while (self->identify_index < prints->len) {
            print = g_ptr_array_index (prints, self->identify_index);
            g_clear_error (&error);
            if (ma_print_get_fid (print, &fid, &error))
                break;
            fp_dbg ("Skipping identify candidate %u: %s", self->identify_index, error->message);
            self->identify_index++;
        }
        g_clear_error (&error);

        if (self->identify_index >= prints->len) {
            /* No usable templates — complete as no-match (resp status left non-zero). */
            self->resp_buf[MA_OVERHEAD] = 0x01;
            fpi_ssm_mark_completed (ssm);
            return;
        }

        self->fid = fid;
        fp_dbg ("Searching hardware memory slot ID: %d (Index %u/%u)",
                self->fid, self->identify_index + 1, prints->len);

        cmd[0] = MA_CMD_SEARCH;
        cmd[1] = (guint8)(self->fid >> 8);
        cmd[2] = (guint8)(self->fid & 0xFF);
        ma_submit_cmd (ssm, device, cmd, 3);
        break;
    }
    case IDENTIFY_RECV_SEARCH:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;
    case IDENTIFY_CHECK_MATCH: {
        guint8 status = self->resp_buf[MA_OVERHEAD];
        if (status == 0x00) {
            fp_dbg ("Hardware match verified on slot ID %d!", self->fid);
            fpi_ssm_mark_completed (ssm);
        } else {
            self->identify_index++;
            GPtrArray *prints = NULL;
            fpi_device_get_identify_data (device, &prints);

            /* Re-GenChar before the next Search so char-buf state stays valid. */
            if (prints && self->identify_index < prints->len) {
                fp_dbg ("Slot %d match failed. Re-extracting characteristics for next index...", self->fid);
                fpi_ssm_jump_to_state (ssm, IDENTIFY_GEN_CHAR);
            } else {
                fp_dbg ("Scan completed: No matching enrolled prints found.");
                fpi_ssm_mark_completed (ssm);
            }
        }
        break;
    }
    default:
        g_assert_not_reached ();
    }
}

static void
identify_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);

    if (error) {
        fpi_device_identify_complete (device, error);
        return;
    }

    if (self->resp_buf[MA_OVERHEAD] == 0x00) {
        GPtrArray *prints = NULL;
        fpi_device_get_identify_data (device, &prints);
        
        if (prints && self->identify_index < prints->len) {
            FpPrint *match = g_ptr_array_index (prints, self->identify_index);
            fpi_device_identify_report (device, match, NULL, NULL);
        } else {
            fpi_device_identify_report (device, NULL, NULL, NULL);
        }
    } else {
        fpi_device_identify_report (device, NULL, NULL, NULL);
    }
    fpi_device_identify_complete (device, NULL);
}

static void
ma_verify (FpDevice *device)
{
    FpiSsm *ssm = fpi_ssm_new (device, verify_run_state, VERIFY_NUM_STATES);
    fpi_ssm_start (ssm, verify_ssm_done);
}

static void
ma_identify (FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    GPtrArray *prints = NULL;

    fpi_device_get_identify_data (device, &prints);

    if (!prints || prints->len == 0) {
        fp_dbg ("No templates enrolled on the system. Skipping hardware search loop.");
        fpi_device_identify_report (device, NULL, NULL, NULL);
        fpi_device_identify_complete (device, NULL);
        return;
    }

    self->identify_index = 0;
    FpiSsm *ssm = fpi_ssm_new (device, identify_run_state, IDENTIFY_NUM_STATES);
    fpi_ssm_start (ssm, identify_ssm_done);
}

/* --------------------------------------------------------------------------
 * Delete
 *
 * Hardware only documents CMD 0x0D Empty (erase ALL templates). Issuing that
 * for a single fprintd delete would wipe every enrolled user. Refuse instead.
 * -------------------------------------------------------------------------- */

static void
ma_delete (FpDevice *device)
{
    fpi_device_delete_complete (device,
                                fpi_device_error_new_msg (
                                    FP_DEVICE_ERROR_NOT_SUPPORTED,
                                    "Device cannot delete a single template "
                                    "(Empty would erase all slots)"));
}

/* --------------------------------------------------------------------------
 * GObject boilerplate
 * -------------------------------------------------------------------------- */

static const FpIdEntry id_table[] = {
    { .vid = 0x3274, .pid = 0x8012, .driver_data = 0 },
    { .vid = 0,      .pid = 0,      .driver_data = 0 },
};

static void
fpi_device_microarray_init (FpiDeviceMicroarray *self)
{
    self->enroll_stage = 0;
    self->fid = -1;
    self->waiting_for_lift = FALSE;
    self->identify_index = 0;
    self->poll_timeout_id = 0;
    self->resp_buf_size = MA_RESP_BUF;
    self->resp_buf = g_malloc0 (self->resp_buf_size);
}

static void
fpi_device_microarray_finalize (GObject *object)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (object);
    ma_cancel_poll_timeout (self);
    g_clear_pointer (&self->resp_buf, g_free);
    G_OBJECT_CLASS (fpi_device_microarray_parent_class)->finalize (object);
}

static void
fpi_device_microarray_class_init (FpiDeviceMicroarrayClass *klass)
{
    GObjectClass   *obj_class = G_OBJECT_CLASS (klass);
    FpDeviceClass  *dev_class = FP_DEVICE_CLASS (klass);

    obj_class->finalize = fpi_device_microarray_finalize;

    dev_class->id               = "microarray";
    dev_class->full_name        = "MicroarrayTechnology MAFP";
    dev_class->type             = FP_DEVICE_TYPE_USB;
    dev_class->id_table         = id_table;
    dev_class->nr_enroll_stages = MA_ENROLL_SAMPLES;
    dev_class->scan_type        = FP_SCAN_TYPE_PRESS;

    dev_class->open     = ma_dev_open;
    dev_class->close    = ma_dev_close;
    dev_class->enroll   = ma_enroll;
    dev_class->verify   = ma_verify;
    dev_class->identify = ma_identify;
    dev_class->delete   = ma_delete;

    fpi_device_class_auto_initialize_features (dev_class);
}