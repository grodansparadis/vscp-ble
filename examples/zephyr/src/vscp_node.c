/*
 * vscp_node.c - VSCP BLE node for Zephyr / nRF Connect SDK
 *
 * Threads: GATT callbacks run in the Bluetooth RX thread, vscp_node_send()
 * in the caller's thread and the timers in the system work queue. All G1
 * state is protected by g1_lock. Indications are sent from the work queue,
 * one at a time.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/byteorder.h>

#include "vscp-ble-a2.h"
#include "vscp-ble-counter.h"
#include "vscp-ble-crypto.h"
#include "vscp-ble-e1.h"
#include "vscp-ble-g1.h"

#include "vscp_node.h"

LOG_MODULE_REGISTER(vscp_node, LOG_LEVEL_INF);

#define COUNTER_BLOCK 256

static vscp_node_config_t cfg;

// ---------------------------------------------------------------------------
//                 Settings: counters and the A2 key
// ---------------------------------------------------------------------------

typedef struct {
  uint32_t epoch;
  uint64_t reserved_until;
} counter_record_t;

static counter_record_t e1_saved, a2_saved;
static vscp_ble_counter_t e1_counter, a2_counter;

static struct {
  bool valid;
  uint16_t key_id;
  uint8_t key[16];
  uint8_t prefix[5];
} a2_key;

static int
settings_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
  const char *next;
  if (settings_name_steq(name, "e1", &next) && !next && (sizeof(e1_saved) == len)) {
    return (read_cb(cb_arg, &e1_saved, len) == (ssize_t) len) ? 0 : -EIO;
  }
  if (settings_name_steq(name, "a2", &next) && !next && (sizeof(a2_saved) == len)) {
    return (read_cb(cb_arg, &a2_saved, len) == (ssize_t) len) ? 0 : -EIO;
  }
  if (settings_name_steq(name, "a2key", &next) && !next && (23 == len)) {
    // 2 octets key id (BE), 16 octets AES key, 5 octets nonce prefix
    uint8_t blob[23];
    if (read_cb(cb_arg, blob, len) != (ssize_t) len) {
      return -EIO;
    }
    a2_key.key_id = sys_get_be16(blob);
    memcpy(a2_key.key, blob + 2, 16);
    memcpy(a2_key.prefix, blob + 18, 5);
    a2_key.valid = (0 != a2_key.key_id);
    vscp_ble_secure_zero(blob, sizeof(blob));
    return 0;
  }
  return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(vscp_ble, "vscp_ble", NULL, settings_set, NULL, NULL);

// Durable before any value of the new block is used
static int
counter_persist(void *ctx, uint32_t epoch, uint64_t reserved_until)
{
  counter_record_t rec = { epoch, reserved_until };
  int rc               = settings_save_one((const char *) ctx, &rec, sizeof(rec));
  if (rc) {
    LOG_ERR("Counter %s not saved (%d): sending stops", (const char *) ctx, rc);
  }
  return rc;
}

// ---------------------------------------------------------------------------
//                              Advertising
// ---------------------------------------------------------------------------

static struct bt_le_ext_adv *adv_g1, *adv_e1, *adv_a2;

#define G1_UUID_VAL(n) BT_UUID_128_ENCODE(0x9b7a0000 + (n), 0x6e44, 0x4b8a, 0x9d64, 0x565343502001)

static const struct bt_data g1_ad[] = {
  BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
  BT_DATA_BYTES(BT_DATA_UUID128_ALL, G1_UUID_VAL(0)),
};

static const struct bt_data g1_sd[] = {
  BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME, sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};

static int
create_broadcast_set(struct bt_le_ext_adv **adv, uint8_t sid)
{
  // EA-B: extended, non-connectable, non-scannable, LE 1M primary/secondary
  struct bt_le_adv_param param = BT_LE_ADV_PARAM_INIT(BT_LE_ADV_OPT_EXT_ADV | BT_LE_ADV_OPT_USE_IDENTITY,
                                                      BT_GAP_MS_TO_ADV_INTERVAL(100),
                                                      BT_GAP_MS_TO_ADV_INTERVAL(150),
                                                      NULL);
  param.sid                    = sid;
  return bt_le_ext_adv_create(&param, NULL, adv);
}

// Replace the data of a broadcast set with one VSCP frame
static void
publish(struct bt_le_ext_adv *adv, const uint8_t *frame, size_t len)
{
  // Zephyr adds the AD Length and Type octets itself
  struct bt_data ad = BT_DATA(BT_DATA_MANUFACTURER_DATA, frame + 2, (uint8_t) (len - 2));
  bt_le_ext_adv_stop(adv);
  int rc = bt_le_ext_adv_set_data(adv, &ad, 1, NULL, 0);
  if (!rc) {
    rc = bt_le_ext_adv_start(adv, BT_LE_EXT_ADV_START_DEFAULT);
  }
  if (rc) {
    LOG_ERR("Broadcast failed (%d)", rc);
  }
}

static void
g1_advertise(void)
{
  if (!IS_ENABLED(CONFIG_VSCP_NODE_G1) || (NULL == adv_g1)) {
    return;
  }
  int rc = bt_le_ext_adv_start(adv_g1, BT_LE_EXT_ADV_START_DEFAULT);
  if (rc && (-EALREADY != rc)) {
    LOG_ERR("G1 advertising failed (%d)", rc);
  }
  else if (cfg.on_state) {
    cfg.on_state(VSCP_NODE_ADVERTISING);
  }
}

// ---------------------------------------------------------------------------
//                              G1 GATT server
// ---------------------------------------------------------------------------

static K_MUTEX_DEFINE(g1_lock);
static vscp_ble_g1_server_t g1;
static struct bt_conn *g1_conn;

static const struct bt_gatt_attr *attr_event_tx, *attr_control;

// Indication queue, drained from the system work queue
#define IND_QUEUE_LEN 8
static struct {
  uint8_t data[16];
  uint8_t len;
} ind_queue[IND_QUEUE_LEN];
static unsigned ind_head, ind_count;
static bool ind_busy;
static uint8_t ind_buf[16];
static struct bt_gatt_indicate_params ind_params;
static void
ind_work_handler(struct k_work *work);
static K_WORK_DEFINE(ind_work, ind_work_handler);

static void
ind_done(struct bt_conn *conn, struct bt_gatt_indicate_params *params, uint8_t err)
{
  ARG_UNUSED(conn);
  ARG_UNUSED(params);
  ARG_UNUSED(err);
  k_mutex_lock(&g1_lock, K_FOREVER);
  ind_busy = false;
  k_mutex_unlock(&g1_lock);
  k_work_submit(&ind_work);
}

static void
ind_work_handler(struct k_work *work)
{
  ARG_UNUSED(work);
  k_mutex_lock(&g1_lock, K_FOREVER);
  if (!ind_busy && ind_count && g1_conn) {
    memcpy(ind_buf, ind_queue[ind_head].data, ind_queue[ind_head].len);
    memset(&ind_params, 0, sizeof(ind_params));
    ind_params.attr = attr_control;
    ind_params.func = ind_done;
    ind_params.data = ind_buf;
    ind_params.len  = ind_queue[ind_head].len;
    ind_head        = (ind_head + 1) % IND_QUEUE_LEN;
    ind_count--;
    if (0 == bt_gatt_indicate(g1_conn, &ind_params)) {
      ind_busy = true;
    }
    else {
      k_work_submit(&ind_work); // Try the next one
    }
  }
  k_mutex_unlock(&g1_lock);
}

// Called with g1_lock held
static int
g1_indicate(void *ctx, const uint8_t *data, size_t len)
{
  ARG_UNUSED(ctx);
  if ((IND_QUEUE_LEN == ind_count) || (len > sizeof(ind_queue[0].data))) {
    return -1;
  }
  unsigned slot = (ind_head + ind_count) % IND_QUEUE_LEN;
  memcpy(ind_queue[slot].data, data, len);
  ind_queue[slot].len = (uint8_t) len;
  ind_count++;
  k_work_submit(&ind_work);
  return 0;
}

// Called with g1_lock held, from vscp_node_send() (thread context)
static int
g1_notify(void *ctx, const uint8_t *data, size_t len)
{
  ARG_UNUSED(ctx);
  return bt_gatt_notify(g1_conn, attr_event_tx, data, (uint16_t) len) ? -1 : 0;
}

static uint8_t
g1_on_event(void *ctx, const vscp_ble_event_t *ev, uint32_t tid)
{
  ARG_UNUSED(ctx);
  ARG_UNUSED(tid);
  return cfg.on_event ? cfg.on_event(ev) : VSCP_BLE_G1_NOT_AUTHORIZED;
}

static const vscp_ble_g1_ops_t g1_ops = { g1_indicate, g1_notify, g1_on_event };

static ssize_t
read_value(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf, uint16_t len, uint16_t offset)
{
  uint8_t value[16];
  size_t n = 0;
  k_mutex_lock(&g1_lock, K_FOREVER);
  switch ((uintptr_t) attr->user_data) {
    case VSCP_BLE_G1_UUID_CAPABILITIES:
      n = vscp_ble_g1_server_read_capabilities(&g1, value);
      break;
    case VSCP_BLE_G1_UUID_GUID:
      n = vscp_ble_g1_server_read_guid(&g1, value);
      break;
    case VSCP_BLE_G1_UUID_SECURITY:
      n = vscp_ble_g1_server_read_security(&g1, value);
      break;
    case VSCP_BLE_G1_UUID_CONFIGURATION:
      n = vscp_ble_g1_server_read_configuration(&g1, value);
      break;
  }
  k_mutex_unlock(&g1_lock);
  return bt_gatt_attr_read(conn, attr, buf, len, offset, value, (uint16_t) n);
}

static ssize_t
write_value(struct bt_conn *conn,
            const struct bt_gatt_attr *attr,
            const void *buf,
            uint16_t len,
            uint16_t offset,
            uint8_t flags)
{
  if (offset || (flags & BT_GATT_WRITE_FLAG_PREPARE)) {
    return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET); // One fragment per write
  }
  if (conn != g1_conn) {
    return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
  }
  uint8_t att = 0;
  k_mutex_lock(&g1_lock, K_FOREVER);
  switch ((uintptr_t) attr->user_data) {
    case VSCP_BLE_G1_UUID_CONTROL:
      att = vscp_ble_g1_server_write_control(&g1, buf, len, k_uptime_get_32());
      break;
    case VSCP_BLE_G1_UUID_EVENT_RX:
      att = vscp_ble_g1_server_write_event_rx(&g1, buf, len, k_uptime_get_32());
      break;
    case VSCP_BLE_G1_UUID_CONFIGURATION:
      att = vscp_ble_g1_server_write_configuration(&g1, buf, len);
      break;
    default:
      att = BT_ATT_ERR_WRITE_NOT_PERMITTED;
  }
  k_mutex_unlock(&g1_lock);
  return att ? BT_GATT_ERR(att) : (ssize_t) len;
}

static void
control_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
  ARG_UNUSED(attr);
  k_mutex_lock(&g1_lock, K_FOREVER);
  vscp_ble_g1_server_set_control_indicate(&g1, BT_GATT_CCC_INDICATE == value);
  k_mutex_unlock(&g1_lock);
}

static void
event_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
  ARG_UNUSED(attr);
  k_mutex_lock(&g1_lock, K_FOREVER);
  vscp_ble_g1_server_set_event_notify(&g1, BT_GATT_CCC_NOTIFY == value);
  k_mutex_unlock(&g1_lock);
}

#define G1_UUID(n) BT_UUID_DECLARE_128(G1_UUID_VAL(n))
#define TAG(n)     ((void *) (uintptr_t) (n))

// Protected attributes need authenticated (MITM) encryption; the CCCDs too
BT_GATT_SERVICE_DEFINE(vscp_g1_svc,
                       BT_GATT_PRIMARY_SERVICE(G1_UUID(0)),
                       BT_GATT_CHARACTERISTIC(G1_UUID(1),
                                              BT_GATT_CHRC_READ,
                                              BT_GATT_PERM_READ,
                                              read_value,
                                              NULL,
                                              TAG(VSCP_BLE_G1_UUID_CAPABILITIES)),
                       BT_GATT_CHARACTERISTIC(G1_UUID(2),
                                              BT_GATT_CHRC_READ,
                                              BT_GATT_PERM_READ,
                                              read_value,
                                              NULL,
                                              TAG(VSCP_BLE_G1_UUID_GUID)),
                       BT_GATT_CHARACTERISTIC(G1_UUID(3),
                                              BT_GATT_CHRC_NOTIFY,
                                              BT_GATT_PERM_NONE,
                                              NULL,
                                              NULL,
                                              TAG(VSCP_BLE_G1_UUID_EVENT_TX)),
                       BT_GATT_CCC(event_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE_AUTHEN),
                       BT_GATT_CHARACTERISTIC(G1_UUID(4),
                                              BT_GATT_CHRC_WRITE,
                                              BT_GATT_PERM_WRITE_AUTHEN,
                                              NULL,
                                              write_value,
                                              TAG(VSCP_BLE_G1_UUID_EVENT_RX)),
                       BT_GATT_CHARACTERISTIC(G1_UUID(5),
                                              BT_GATT_CHRC_WRITE | BT_GATT_CHRC_INDICATE,
                                              BT_GATT_PERM_WRITE_AUTHEN,
                                              NULL,
                                              write_value,
                                              TAG(VSCP_BLE_G1_UUID_CONTROL)),
                       BT_GATT_CCC(control_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE_AUTHEN),
                       BT_GATT_CHARACTERISTIC(G1_UUID(6),
                                              BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
                                              BT_GATT_PERM_READ_AUTHEN | BT_GATT_PERM_WRITE_AUTHEN,
                                              read_value,
                                              write_value,
                                              TAG(VSCP_BLE_G1_UUID_CONFIGURATION)),
                       BT_GATT_CHARACTERISTIC(G1_UUID(7),
                                              BT_GATT_CHRC_READ,
                                              BT_GATT_PERM_READ_AUTHEN,
                                              read_value,
                                              NULL,
                                              TAG(VSCP_BLE_G1_UUID_SECURITY)), );

// ---------------------------------------------------------------------------
//                           Connection handling
// ---------------------------------------------------------------------------

static void
connected(struct bt_conn *conn, uint8_t err)
{
  if (err || g1_conn) {
    return;
  }
  g1_conn = bt_conn_ref(conn);
  k_mutex_lock(&g1_lock, K_FOREVER);
  ind_count = 0;
  ind_busy  = false;
  vscp_ble_g1_server_connected(&g1, bt_gatt_get_mtu(conn));
  k_mutex_unlock(&g1_lock);
  if (cfg.on_state) {
    cfg.on_state(VSCP_NODE_CONNECTED);
  }
  // LE Secure Connections with MITM protection
  if (bt_conn_set_security(conn, BT_SECURITY_L4)) {
    LOG_WRN("Could not request security level 4");
  }
}

static void
disconnected(struct bt_conn *conn, uint8_t reason)
{
  if (conn != g1_conn) {
    return;
  }
  LOG_INF("Disconnected (0x%02x)", reason);
  k_mutex_lock(&g1_lock, K_FOREVER);
  vscp_ble_g1_server_disconnected(&g1);
  ind_count = 0;
  ind_busy  = false;
  k_mutex_unlock(&g1_lock);
  bt_conn_unref(g1_conn);
  g1_conn = NULL;
  if (cfg.on_state) {
    cfg.on_state(VSCP_NODE_DISCONNECTED);
  }
}

static void
recycled(void)
{
  g1_advertise(); // Connection object free again
}

static void
security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
  if (conn != g1_conn) {
    return;
  }
  struct bt_conn_info info;
  bt_conn_get_info(conn, &info);
  // L3 = authenticated pairing, L4 = authenticated LE Secure Connections
  uint8_t pairing = (!err && (level >= BT_SECURITY_L3)) ? VSCP_BLE_G1_PAIRING_AUTHENTICATED : VSCP_BLE_G1_PAIRING_NONE;
  uint8_t auth    = VSCP_BLE_G1_AUTH_NONE;
  if (pairing && bt_le_bond_exists(info.id, info.le.dst) && cfg.authorize) {
    auth = cfg.authorize(info.le.dst);
  }
  k_mutex_lock(&g1_lock, K_FOREVER);
  vscp_ble_g1_server_set_security(&g1, pairing, auth);
  k_mutex_unlock(&g1_lock);
  LOG_INF("Security level %d (err %d), authorization %d", level, err, auth);
  if (cfg.on_state && pairing) {
    cfg.on_state(auth ? VSCP_NODE_AUTHORIZED : VSCP_NODE_SECURED);
  }
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
  .connected        = connected,
  .disconnected     = disconnected,
  .recycled         = recycled,
  .security_changed = security_changed,
};

static void
mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx)
{
  if (conn == g1_conn) {
    k_mutex_lock(&g1_lock, K_FOREVER);
    vscp_ble_g1_server_set_mtu(&g1, MIN(tx, rx));
    k_mutex_unlock(&g1_lock);
  }
}

static struct bt_gatt_cb gatt_callbacks = { .att_mtu_updated = mtu_updated };

static void
passkey_display(struct bt_conn *conn, unsigned int passkey)
{
  ARG_UNUSED(conn);
  LOG_WRN("Pairing passkey: %06u", passkey);
}

static void
auth_cancel(struct bt_conn *conn)
{
  ARG_UNUSED(conn);
  LOG_WRN("Pairing cancelled");
}

static const struct bt_conn_auth_cb auth_callbacks = {
  .passkey_display = passkey_display,
  .cancel          = auth_cancel,
};

static void
g1_tick_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(g1_tick_work, g1_tick_handler);

static void
g1_tick_handler(struct k_work *work)
{
  ARG_UNUSED(work);
  k_mutex_lock(&g1_lock, K_FOREVER);
  vscp_ble_g1_server_tick(&g1, k_uptime_get_32());
  k_mutex_unlock(&g1_lock);
  k_work_reschedule(&g1_tick_work, K_SECONDS(1));
}

// ---------------------------------------------------------------------------
//                                 API
// ---------------------------------------------------------------------------

int
vscp_node_start(const vscp_node_config_t *config)
{
  cfg = *config;

  int rc = bt_enable(NULL);
  if (rc) {
    LOG_ERR("Bluetooth init failed (%d)", rc);
    return rc;
  }
  settings_load(); // Bonds, counters, A2 key

  vscp_ble_counter_init(&e1_counter,
                        e1_saved.epoch,
                        e1_saved.reserved_until,
                        COUNTER_BLOCK,
                        0,
                        counter_persist,
                        (void *) "vscp_ble/e1");
  vscp_ble_counter_init(&a2_counter,
                        a2_saved.epoch,
                        a2_saved.reserved_until,
                        COUNTER_BLOCK,
                        1,
                        counter_persist,
                        (void *) "vscp_ble/a2");

#if defined(CONFIG_VSCP_NODE_A2_INSECURE_TEST_KEY)
  if (!a2_key.valid) {
    LOG_WRN("A2 uses the PUBLIC test key: anyone can read and forge these events");
    a2_key.key_id = 1;
    for (int i = 0; i < 16; i++) {
      a2_key.key[i] = (uint8_t) i;
    }
    const uint8_t prefix[5] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4 };
    memcpy(a2_key.prefix, prefix, 5);
    a2_key.valid = true;
  }
#endif
  if (IS_ENABLED(CONFIG_VSCP_NODE_A2) && !a2_key.valid) {
    LOG_WRN("No A2 key provisioned (setting vscp_ble/a2key): A2 disabled");
  }

  if (IS_ENABLED(CONFIG_VSCP_NODE_E1) && create_broadcast_set(&adv_e1, 1)) {
    LOG_ERR("No extended advertising set for E1");
  }
  if (IS_ENABLED(CONFIG_VSCP_NODE_A2) && a2_key.valid && create_broadcast_set(&adv_a2, 2)) {
    LOG_ERR("No extended advertising set for A2");
  }

  if (IS_ENABLED(CONFIG_VSCP_NODE_G1)) {
    vscp_ble_g1_server_init(&g1, &g1_ops, NULL, cfg.guid, VSCP_BLE_G1_MAX_DATA);
    attr_event_tx = bt_gatt_find_by_uuid(vscp_g1_svc.attrs, vscp_g1_svc.attr_count, G1_UUID(3));
    attr_control  = bt_gatt_find_by_uuid(vscp_g1_svc.attrs, vscp_g1_svc.attr_count, G1_UUID(5));
    bt_gatt_cb_register(&gatt_callbacks);
    bt_conn_auth_cb_register(&auth_callbacks);
    // Legacy connectable set so every central finds the service
    struct bt_le_adv_param param = BT_LE_ADV_PARAM_INIT(BT_LE_ADV_OPT_CONN | BT_LE_ADV_OPT_USE_IDENTITY,
                                                        BT_GAP_ADV_FAST_INT_MIN_2,
                                                        BT_GAP_ADV_FAST_INT_MAX_2,
                                                        NULL);
    rc                           = bt_le_ext_adv_create(&param, NULL, &adv_g1);
    if (!rc) {
      rc = bt_le_ext_adv_set_data(adv_g1, g1_ad, ARRAY_SIZE(g1_ad), g1_sd, ARRAY_SIZE(g1_sd));
    }
    if (rc) {
      LOG_ERR("G1 advertising set failed (%d)", rc);
    }
    g1_advertise();
    k_work_reschedule(&g1_tick_work, K_SECONDS(1));
  }

  LOG_INF("vscp-ble %s, crypto %s, company 0x%04X%s",
          VSCP_BLE_LIB_VERSION_STR,
          vscp_ble_crypto_backend(),
          cfg.company,
          (0xFFFF == cfg.company) ? " (TEST ONLY)" : "");
  return 0;
}

int
vscp_node_send(uint16_t vscp_class, uint16_t vscp_type, const uint8_t *data, uint16_t len)
{
  vscp_ble_event_t ev;
  memcpy(ev.guid, cfg.guid, 16);
  ev.head       = 0;
  ev.vscp_class = vscp_class;
  ev.vscp_type  = vscp_type;
  ev.size       = len;
  ev.data       = data;

  static uint8_t frame[VSCP_BLE_A2_MAX_SIZE];
  size_t flen;
  uint32_t epoch, seq;
  int rv = VSCP_BLE_OK;

  if (adv_e1) {
    rv = vscp_ble_counter_next(&e1_counter, NULL, &seq);
    if (VSCP_BLE_OK == rv) {
      rv = vscp_ble_e1_encode(frame, sizeof(frame), cfg.company, seq, &ev, &flen);
    }
    if (VSCP_BLE_OK == rv) {
      publish(adv_e1, frame, flen);
      LOG_INF("E1 seq %u", seq);
    }
    else {
      LOG_ERR("E1: %s", vscp_ble_strerror(rv));
    }
  }

  if (adv_a2) {
    rv = vscp_ble_counter_next(&a2_counter, &epoch, &seq);
    if (VSCP_BLE_OK == rv) {
      rv = vscp_ble_a2_encode(frame,
                              sizeof(frame),
                              cfg.company,
                              a2_key.key_id,
                              epoch,
                              seq,
                              a2_key.key,
                              a2_key.prefix,
                              &ev,
                              &flen);
    }
    if (VSCP_BLE_OK == rv) {
      publish(adv_a2, frame, flen);
      LOG_INF("A2 key %u epoch %u seq %u", a2_key.key_id, epoch, seq);
    }
    else {
      LOG_ERR("A2: %s (exhausted needs a new key)", vscp_ble_strerror(rv));
    }
  }

  if (IS_ENABLED(CONFIG_VSCP_NODE_G1)) {
    k_mutex_lock(&g1_lock, K_FOREVER);
    if (g1_conn) {
      int g = vscp_ble_g1_server_send_event(&g1, &ev);
      if (VSCP_BLE_ERR_STATE != g) {
        LOG_INF("G1 notify: %s", vscp_ble_strerror(g));
      }
    }
    k_mutex_unlock(&g1_lock);
  }
  return rv;
}

int
vscp_node_unpair_all(void)
{
  if (g1_conn) {
    bt_conn_disconnect(g1_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
  }
  return bt_unpair(BT_ID_DEFAULT, BT_ADDR_LE_ANY);
}
