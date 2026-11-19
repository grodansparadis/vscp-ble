/*
 * VSCP BLE reference node for ESP32 (ESP-IDF 6.1, NimBLE)
 *
 *   - Reads the on-chip temperature sensor every VSCP_BLE_EVENT_PERIOD_MS
 *     and sends it as CLASS1.MEASUREMENT / TEMPERATURE:
 *       * E1 cleartext extended advertising (public, unauthenticated)
 *       * A2 authenticated + encrypted extended advertising (provisioned key)
 *       * G1 notification to a connected, authorized central
 *   - G1 GATT server (spec section 6) with LE Secure Connections pairing,
 *     MITM protection (passkey shown on the console) and bonding.
 *   - Sequence counters persisted in NVS in reserved blocks, so values are
 *     never reused across restarts or power loss.
 *
 * Needs a BLE 5 chip with LE extended advertising: esp32s3, esp32c3,
 * esp32c6, esp32h2 ... (not the original ESP32).
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <stdio.h>
#include <string.h>

#include "driver/temperature_sensor.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "vscp-ble-a2.h"
#include "vscp-ble-counter.h"
#include "vscp-ble-crypto.h"
#include "vscp-ble-e1.h"
#include "vscp-ble-g1.h"

static const char *TAG = "vscp-ble";

#define COMPANY_ID ((uint16_t) CONFIG_VSCP_BLE_COMPANY_ID)

#define ADV_INSTANCE_G1 0 // Legacy connectable advertising for the G1 service
#define ADV_INSTANCE_E1 1 // Extended, non-connectable, non-scannable (EA-B)
#define ADV_INSTANCE_A2 2

#define VSCP_CLASS1_MEASUREMENT           10
#define VSCP_TYPE_MEASUREMENT_TEMPERATURE 6

#define NVS_NAMESPACE "vscp_ble"
#define COUNTER_BLOCK 256 // Values reserved per flash write

static uint8_t own_addr_type;
static uint8_t node_guid[16];

// ---------------------------------------------------------------------------
//                     Persistent counters (NVS)
// ---------------------------------------------------------------------------

typedef struct {
  const char *key;
  vscp_ble_counter_t counter;
} nvs_counter_t;

static nvs_counter_t e1_counter = { .key = "e1_ctr" };
static nvs_counter_t a2_counter = { .key = "a2_ctr" };

typedef struct {
  uint32_t epoch;
  uint64_t reserved_until;
} counter_record_t;

// Called before any value of a new block is used: must be durable
static int
counter_persist(void *ctx, uint32_t epoch, uint64_t reserved_until)
{
  nvs_counter_t *c     = (nvs_counter_t *) ctx;
  counter_record_t rec = { epoch, reserved_until };
  nvs_handle_t h;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
  if (ESP_OK == err) {
    err = nvs_set_blob(h, c->key, &rec, sizeof(rec));
    if (ESP_OK == err) {
      err = nvs_commit(h);
    }
    nvs_close(h);
  }
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "Counter %s not saved (%s): sending stops", c->key, esp_err_to_name(err));
    return -1;
  }
  return 0;
}

static void
counter_load(nvs_counter_t *c, int use_epoch)
{
  counter_record_t rec = { 0, 0 };
  size_t len           = sizeof(rec);
  nvs_handle_t h;
  if (ESP_OK == nvs_open(NVS_NAMESPACE, NVS_READONLY, &h)) {
    if ((ESP_OK != nvs_get_blob(h, c->key, &rec, &len)) || (sizeof(rec) != len)) {
      rec.epoch          = 0;
      rec.reserved_until = 0;
    }
    nvs_close(h);
  }
  vscp_ble_counter_init(&c->counter, rec.epoch, rec.reserved_until, COUNTER_BLOCK, use_epoch, counter_persist, c);
}

// ---------------------------------------------------------------------------
//                          A2 key (provisioned)
// ---------------------------------------------------------------------------

static struct {
  int valid;
  uint16_t key_id;
  uint8_t key[16];
  uint8_t prefix[5];
} a2_key;

static void
a2_key_load(void)
{
#if CONFIG_VSCP_BLE_SEND_A2
  uint8_t blob[23];
  size_t len = sizeof(blob);
  nvs_handle_t h;
  if (ESP_OK == nvs_open(NVS_NAMESPACE, NVS_READONLY, &h)) {
    if ((ESP_OK == nvs_get_blob(h, "a2_key", blob, &len)) && (sizeof(blob) == len)) {
      a2_key.key_id = vscp_ble_get16(blob);
      memcpy(a2_key.key, blob + 2, 16);
      memcpy(a2_key.prefix, blob + 18, 5);
      a2_key.valid = (0 != a2_key.key_id);
    }
    vscp_ble_secure_zero(blob, sizeof(blob));
    nvs_close(h);
  }
#if CONFIG_VSCP_BLE_A2_INSECURE_TEST_KEY
  if (!a2_key.valid) {
    ESP_LOGW(TAG, "A2 uses the PUBLIC test key: anyone can read and forge these events");
    a2_key.key_id = 1;
    for (int i = 0; i < 16; i++) {
      a2_key.key[i] = (uint8_t) i;
    }
    const uint8_t prefix[5] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4 };
    memcpy(a2_key.prefix, prefix, 5);
    a2_key.valid = 1;
  }
#endif
  if (!a2_key.valid) {
    ESP_LOGW(TAG, "No A2 key provisioned (NVS %s/a2_key): A2 disabled", NVS_NAMESPACE);
  }
#endif
}

// ---------------------------------------------------------------------------
//                       Extended advertising (E1/A2)
// ---------------------------------------------------------------------------

static int
ext_adv_configure(uint8_t instance, uint8_t sid)
{
  struct ble_gap_ext_adv_params params;
  memset(&params, 0, sizeof(params));
  params.connectable   = 0; // EA-B: non-connectable, non-scannable
  params.scannable     = 0;
  params.legacy_pdu    = 0;
  params.own_addr_type = own_addr_type;
  params.primary_phy   = BLE_HCI_LE_PHY_1M;
  params.secondary_phy = BLE_HCI_LE_PHY_1M;
  params.sid           = sid;
  params.tx_power      = 127; // No preference
  params.itvl_min      = BLE_GAP_ADV_ITVL_MS(100);
  params.itvl_max      = BLE_GAP_ADV_ITVL_MS(150);
  return ble_gap_ext_adv_configure(instance, &params, NULL, NULL, NULL);
}

// Replace the advertising data of an instance with one VSCP frame
static void
ext_adv_publish(uint8_t instance, const uint8_t *frame, size_t len)
{
  if (ble_gap_ext_adv_active(instance)) {
    ble_gap_ext_adv_stop(instance);
  }
  struct os_mbuf *om = os_msys_get_pkthdr(len, 0);
  if (NULL == om) {
    ESP_LOGE(TAG, "No mbuf for advertising data");
    return;
  }
  int rc = os_mbuf_append(om, frame, len);
  if (0 == rc) {
    rc = ble_gap_ext_adv_set_data(instance, om); // Takes the mbuf
  }
  else {
    os_mbuf_free_chain(om);
  }
  if (0 == rc) {
    rc = ble_gap_ext_adv_start(instance, 0, 0);
  }
  if (0 != rc) {
    ESP_LOGE(TAG, "Advertising instance %d failed: %d", instance, rc);
  }
}

// ---------------------------------------------------------------------------
//                              G1 GATT server
// ---------------------------------------------------------------------------

static vscp_ble_g1_server_t g1;
static uint16_t g1_conn = BLE_HS_CONN_HANDLE_NONE;
static uint16_t h_caps, h_guid, h_event_tx, h_event_rx, h_control, h_config, h_security;

// Control indications go one at a time (wait for the confirmation)
#define IND_QUEUE_LEN 8
static struct {
  uint8_t data[16];
  uint8_t len;
} ind_queue[IND_QUEUE_LEN];
static unsigned ind_head, ind_count;
static bool ind_busy;

static void
ind_send_next(void)
{
  while (!ind_busy && ind_count && (BLE_HS_CONN_HANDLE_NONE != g1_conn)) {
    struct os_mbuf *om = ble_hs_mbuf_from_flat(ind_queue[ind_head].data, ind_queue[ind_head].len);
    ind_head           = (ind_head + 1) % IND_QUEUE_LEN;
    ind_count--;
    if ((NULL != om) && (0 == ble_gatts_indicate_custom(g1_conn, h_control, om))) {
      ind_busy = true;
    }
  }
}

static int
g1_indicate(void *ctx, const uint8_t *data, size_t len)
{
  (void) ctx;
  if ((IND_QUEUE_LEN == ind_count) || (len > sizeof(ind_queue[0].data))) {
    return -1;
  }
  unsigned slot = (ind_head + ind_count) % IND_QUEUE_LEN;
  memcpy(ind_queue[slot].data, data, len);
  ind_queue[slot].len = (uint8_t) len;
  ind_count++;
  ind_send_next();
  return 0;
}

static int
g1_notify(void *ctx, const uint8_t *data, size_t len)
{
  (void) ctx;
  struct os_mbuf *om = ble_hs_mbuf_from_flat(data, (uint16_t) len);
  if (NULL == om) {
    return -1;
  }
  return (0 == ble_gatts_notify_custom(g1_conn, h_event_tx, om)) ? 0 : -1;
}

// An event written by the central. Validate VSCP semantics and authorize
// it (by class/type and peer) before acting on it.
static uint8_t
g1_on_event(void *ctx, const vscp_ble_event_t *ev, uint32_t tid)
{
  (void) ctx;
  ESP_LOGI(TAG,
           "G1 event tid %lu: class %u type %u, %u data octets",
           (unsigned long) tid,
           ev->vscp_class,
           ev->vscp_type,
           ev->size);
  return VSCP_BLE_G1_OK;
}

static const vscp_ble_g1_ops_t g1_ops = { g1_indicate, g1_notify, g1_on_event };

static uint32_t
now_ms(void)
{
  return (uint32_t) (esp_timer_get_time() / 1000);
}

static int
gatt_access(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
  (void) arg;
  uint8_t buf[VSCP_BLE_G1_FRAG_HEADER + VSCP_BLE_G1_MAX_RECORD];
  size_t len = 0;

  if (conn_handle != g1_conn) {
    return BLE_ATT_ERR_UNLIKELY;
  }
  if (BLE_GATT_ACCESS_OP_READ_CHR == ctxt->op) {
    if (attr_handle == h_caps) {
      len = vscp_ble_g1_server_read_capabilities(&g1, buf);
    }
    else if (attr_handle == h_guid) {
      len = vscp_ble_g1_server_read_guid(&g1, buf);
    }
    else if (attr_handle == h_security) {
      len = vscp_ble_g1_server_read_security(&g1, buf);
    }
    else if (attr_handle == h_config) {
      len = vscp_ble_g1_server_read_configuration(&g1, buf);
    }
    else {
      return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }
    return (0 == os_mbuf_append(ctxt->om, buf, len)) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
  }

  if (BLE_GATT_ACCESS_OP_WRITE_CHR == ctxt->op) {
    uint16_t n = 0;
    if (0 != ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &n)) {
      return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    // The return value is the ATT error code (0 = success)
    if (attr_handle == h_control) {
      return vscp_ble_g1_server_write_control(&g1, buf, n, now_ms());
    }
    if (attr_handle == h_event_rx) {
      return vscp_ble_g1_server_write_event_rx(&g1, buf, n, now_ms());
    }
    if (attr_handle == h_config) {
      return vscp_ble_g1_server_write_configuration(&g1, buf, n);
    }
    return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
  }
  return BLE_ATT_ERR_UNLIKELY;
}

#define G1_UUID(n)                                                                                                     \
  BLE_UUID128_INIT(0x01, 0x20, 0x50, 0x43, 0x53, 0x56, 0x64, 0x9d, 0x8a, 0x4b, 0x44, 0x6e, (n), 0x00, 0x7a, 0x9b)

static const ble_uuid128_t uuid_service  = G1_UUID(0x00);
static const ble_uuid128_t uuid_caps     = G1_UUID(0x01);
static const ble_uuid128_t uuid_guid     = G1_UUID(0x02);
static const ble_uuid128_t uuid_event_tx = G1_UUID(0x03);
static const ble_uuid128_t uuid_event_rx = G1_UUID(0x04);
static const ble_uuid128_t uuid_control  = G1_UUID(0x05);
static const ble_uuid128_t uuid_config   = G1_UUID(0x06);
static const ble_uuid128_t uuid_security = G1_UUID(0x07);

// Protected attributes need an encrypted link with MITM protection
#define F_AUTH_READ  (BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_READ_AUTHEN)
#define F_AUTH_WRITE (BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC | BLE_GATT_CHR_F_WRITE_AUTHEN)

static const struct ble_gatt_svc_def g1_service[] = {
  {
    .type = BLE_GATT_SVC_TYPE_PRIMARY,
    .uuid = &uuid_service.u,
    .characteristics =
      (struct ble_gatt_chr_def[]) {
        { .uuid = &uuid_caps.u, .access_cb = gatt_access, .flags = BLE_GATT_CHR_F_READ, .val_handle = &h_caps },
        { .uuid = &uuid_guid.u, .access_cb = gatt_access, .flags = BLE_GATT_CHR_F_READ, .val_handle = &h_guid },
        // The CCCD write is not encrypted by NimBLE; events only flow after an
        // authenticated HELLO and while the peer is authorized
        { .uuid       = &uuid_event_tx.u,
          .access_cb  = gatt_access,
          .flags      = BLE_GATT_CHR_F_NOTIFY,
          .val_handle = &h_event_tx },
        { .uuid = &uuid_event_rx.u, .access_cb = gatt_access, .flags = F_AUTH_WRITE, .val_handle = &h_event_rx },
        { .uuid       = &uuid_control.u,
          .access_cb  = gatt_access,
          .flags      = F_AUTH_WRITE | BLE_GATT_CHR_F_INDICATE,
          .val_handle = &h_control },
        { .uuid       = &uuid_config.u,
          .access_cb  = gatt_access,
          .flags      = F_AUTH_READ | F_AUTH_WRITE,
          .val_handle = &h_config },
        { .uuid = &uuid_security.u, .access_cb = gatt_access, .flags = F_AUTH_READ, .val_handle = &h_security },
        { 0 } },
  },
  { 0 },
};

static int
gap_event(struct ble_gap_event *event, void *arg);

static void
g1_advertise(void)
{
#if CONFIG_VSCP_BLE_G1
  struct ble_gap_ext_adv_params params;
  memset(&params, 0, sizeof(params));
  params.connectable   = 1;
  params.scannable     = 1;
  params.legacy_pdu    = 1; // Found by every central
  params.own_addr_type = own_addr_type;
  params.primary_phy   = BLE_HCI_LE_PHY_1M;
  params.secondary_phy = BLE_HCI_LE_PHY_1M;
  params.sid           = 0;
  params.tx_power      = 127;
  params.itvl_min      = BLE_GAP_ADV_ITVL_MS(200);
  params.itvl_max      = BLE_GAP_ADV_ITVL_MS(300);
  if (ble_gap_ext_adv_active(ADV_INSTANCE_G1)) {
    return;
  }
  int rc = ble_gap_ext_adv_configure(ADV_INSTANCE_G1, &params, NULL, gap_event, NULL);
  if (0 != rc) {
    ESP_LOGE(TAG, "G1 advertising configure: %d", rc);
    return;
  }
  // Flags + complete list of 128-bit service UUIDs (21 of 31 octets)
  uint8_t adv[21] = { 0x02, 0x01, 0x06, 0x11, 0x07 };
  memcpy(adv + 5, uuid_service.value, 16);
  const char *name = ble_svc_gap_device_name();
  uint8_t rsp[31];
  size_t nlen = strlen(name) > 29 ? 29 : strlen(name);
  rsp[0]      = (uint8_t) (nlen + 1);
  rsp[1]      = 0x09; // Complete Local Name
  memcpy(rsp + 2, name, nlen);
  struct os_mbuf *a = ble_hs_mbuf_from_flat(adv, sizeof(adv));
  struct os_mbuf *r = ble_hs_mbuf_from_flat(rsp, (uint16_t) (nlen + 2));
  if ((NULL == a) || (NULL == r) || ble_gap_ext_adv_set_data(ADV_INSTANCE_G1, a) ||
      ble_gap_ext_adv_rsp_set_data(ADV_INSTANCE_G1, r) || ble_gap_ext_adv_start(ADV_INSTANCE_G1, 0, 0)) {
    ESP_LOGE(TAG, "G1 advertising failed");
  }
#endif
}

static void
g1_update_security(uint16_t conn_handle)
{
  struct ble_gap_conn_desc desc;
  if (0 != ble_gap_conn_find(conn_handle, &desc)) {
    return;
  }
  uint8_t pairing = (desc.sec_state.encrypted && desc.sec_state.authenticated) ? VSCP_BLE_G1_PAIRING_AUTHENTICATED
                                                                               : VSCP_BLE_G1_PAIRING_NONE;
  uint8_t auth    = VSCP_BLE_G1_AUTH_NONE;
#if CONFIG_VSCP_BLE_G1_AUTHORIZE_BONDED
  if (pairing && desc.sec_state.bonded) {
    auth = VSCP_BLE_G1_AUTH_EVENT; // Demo policy, see Kconfig help
  }
#endif
  vscp_ble_g1_server_set_security(&g1, pairing, auth);
  ESP_LOGI(TAG,
           "Link security: encrypted %d authenticated %d bonded %d -> authorization %d",
           desc.sec_state.encrypted,
           desc.sec_state.authenticated,
           desc.sec_state.bonded,
           auth);
}

static int
gap_event(struct ble_gap_event *event, void *arg)
{
  (void) arg;
  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
      if (0 == event->connect.status) {
        g1_conn   = event->connect.conn_handle;
        ind_count = 0;
        ind_busy  = false;
        vscp_ble_g1_server_connected(&g1, ble_att_mtu(g1_conn));
        ESP_LOGI(TAG, "Connected; requesting LE Secure Connections pairing");
        ble_gap_security_initiate(g1_conn);
      }
      else {
        g1_advertise();
      }
      return 0;

    case BLE_GAP_EVENT_DISCONNECT:
      ESP_LOGI(TAG, "Disconnected (reason 0x%04x)", event->disconnect.reason);
      vscp_ble_g1_server_disconnected(&g1);
      g1_conn   = BLE_HS_CONN_HANDLE_NONE;
      ind_count = 0;
      ind_busy  = false;
      g1_advertise();
      return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
      if (ADV_INSTANCE_G1 == event->adv_complete.instance && BLE_HS_CONN_HANDLE_NONE == g1_conn) {
        g1_advertise();
      }
      return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
      g1_update_security(event->enc_change.conn_handle);
      return 0;

    case BLE_GAP_EVENT_MTU:
      vscp_ble_g1_server_set_mtu(&g1, event->mtu.value);
      return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
      if (event->subscribe.attr_handle == h_control) {
        vscp_ble_g1_server_set_control_indicate(&g1, event->subscribe.cur_indicate);
      }
      else if (event->subscribe.attr_handle == h_event_tx) {
        vscp_ble_g1_server_set_event_notify(&g1, event->subscribe.cur_notify);
      }
      return 0;

    case BLE_GAP_EVENT_NOTIFY_TX:
      // Indication confirmed (BLE_HS_EDONE) or failed: send the next one
      if (event->notify_tx.indication && (0 != event->notify_tx.status)) {
        ind_busy = false;
        ind_send_next();
      }
      return 0;

    case BLE_GAP_EVENT_PASSKEY_ACTION:
      if (BLE_SM_IOACT_DISP == event->passkey.params.action) {
        struct ble_sm_io pk = { .action = BLE_SM_IOACT_DISP, .passkey = esp_random() % 1000000 };
        ESP_LOGW(TAG, "Pairing passkey: %06lu", (unsigned long) pk.passkey);
        ble_sm_inject_io(event->passkey.conn_handle, &pk);
      }
      return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING: {
      // Forget the old bond and pair again
      struct ble_gap_conn_desc desc;
      if (0 == ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc)) {
        ble_store_util_delete_peer(&desc.peer_id_addr);
      }
      return BLE_GAP_REPEAT_PAIRING_RETRY;
    }

    default:
      return 0;
  }
}

// ---------------------------------------------------------------------------
//                             Measurements
// ---------------------------------------------------------------------------

static temperature_sensor_handle_t tsens;
static struct ble_npl_callout measure_timer;
static struct ble_npl_callout tick_timer;

// CLASS1.MEASUREMENT data: byte 0 = 0b101 (32-bit float) | unit 1 (Celsius) << 3
// | sensor index, then the IEEE 754 value, most significant byte first
static void
measurement_data(float celsius, uint8_t data[5])
{
  uint32_t u;
  memcpy(&u, &celsius, sizeof(u));
  data[0] = 0xA0 | (1 << 3) | 0;
  vscp_ble_put32(data + 1, u);
}

static void
measure(struct ble_npl_event *ev)
{
  (void) ev;
  float celsius = 0;
  if ((NULL == tsens) || (ESP_OK != temperature_sensor_get_celsius(tsens, &celsius))) {
    celsius = -273.15f; // Sensor missing: still show the transport working
  }
  uint8_t data[5];
  measurement_data(celsius, data);
  vscp_ble_event_t vev;
  memcpy(vev.guid, node_guid, 16);
  vev.head       = 0;
  vev.vscp_class = VSCP_CLASS1_MEASUREMENT;
  vev.vscp_type  = VSCP_TYPE_MEASUREMENT_TEMPERATURE;
  vev.size       = sizeof(data);
  vev.data       = data;

  uint8_t frame[VSCP_BLE_A2_MAX_SIZE];
  size_t len;
  uint32_t epoch, seq;
  int rv;

#if CONFIG_VSCP_BLE_SEND_E1
  rv = vscp_ble_counter_next(&e1_counter.counter, NULL, &seq);
  if ((VSCP_BLE_OK == rv) && (VSCP_BLE_OK == vscp_ble_e1_encode(frame, sizeof(frame), COMPANY_ID, seq, &vev, &len))) {
    ext_adv_publish(ADV_INSTANCE_E1, frame, len);
    ESP_LOGI(TAG, "E1 seq %lu: %.2f C", (unsigned long) seq, celsius);
  }
  else if (VSCP_BLE_OK != rv) {
    ESP_LOGE(TAG, "E1 stopped: %s", vscp_ble_strerror(rv));
  }
#endif

#if CONFIG_VSCP_BLE_SEND_A2
  if (a2_key.valid) {
    rv = vscp_ble_counter_next(&a2_counter.counter, &epoch, &seq);
    if (VSCP_BLE_OK == rv) {
      rv = vscp_ble_a2_encode(frame,
                              sizeof(frame),
                              COMPANY_ID,
                              a2_key.key_id,
                              epoch,
                              seq,
                              a2_key.key,
                              a2_key.prefix,
                              &vev,
                              &len);
    }
    if (VSCP_BLE_OK == rv) {
      ext_adv_publish(ADV_INSTANCE_A2, frame, len);
      ESP_LOGI(TAG, "A2 key %u epoch %lu seq %lu", a2_key.key_id, (unsigned long) epoch, (unsigned long) seq);
    }
    else {
      ESP_LOGE(TAG, "A2: %s (exhausted needs a new key)", vscp_ble_strerror(rv));
    }
  }
#endif

#if CONFIG_VSCP_BLE_G1
  if (BLE_HS_CONN_HANDLE_NONE != g1_conn) {
    rv = vscp_ble_g1_server_send_event(&g1, &vev);
    if (VSCP_BLE_ERR_STATE != rv) {
      ESP_LOGI(TAG, "G1 notify: %s", vscp_ble_strerror(rv));
    }
  }
#endif
  (void) epoch;
  ble_npl_callout_reset(&measure_timer, ble_npl_time_ms_to_ticks32(CONFIG_VSCP_BLE_EVENT_PERIOD_MS));
}

static void
g1_tick(struct ble_npl_event *ev)
{
  (void) ev;
  vscp_ble_g1_server_tick(&g1, now_ms());
  ble_npl_callout_reset(&tick_timer, ble_npl_time_ms_to_ticks32(1000));
}

// ---------------------------------------------------------------------------
//                                Startup
// ---------------------------------------------------------------------------

static void
on_sync(void)
{
  int rc = ble_hs_util_ensure_addr(0);
  assert(0 == rc);
  rc = ble_hs_id_infer_auto(0, &own_addr_type);
  assert(0 == rc);

  if (0 != ext_adv_configure(ADV_INSTANCE_E1, 1) || 0 != ext_adv_configure(ADV_INSTANCE_A2, 2)) {
    ESP_LOGE(TAG, "The controller has no LE extended advertising");
  }
  g1_advertise();

  ble_npl_callout_init(&measure_timer, nimble_port_get_dflt_eventq(), measure, NULL);
  ble_npl_callout_init(&tick_timer, nimble_port_get_dflt_eventq(), g1_tick, NULL);
  ble_npl_callout_reset(&measure_timer, ble_npl_time_ms_to_ticks32(1000));
  ble_npl_callout_reset(&tick_timer, ble_npl_time_ms_to_ticks32(1000));
}

static void
on_reset(int reason)
{
  ESP_LOGE(TAG, "BLE host reset, reason %d", reason);
}

static void
host_task(void *param)
{
  (void) param;
  nimble_port_run();
  nimble_port_freertos_deinit();
}

void
ble_store_config_init(void);

void
app_main(void)
{
  esp_err_t err = nvs_flash_init();
  if ((ESP_ERR_NVS_NO_FREE_PAGES == err) || (ESP_ERR_NVS_NEW_VERSION_FOUND == err)) {
    // Never erase silently: counters and bonds live here. Fail instead.
    ESP_LOGE(TAG, "NVS needs erasing (%s); refusing to reuse sequence numbers", esp_err_to_name(err));
    return;
  }
  ESP_ERROR_CHECK(err);

  // GUID from the factory MAC: FF:FF:FF:FF:FF:FF:FF:FE:<MAC>:00:00
  uint8_t mac[6];
  ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_BT));
  memset(node_guid, 0xFF, 7);
  node_guid[7] = 0xFE;
  memcpy(node_guid + 8, mac, 6);
  node_guid[14] = 0;
  node_guid[15] = 0;

  counter_load(&e1_counter, 0);
  counter_load(&a2_counter, 1);
  a2_key_load();
  ESP_LOGI(TAG,
           "vscp-ble %s, crypto %s, company 0x%04X%s",
           VSCP_BLE_LIB_VERSION_STR,
           vscp_ble_crypto_backend(),
           COMPANY_ID,
           (0xFFFF == COMPANY_ID) ? " (TEST ONLY)" : "");

  temperature_sensor_config_t tcfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
  if ((ESP_OK != temperature_sensor_install(&tcfg, &tsens)) || (ESP_OK != temperature_sensor_enable(tsens))) {
    tsens = NULL;
  }

  ESP_ERROR_CHECK(nimble_port_init());
  ble_hs_cfg.reset_cb        = on_reset;
  ble_hs_cfg.sync_cb         = on_sync;
  ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
  // LE Secure Connections, MITM (passkey on the console), bonding
  ble_hs_cfg.sm_io_cap         = BLE_HS_IO_DISPLAY_ONLY;
  ble_hs_cfg.sm_bonding        = 1;
  ble_hs_cfg.sm_mitm           = 1;
  ble_hs_cfg.sm_sc             = 1;
  ble_hs_cfg.sm_our_key_dist   = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
  ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

  ble_svc_gap_init();
  ble_svc_gatt_init();
  ESP_ERROR_CHECK(ble_svc_gap_device_name_set("VSCP BLE node"));
#if CONFIG_VSCP_BLE_G1
  vscp_ble_g1_server_init(&g1, &g1_ops, NULL, node_guid, VSCP_BLE_G1_MAX_DATA);
  ESP_ERROR_CHECK(ble_gatts_count_cfg(g1_service));
  ESP_ERROR_CHECK(ble_gatts_add_svcs(g1_service));
#endif
  ble_store_config_init();
  nimble_port_freertos_init(host_task);
}
