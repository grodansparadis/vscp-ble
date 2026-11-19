/*
 * VSCP BLE node for Zephyr - sends the die temperature as
 * CLASS1.MEASUREMENT / TEMPERATURE over E1, A2 and G1.
 *
 *   west build -b nrf52840dk/nrf52840 examples/zephyr
 *   west build -b esp32s3_devkitc/esp32s3/procpu examples/zephyr  (any BLE 5 board)
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include <zephyr/device.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "vscp-ble-g1.h"
#include "vscp_node.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

#define VSCP_CLASS1_MEASUREMENT           10
#define VSCP_TYPE_MEASUREMENT_TEMPERATURE 6

#if DT_NODE_HAS_STATUS(DT_ALIAS(die_temp0), okay)
static const struct device *const temp_dev = DEVICE_DT_GET(DT_ALIAS(die_temp0));
#else
static const struct device *const temp_dev = NULL;
#endif

static uint8_t
on_event(const vscp_ble_event_t *ev)
{
  // Validate the VSCP event and authorize it by class/type before acting
  LOG_INF("G1 event: class %u type %u, %u octets", ev->vscp_class, ev->vscp_type, ev->size);
  return VSCP_BLE_G1_OK;
}

static uint8_t
authorize(const void *peer)
{
  ARG_UNUSED(peer);
  return IS_ENABLED(CONFIG_VSCP_NODE_AUTHORIZE_BONDED) ? VSCP_BLE_G1_AUTH_EVENT : VSCP_BLE_G1_AUTH_NONE;
}

// Development GUID FF:FF:FF:FF:FF:FF:FF:FD + 8 octets of the chip id. Set a
// GUID from your own range in products.
static void
make_guid(uint8_t guid[16])
{
  uint8_t id[8] = { 0 };
  memset(guid, 0xFF, 7);
  guid[7] = 0xFD;
  hwinfo_get_device_id(id, sizeof(id));
  memcpy(guid + 8, id, 8);
}

static float
read_temperature(void)
{
  struct sensor_value v;
  if (temp_dev && device_is_ready(temp_dev) && !sensor_sample_fetch(temp_dev) &&
      !sensor_channel_get(temp_dev, SENSOR_CHAN_DIE_TEMP, &v)) {
    return (float) sensor_value_to_double(&v);
  }
  return -273.15f; // No sensor: still shows the transport working
}

int
main(void)
{
  vscp_node_config_t cfg = {
    .company   = CONFIG_VSCP_NODE_COMPANY_ID,
    .on_event  = on_event,
    .authorize = authorize,
  };
  make_guid(cfg.guid);
  if (vscp_node_start(&cfg)) {
    return 0;
  }

  for (;;) {
    float celsius = read_temperature();
    uint32_t u;
    memcpy(&u, &celsius, sizeof(u));
    // Byte 0: 0b101 32-bit float | unit 1 (Celsius) << 3 | sensor 0
    uint8_t data[5] = { 0xA0 | (1 << 3), (uint8_t) (u >> 24), (uint8_t) (u >> 16), (uint8_t) (u >> 8), (uint8_t) u };
    vscp_node_send(VSCP_CLASS1_MEASUREMENT, VSCP_TYPE_MEASUREMENT_TEMPERATURE, data, sizeof(data));
    k_sleep(K_MSEC(CONFIG_VSCP_NODE_PERIOD_MS));
  }
  return 0;
}
