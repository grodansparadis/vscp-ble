/*
 * VSCP BLE node for Nordic development kits (nRF Connect SDK 3.x)
 *
 *   west build -b nrf52840dk/nrf52840 examples/nordic
 *   west build -b nrf5340dk/nrf5340/cpuapp examples/nordic   (sysbuild adds ipc_radio)
 *   west build -b nrf54l15dk/nrf54l15/cpuapp examples/nordic
 *
 * Sends the die temperature (CLASS1.MEASUREMENT / TEMPERATURE) every
 * CONFIG_VSCP_NODE_PERIOD_MS over E1, A2 and G1.
 *
 *   Button 1  send CLASS1.INFORMATION BUTTON (pressed/released)
 *   Button 2  hold at reset: erase all bonds
 *   LED 1     blinks while advertising, on when connected
 *   LED 2     on when the central is authorized (G1 event access)
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include <dk_buttons_and_leds.h>
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
#define VSCP_CLASS1_INFORMATION           20
#define VSCP_TYPE_INFORMATION_BUTTON      1

#if DT_HAS_COMPAT_STATUS_OKAY(nordic_nrf_temp)
static const struct device *const temp_dev = DEVICE_DT_GET_ONE(nordic_nrf_temp);
#else
static const struct device *const temp_dev = NULL;
#endif

static volatile bool advertising;

static void
on_state(vscp_node_state_t state)
{
  switch (state) {
    case VSCP_NODE_ADVERTISING:
      advertising = true;
      break;
    case VSCP_NODE_CONNECTED:
      advertising = false;
      dk_set_led_on(DK_LED1);
      break;
    case VSCP_NODE_AUTHORIZED:
      dk_set_led_on(DK_LED2);
      break;
    case VSCP_NODE_DISCONNECTED:
      dk_set_led_off(DK_LED1);
      dk_set_led_off(DK_LED2);
      break;
    default:
      break;
  }
}

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

// Button events are sent from a work item (not the button callback)
static uint8_t button_state;
static void
button_work_handler(struct k_work *work)
{
  ARG_UNUSED(work);
  // CLASS1.INFORMATION data: index, zone, subzone (pressed = 1, released = 0 in index)
  uint8_t data[3] = { button_state, 0, 0 };
  vscp_node_send(VSCP_CLASS1_INFORMATION, VSCP_TYPE_INFORMATION_BUTTON, data, sizeof(data));
}
static K_WORK_DEFINE(button_work, button_work_handler);

static void
button_changed(uint32_t state, uint32_t has_changed)
{
  if (has_changed & DK_BTN1_MSK) {
    button_state = (state & DK_BTN1_MSK) ? 1 : 0;
    k_work_submit(&button_work);
  }
}

// Development GUID FF:FF:FF:FF:FF:FF:FF:FD + 8 octets of the FICR device
// id. Use a GUID from your own range in products.
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
  return -273.15f;
}

int
main(void)
{
  dk_leds_init();
  dk_buttons_init(button_changed);

  vscp_node_config_t cfg = {
    .company   = CONFIG_VSCP_NODE_COMPANY_ID,
    .on_state  = on_state,
    .on_event  = on_event,
    .authorize = authorize,
  };
  make_guid(cfg.guid);
  if (vscp_node_start(&cfg)) {
    return 0;
  }
  uint32_t buttons = 0;
  dk_read_buttons(&buttons, NULL);
  if (buttons & DK_BTN2_MSK) {
    LOG_WRN("Button 2 held: erasing all bonds");
    vscp_node_unpair_all();
  }

  int64_t next_measurement = k_uptime_get();
  for (unsigned blink = 0;; blink++) {
    if (advertising) {
      dk_set_led(DK_LED1, blink & 1);
    }
    if (k_uptime_get() >= next_measurement) {
      next_measurement += CONFIG_VSCP_NODE_PERIOD_MS;
      float celsius = read_temperature();
      uint32_t u;
      memcpy(&u, &celsius, sizeof(u));
      // Byte 0: 0b101 32-bit float | unit 1 (Celsius) << 3 | sensor 0
      uint8_t data[5] = { 0xA0 | (1 << 3), (uint8_t) (u >> 24), (uint8_t) (u >> 16), (uint8_t) (u >> 8), (uint8_t) u };
      vscp_node_send(VSCP_CLASS1_MEASUREMENT, VSCP_TYPE_MEASUREMENT_TEMPERATURE, data, sizeof(data));
    }
    k_sleep(K_MSEC(500));
  }
  return 0;
}
