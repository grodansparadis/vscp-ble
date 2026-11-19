///////////////////////////////////////////////////////////////////////////////
// File: vscp-ble-version.h
//

/* ******************************************************************************
 * VSCP (Very Simple Control Protocol)
 * https://www.vscp.org
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sub license, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

/*
  Version of the vscp-ble library: year.month.patch

    VSCP_BLE_LIB_VERSION_YEAR   Two digit year (26 = 2026)
    VSCP_BLE_LIB_VERSION_MONTH  Month 1-12
    VSCP_BLE_LIB_VERSION_PATCH  Push number within the month, from 0

  The values are updated automatically on every push to master by the
  "Update version" GitHub workflow (tools/update_version.py). Do not edit
  them by hand.

  This is the version of the library code. The versions of the transport
  formats (E1/A2/F1 frame versions, G1 protocol version) are on the wire
  and defined by the specification.

  VSCP_BLE_LIB_VERSION is one number for compile time checks:
  (year << 24) | (month << 16) | patch, e.g.

    #if VSCP_BLE_LIB_VERSION >= VSCP_BLE_LIB_VERSION_CODE(26, 11, 3)
    ...
    #endif
*/

#ifndef VSCP_BLE_VERSION_H
#define VSCP_BLE_VERSION_H

#define VSCP_BLE_LIB_VERSION_YEAR  26
#define VSCP_BLE_LIB_VERSION_MONTH 11
#define VSCP_BLE_LIB_VERSION_PATCH 2
#define VSCP_BLE_LIB_VERSION_STR   "26.11.2"
#define VSCP_BLE_LIB_VERSION       0x1A0B0002UL

// No casts so it also works in #if expressions
#define VSCP_BLE_LIB_VERSION_CODE(year, month, patch) (((year) * 0x1000000UL) + ((month) * 0x10000UL) + (patch))

#endif // VSCP_BLE_VERSION_H
