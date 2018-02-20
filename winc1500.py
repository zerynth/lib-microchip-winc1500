"""
.. module:: winc1500

***************
WINC1500 Module
***************

This module implements the winc1500 wifi driver. At the moment some functionalities are missing:

    * wifi ap mode
    * wifi direct p2p mode
    * internal firmware ota upgrade

It can be used to enable Arduino/Genuino MKR1000 wifi capabilities or with any other device mounting `Microchip WINC1500 IEEE 802.11 network controller <http://www.microchip.com/wwwproducts/en/ATWINC1500>`_.

Zerynth driver current implementation supports only communication with the chip through standard SPI interface.

.. note:: Zerynth driver is based on Microchip driver version 19.5.2 provided with Atmel Software Framework version 3.34.1 requiring the internal Firmware to be upgraded at least to version 19.5.2. For the upgrading procedure follow this guide: `Firmware Updater <https://www.arduino.cc/en/Tutorial/FirmwareUpdater>`_.


The WINC1500 chip supports secure connections through tls v1.2.
To take advantage of this feature import the ssl module or simply try https requests with Zerynth requests module.

.. note:: To access securely specific websites root certificates must be loaded on the chip: `Certificate Uploading <https://www.arduino.cc/en/Tutorial/FirmwareUpdater>`_.

To use the module expand on the following example: ::

    from microchip.winc1500 import winc1500 as wifi_driver
    from wireless import wifi

    wifi_driver.auto_init()
    for retry in range(10):
        try:
            wifi.link("Network-SSID", wifi.WIFI_WPA2, "password")
            break
        except Exception as e:
            print(e)

    if not wifi.is_linked():
        raise IOError

    """

import spi

drvinfo = None

def init(spidrv, cs, int_pin, rst, enable, wake = None, clock = 8000000):
    """
.. function:: init(spidrv, cs, int_pin, rst, enable, wake, clock)

To initialize the driver the following parameters are needed:

    * MCU SPI circuitry *spidrv* (one of SPI0, SPI1, ... check pinmap for details);
    * chip select pin *cs*;
    * interrupt pin *int_pin*;
    * reset pin *rst*;
    * enable pin *enable*;
    * wake pin *wake* (can be not set);
    * clock *clock*, default at 8MHz.

.. note:: For supported boards (e.g. Arduino/Genuino MKR1000), auto_init function is available with preset params.
    """
    global drvinfo
    if wake is None:
        wake = -1
    drvinfo = { 'drv': spidrv, 'cs': cs, 'clk': clock, 'int': int_pin }
    drvinfo.update({ 'rst': rst, 'enable': enable, 'wake': wake })
    __chip_init(spidrv,cs,int_pin,rst,enable,wake,clock,drvinfo)
    __builtins__.__default_net["wifi"] = __module__
    __builtins__.__default_net["sock"][0] = __module__ #AF_INET
    __builtins__.__default_net["ssl"] = __module__

def auto_init():
    if __defined(BOARD,"arduino_mkr1000"):
        init(SPI1, D26, D22, D27, D28, D29)
    elif __defined(BOARD,"adafruit_feather_m0wifi"):
        init(SPI0, D20, D24, D21, D23)
    else:
        raise UnsupportedError


@native_c("__chip_init", [
    "csrc/src/nm_bsp.c",
    "csrc/src/nm_bus_wrapper.c",
    "csrc/src/nm_common.c",
    "csrc/src/m2m_ate_mode.c",
    "csrc/src/m2m_crypto.c",
    "csrc/src/m2m_hif.c",
    "csrc/src/m2m_ota.c",
    "csrc/src/m2m_periph.c",
    "csrc/src/m2m_ssl.c",
    "csrc/src/m2m_wifi.c",
    "csrc/src/nmasic.c",
    "csrc/src/nmbus.c",
    "csrc/src/nmdrv.c",
    "csrc/src/nmi2c.c",
    "csrc/src/nmspi.c",
    "csrc/src/nmuart.c",
    "csrc/src/spi_flash.c",
    "csrc/src/socket.c",
    "csrc/winc.c"
], ["VHAL_SPI","__SAMD21G18AU__"],
[
    "-I.../csrc"
])
def __chip_init(spidrv,cs,int_pin,rst,enable,wake,clock,drvinfo):
    pass

# wifi

@native_c("winc_wifi_link",[],[])
def link(ssid,sec,password):
    pass

@native_c("winc_wifi_is_linked",[],[])
def is_linked():
    pass

@native_c("winc_wifi_gethostbyname",[],[])
def gethostbyname(hostname):
    pass

@native_c("winc_wifi_scan",[],[])
def scan(duration):
    pass

@native_c("winc_wifi_unlink",[],[])
def unlink():
    pass

@native_c("winc_wifi_link_info",[],[])
def __link_info():
    pass

def link_info():
    rr = __link_info()
    ip = '.'.join([ str(xx) for xx in rr[0]])
    return (ip, rr[1], rr[2], rr[3], rr[4])

def set_link_info(ip, mask, gw, dns):
    raise UnsupportedError

# socket

@native_c("winc_socket_socket",[],[])
def socket(family, type, proto):
    pass

@native_c("winc_socket_connect",[],[])
def connect(channel, address):
    pass


@native_c("winc_socket_send",[],[])
def send(channel, buffer, flags):
    pass

@native_c("winc_socket_sendall",[],[])
def sendall(channel, buffer, flags):
    pass

@native_c("winc_socket_recv_into",[],[])
def recv_into(channel, buffer, bufsize, flags, ofs = 0):
    pass

@native_c("winc_socket_bind",[],[])
def bind(channel, address):
    pass

@native_c("winc_socket_listen",[],[])
def listen(channel, maxlog):
    pass

@native_c("winc_socket_close",[],[])
def close(channel):
    pass

@native_c("winc_socket_recvfrom_into",[],[])
def recvfrom_into(channel, buffer, bufsize, flags):
    pass

@native_c("winc_socket_sendto",[],[])
def sendto(channel, buffer, address, flags):
    pass

@native_c("winc_socket_accept",[],[])
def accept(channel):
    pass

@native_c("winc_socket_setsockopt",[],[])
def setsockopt(channel, level, optname, value):
    pass

@native_c("winc_secure_socket",[],[])
def secure_socket(family, type, proto, flags):
    pass

# misc

@native_c("__get_chipid",[],[],[])
def __get_chipid():
    pass
