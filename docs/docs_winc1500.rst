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

    
.. function:: init(spidrv, cs, int_pin, rst, enable, wake, clock)

To initialize the driver the following parameters are needed:

    * MCU SPI circuitry *spidrv* (one of SPI0, SPI1, ... check pinmap for details);
    * chip select pin *cs*;
    * interrupt pin *int_pin*;
    * reset pin *rst*;
    * enable pin *enable*;
    * wake pin *wake*;
    * clock *clock*, default at 8MHz.

.. note:: For supported boards (e.g. Arduino/Genuino MKR1000), auto_init function is available with preset params.
    
