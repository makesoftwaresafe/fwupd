# Corsair

## Introduction

This plugin allows to update firmware on Corsair mice and receivers:

* SABRE RGB PRO WIRELESS
* SLIPSTREAM WIRELESS USB Receiver
* KATAR PRO WIRELESS
* KATAR PRO XT Gaming Mouse
* SABRE PRO Gaming Mouse

## Code structure

All devices handled by one object (FuCorsairDevice). Receivers with wireless-only
devices will be shown as two entities: parent device as a receiver and wireless
device as a child. Difference in behavior is handled by private flags.

FuCorsairBp contains low-level protocol related routines. Device objects should
call correct versions of these routines in order to update firmware. Correct
routines chosen by device quirsks and private flags.

## Wired mice update behavior

Mice and/or it's wireless adapter must be connected to host via USB cable
to apply an update. The device is switched to bootloader mode to flash
updates, and is reset automatically to new firmware after flashing.

## Wireless mice update behavior

The receiver should be connected to host and the mouse should be turned on
and not sleeping.

## Plugin-specific quirks

* CorsairVendorInterfaceId: some devices have non-standard USB interface
    for protocol communication. This quirk should be set if protocol interface is not 1.
* CorsairSubdeviceId: specifies ID of any wireless child device which can be updated.
    Polling will be turned on if a subdevice is not connected when parent is
    being probed.

## Plugin-specific flags

These flags will tweak code behavior for specific devices:

* legacy-attach: this flag is used if legacy attach command should be used
* no-version-in-bl: this flag handles cases if device reports incorrect firmware version
    in bootloader mode.
* is-subdevice: this flag tells device that it is a child device. All subdevice behavior
    tweaks will be applied.
