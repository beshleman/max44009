#!/bin/sh

rmmod max44009
insmod max44009.ko
echo "1" > /sys/bus/iio/devices/iio:device0/scan_elements/in_illuminance_en
cat /sys/bus/iio/devices/iio:device0/in_illuminance_raw
cat /sys/class/gpio/gpio49/value
