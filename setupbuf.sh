#!/bin/sh

echo "1" > /sys/bus/iio/devices/iio\:device0/scan_elements/in_illuminance_en
cat /sys/bus/iio/devices/trigger0/name > /sys/bus/iio/devices/iio:device0/trigger/current_trigger
