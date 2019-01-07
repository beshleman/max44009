#!/bin/bash
rmmod max44009
insmod /home/debian/max44009.ko

echo "writing 100 to thresh rising"
echo "100" > /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value
sleep 1
cat /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value

sleep 1
echo "writing 1000 to thr rising"
echo "1000" > /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value
sleep 1
cat /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value


echo "TEST MAX THR"
sleep 1
echo "writing 8355840 to thr rising"
echo "8355840" > /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value
sleep 1
cat /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value

echo "TEST MIN THR"
sleep 1
echo "writing 15 to thr rising"
echo "15" > /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value
sleep 1
cat /sys/bus/iio/devices/iio\:device2/events/in_illuminance_thresh_rising_value

