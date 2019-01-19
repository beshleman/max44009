// SPDX-License-Identifier: GPL-2.0
/*
 * max44009.c - Support for MAX44009 Ambient Light Sensor
 *
 * Copyright (c) 2019 Robert Eshleman <bobbyeshleman@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *
 * Datasheet: https://datasheets.maximintegrated.com/en/ds/MAX44009.pdf
 *
 * TODO: Support continuous mode and processed event value (IIO_EV_INFO_VALUE)
 *
 * Default I2C address: 0x4a
 */

#include <linux/bits.h>
#include <linux/i2c.h>
#include <linux/iio/buffer.h>
#include <linux/iio/events.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/util_macros.h>

#define MAX44009_DRV_NAME "max44009"

/* Registers in datasheet order */
#define MAX44009_REG_STATUS 0x0
#define MAX44009_REG_ENABLE 0x1
#define MAX44009_REG_CFG 0x2
#define MAX44009_REG_LUX_HI 0x3
#define MAX44009_REG_LUX_LO 0x4
#define MAX44009_REG_UPPER_THR 0x5
#define MAX44009_REG_LOWER_THR 0x6
#define MAX44009_REG_THR_TIMER 0x7

#define MAX44009_INT_TIME_MASK (BIT(2) | BIT(1) | BIT(0))
#define MAX44009_INT_TIME_SHIFT (0)

#define MAX44009_MANUAL_MODE_MASK BIT(6)

/* The maxmimum raw rising threshold for the max44009 */
#define MAX44009_MAXIMUM_THRESHOLD 8355840

#define MAX44009_HI_NIBBLE(reg) (((reg) >> 4) & 0xf)
#define MAX44009_LO_NIBBLE(reg) ((reg) & 0xf)

#define MAX44009_EXP_MASK 0xf00
#define MAX44009_EXP_RSHIFT 8
#define MAX44009_LUX_EXP(reg)	                                              \
	(1 << (((reg) & MAX44009_EXP_MASK) >> MAX44009_EXP_RSHIFT))
#define MAX44009_LUX_MANT(reg) ((reg) & 0xff)

#define MAX44009_LUX(reg) (MAX44009_LUX_EXP(reg) * MAX44009_LUX_MANT(reg))

#define MAX44009_THRESH_MANT(reg) ((MAX44009_LO_NIBBLE(reg) << 4) + 15)
#define MAX44009_THRESHOLD(reg)                                                \
	((1 << MAX44009_HI_NIBBLE(reg)) * MAX44009_THRESH_MANT(reg))

static const u32 max44009_int_time_ns_array[] = {
	800000000,
	400000000,
	200000000,
	100000000,
	50000000, /* Manual mode only */
	25000000, /* Manual mode only */
	12500000, /* Manual mode only */
	6250000,  /* Manual mode only */
};

static const char max44009_int_time_str[] =
	"0.8 "
	"0.4 "
	"0.2 "
	"0.1 "
	"0.05 "
	"0.025 "
	"0.0125 "
	"0.00625";

static const u8 max44009_scale_avail_ulux_array[] = {45};
static const char max44009_scale_avail_str[] = "0.045";

struct max44009_data {
	struct i2c_client *client;
	struct mutex lock;
	int64_t timestamp;
};

static const struct iio_event_spec max44009_event_spec[] = {
	{
		.type = IIO_EV_TYPE_THRESH,
		.dir = IIO_EV_DIR_RISING,
		.mask_separate = BIT(IIO_EV_INFO_VALUE) |
				 BIT(IIO_EV_INFO_ENABLE),
	},
	{
		.type = IIO_EV_TYPE_THRESH,
		.dir = IIO_EV_DIR_FALLING,
		.mask_separate = BIT(IIO_EV_INFO_VALUE) |
				 BIT(IIO_EV_INFO_ENABLE),
	},
};

static const struct iio_chan_spec max44009_channels[] = {
	{
		.type = IIO_LIGHT,
		.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),
		.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_INT_TIME),
		.scan_index = 0,
		.scan_type = {
				.sign = 'u',
				.realbits = 24,
				.storagebits = 32,
			},
		.event_spec = max44009_event_spec,
		.num_event_specs = ARRAY_SIZE(max44009_event_spec),
	},
	IIO_CHAN_SOFT_TIMESTAMP(1),
};

static int max44009_read_reg(struct max44009_data *data, char reg)
{
	struct i2c_client *client = data->client;
	int ret;

	mutex_lock(&data->lock);
	ret = i2c_smbus_read_byte_data(client, reg);
	if (ret < 0) {
		dev_err(&client->dev,
			"failed to read reg 0x%0x, err: %d\n", reg, ret);
		goto err;
	}

err:
	mutex_unlock(&data->lock);
	return ret;
}

static int max44009_write_reg(struct max44009_data *data, char reg, char buf)
{
	struct i2c_client *client = data->client;
	int ret;

	mutex_lock(&data->lock);
	ret = i2c_smbus_write_byte_data(client, reg, buf);
	if (ret < 0) {
		dev_err(&client->dev,
			"failed to write reg 0x%0x, err: %d\n",
			reg, ret);
		goto err;
	}

err:
	mutex_unlock(&data->lock);
	return ret;
}

static int max44009_read_int_time(struct max44009_data *data)
{
	int ret = max44009_read_reg(data, MAX44009_REG_CFG);

	if (ret < 0)
		return ret;

	return max44009_int_time_ns_array[ret & MAX44009_INT_TIME_MASK];
}

static int max44009_write_raw(struct iio_dev *indio_dev,
			      struct iio_chan_spec const *chan, int val,
			      int val2, long mask)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret, int_time;
	s64 ns;

	if (mask == IIO_CHAN_INFO_INT_TIME && chan->type == IIO_LIGHT) {
		ns = val * NSEC_PER_SEC + val2;
		int_time = find_closest_descending(
				ns,
				max44009_int_time_ns_array,
				ARRAY_SIZE(max44009_int_time_ns_array));

		ret = max44009_read_reg(data, MAX44009_REG_CFG);
		if (ret < 0)
			return ret;

		ret &= ~MAX44009_INT_TIME_MASK;
		ret |= (int_time << MAX44009_INT_TIME_SHIFT);
		ret |= MAX44009_MANUAL_MODE_MASK;

		return max44009_write_reg(data, MAX44009_REG_CFG, ret);
	}
	return -EINVAL;
}

static int max44009_write_raw_get_fmt(struct iio_dev *indio_dev,
				      struct iio_chan_spec const *chan,
				      long mask)
{
	if (mask == IIO_CHAN_INFO_INT_TIME && chan->type == IIO_LIGHT)
		return IIO_VAL_INT_PLUS_NANO;
	else
		return IIO_VAL_INT;
}

#define READ_LUX_XFER_LEN (4)

static int max44009_read_lux_raw(struct max44009_data *data)
{
	int ret;
	struct i2c_msg xfer[READ_LUX_XFER_LEN];
	u8 luxhireg[1] = {MAX44009_REG_LUX_HI};
	u8 luxloreg[1] = {MAX44009_REG_LUX_LO};
	u8 lo = 0;
	u8 hi = 0;
	u16 reg = 0;

	xfer[0].addr = data->client->addr;
	xfer[0].flags = 0;
	xfer[0].len = 1;
	xfer[0].buf = luxhireg;

	xfer[1].addr = data->client->addr;
	xfer[1].flags = I2C_M_RD;
	xfer[1].len = 1;
	xfer[1].buf = &hi;

	xfer[2].addr = data->client->addr;
	xfer[2].flags = 0;
	xfer[2].len = 1;
	xfer[2].buf = luxloreg;

	xfer[3].addr = data->client->addr;
	xfer[3].flags = I2C_M_RD;
	xfer[3].len = 1;
	xfer[3].buf = &lo;

	/*
	 * Use i2c_transfer instead of smbus read because i2c_transfer
	 * does NOT use a stop bit between address write and data read.
	 * Using a stop bit causes disjoint upper/lower byte reads and
	 * reduces accuracy
	 */
	mutex_lock(&data->lock);
	ret = i2c_transfer(data->client->adapter, xfer, READ_LUX_XFER_LEN);
	mutex_unlock(&data->lock);
	if (ret != READ_LUX_XFER_LEN)
		return -EIO;

	reg = (((u16)hi) << 4) | (lo & 0xf);

	return MAX44009_LUX(reg);
}

static int max44009_read_raw(struct iio_dev *indio_dev,
			     struct iio_chan_spec const *chan, int *val,
			     int *val2, long mask)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	switch (mask) {
	case IIO_CHAN_INFO_RAW: {
		switch (chan->type) {
		case IIO_LIGHT: {
			ret = max44009_read_lux_raw(data);
			if (ret < 0)
				return ret;

			*val = ret;
			*val2 = 0;
			return IIO_VAL_INT;
		}
		default:
			return -EINVAL;
		}
		break;
	}

	case IIO_CHAN_INFO_INT_TIME: {
		ret = max44009_read_int_time(data);
		if (ret < 0)
			return ret;

		*val2 = ret;
		*val = 0;
		return IIO_VAL_INT_PLUS_NANO;
	}

	default:
		return -EINVAL;
	}
}

static IIO_CONST_ATTR(illuminance_scale_available, max44009_scale_avail_str);
static IIO_CONST_ATTR(illuminance_integration_time_available,
		      max44009_int_time_str);

static struct attribute *max44009_attributes[] = {
	&iio_const_attr_illuminance_integration_time_available.dev_attr.attr,
	&iio_const_attr_illuminance_scale_available.dev_attr.attr, NULL
};

static const struct attribute_group max44009_attribute_group = {
	.attrs = max44009_attributes,
};

static int max44009_thresh_byte_from_int(int thresh)
{
	int mantissa, exp;

	if (thresh < 0 || thresh > MAX44009_MAXIMUM_THRESHOLD)
		return -EINVAL;

	for (mantissa = thresh, exp = 0; mantissa > 0xff; exp++)
		mantissa >>= 1;

	mantissa >>= 4;
	mantissa &= 0xf;
	exp <<= 4;

	return exp | mantissa;
}

static int max44009_get_thr_reg(enum iio_event_direction dir)
{
	switch (dir) {
	case IIO_EV_DIR_RISING:
		return MAX44009_REG_UPPER_THR;
	case IIO_EV_DIR_FALLING:
		return MAX44009_REG_LOWER_THR;
	default:
		return -EINVAL;
	}
}

static int max44009_write_thresh(struct iio_dev *indio_dev,
				 enum iio_event_direction dir, int val)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int thresh;
	int reg;

	reg = max44009_get_thr_reg(dir);
	if (reg < 0)
		return reg;

	thresh = max44009_thresh_byte_from_int(val);
	if (thresh < 0)
		return thresh;

	return max44009_write_reg(data, reg, thresh);
}

static int max44009_write_event_value(struct iio_dev *indio_dev,
				      const struct iio_chan_spec *chan,
				      enum iio_event_type type,
				      enum iio_event_direction dir,
				      enum iio_event_info info,
				      int val, int val2)
{
	if (info != IIO_EV_INFO_VALUE || chan->type != IIO_LIGHT || val2 != 0)
		return -EINVAL;

	return max44009_write_thresh(indio_dev, dir, val);
}

static int max44009_read_event_value(struct iio_dev *indio_dev,
				     const struct iio_chan_spec *chan,
				     enum iio_event_type type,
				     enum iio_event_direction dir,
				     enum iio_event_info info,
				     int *val, int *val2)
{
	int thresh, reg;
	struct max44009_data *data = iio_priv(indio_dev);

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	reg = max44009_get_thr_reg(dir);
	if (reg < 0)
		return reg;

	thresh = max44009_read_reg(data, reg);
	if (thresh < 0)
		return thresh;

	*val = MAX44009_THRESHOLD(thresh);

	return IIO_VAL_INT;
}

static int max44009_write_event_config(struct iio_dev *indio_dev,
				       const struct iio_chan_spec *chan,
				       enum iio_event_type type,
				       enum iio_event_direction dir,
				       int state)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, state);
	if (ret < 0)
		return ret;

	/*
	 * Set device to trigger interrupt immediately upon exceeding
	 * the threshold limit
	 */
	ret = max44009_write_reg(data, MAX44009_REG_THR_TIMER, 0);
	if (ret < 0)
		return ret;

	return 0;
}

static int max44009_read_event_config(struct iio_dev *indio_dev,
				      const struct iio_chan_spec *chan,
				      enum iio_event_type type,
				      enum iio_event_direction dir)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	ret = max44009_read_reg(data, MAX44009_REG_ENABLE);
	if (ret < 0)
		return ret;

	return ret;
}

static const struct iio_info max44009_info = {
	.read_raw = max44009_read_raw,
	.write_raw = max44009_write_raw,
	.write_raw_get_fmt = max44009_write_raw_get_fmt,
	.read_event_value = max44009_read_event_value,
	.read_event_config = max44009_read_event_config,
	.write_event_value = max44009_write_event_value,
	.write_event_config = max44009_write_event_config,
	.attrs = &max44009_attribute_group,
};

static irqreturn_t max44009_thread_fn(int irq, void *p)
{
	struct iio_dev *indio_dev = p;
	struct max44009_data *data = iio_priv(indio_dev);
	int lux, upper, lower;
	int ret;
	enum iio_event_direction direction;

	/* 32-bit for lux and 64-bit for timestamp */
	u32 buf[3] = {0};

	ret = max44009_read_reg(data, MAX44009_REG_STATUS);
	if (ret <= 0)
		goto err;

	ret = max44009_read_reg(data, MAX44009_REG_ENABLE);
	if (ret <= 0)
		goto err;

	/* Clear interrupt by disabling interrupt (see datasheet) */
	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, 0);
	if (ret < 0)
		goto err;

	lux = max44009_read_lux_raw(data);
	if (lux < 0)
		goto err;

	upper = max44009_read_reg(data, MAX44009_REG_UPPER_THR);
	if (upper < 0)
		goto err;

	upper = MAX44009_THRESHOLD(upper);

	lower = max44009_read_reg(data, MAX44009_REG_LOWER_THR);
	if (lower < 0)
		goto err;

	lower = MAX44009_THRESHOLD(lower);

	/* If lux is NOT out-of-bounds then the interrupt was not triggered
	 * by this device
	 */
	if (lux < upper && lux > lower)
		goto err;

	/* Get event for correct thresh direction */
	if (lux >= upper)
		direction = IIO_EV_DIR_RISING;
	else if (lux <= lower)
		direction = IIO_EV_DIR_FALLING;
	else
		goto err;

	buf[0] = lux;
	iio_push_to_buffers_with_timestamp(indio_dev, &buf, data->timestamp);

	iio_push_event(indio_dev,
		       IIO_UNMOD_EVENT_CODE(IIO_LIGHT, 0,
					    IIO_EV_TYPE_THRESH, direction),
		       data->timestamp);

	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, 1);
	if (ret < 0)
		goto err;

	return IRQ_HANDLED;

err:
	/* Re-enable interrupt */
	max44009_write_reg(data, MAX44009_REG_ENABLE, 1);
	return IRQ_NONE;
}

static irqreturn_t max44009_irq_handler(int irq, void *p)
{
	struct iio_dev *indio_dev = p;
	struct max44009_data *data = iio_priv(indio_dev);

	data->timestamp = iio_get_time_ns(indio_dev);
	return IRQ_WAKE_THREAD;
}

static int max44009_probe(struct i2c_client *client,
			  const struct i2c_device_id *id)
{
	struct max44009_data *data;
	struct iio_dev *indio_dev;
	int ret;

	indio_dev = devm_iio_device_alloc(&client->dev, sizeof(*data));
	if (!indio_dev)
		return -ENOMEM;
	data = iio_priv(indio_dev);
	i2c_set_clientdata(client, indio_dev);
	data->client = client;
	indio_dev->dev.parent = &client->dev;
	indio_dev->info = &max44009_info;
	indio_dev->modes = INDIO_DIRECT_MODE;
	indio_dev->name = MAX44009_DRV_NAME;
	indio_dev->channels = max44009_channels;
	indio_dev->num_channels = ARRAY_SIZE(max44009_channels);
	mutex_init(&data->lock);

	/* Clear stale interrupt bit */
	ret = max44009_read_reg(data, MAX44009_REG_STATUS);
	if (ret < 0)
		goto err;

	if (client->irq > 0) {
		ret = devm_request_threaded_irq(&client->dev, client->irq,
						max44009_irq_handler,
						max44009_thread_fn,
						IRQF_TRIGGER_FALLING |
						IRQF_ONESHOT,
						"max44009_event", indio_dev);
		if (ret < 0)
			goto err;
	}

	ret = devm_iio_device_register(&client->dev, indio_dev);
	if (ret < 0)
		goto err;

	return 0;
err:
	mutex_destroy(&data->lock);
	return ret;
}

static const struct i2c_device_id max44009_id[] = {
	{ "max44009", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, max44009_id);

static struct i2c_driver max44009_driver = {
	.driver = {
		.name = MAX44009_DRV_NAME,
	},
	.probe = max44009_probe,
	.id_table = max44009_id,
};
module_i2c_driver(max44009_driver);

static const struct of_device_id max44009_of_match[] = {
	{ .compatible = "maxim,max44009" },
	{ }
};
MODULE_DEVICE_TABLE(of, max44009_of_match);

MODULE_AUTHOR("Robert Eshleman <bobbyeshleman@gmail.com>");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("MAX44009 ambient light sensor driver");
