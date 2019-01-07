// SPDX-License-Identifier: GPL-2.0
/*
 * max44009.c - Support for MAX44009 Ambient Light Sensor
 *
 * Copyright (c) 2018 Robert Eshleman <bobbyeshleman@gmail.com>
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
 *
 */

#include <linux/bits.h>
#include <linux/i2c.h>
#include <linux/iio/buffer.h>
#include <linux/iio/events.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/iio/trigger.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/iio/triggered_buffer.h>
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
#define MAX44009_LO_NIBBLE(reg) ((reg)&0xf)

#define MAX44009_EXP_MASK 0xf00
#define MAX44009_EXP_RSHIFT 8
#define MAX44009_LUX_EXP(reg)	                                              \
	(1 << (((reg)&MAX44009_EXP_MASK) >> MAX44009_EXP_RSHIFT))
#define MAX44009_LUX_MANT(reg) ((reg)&0xff)

#define MAX44009_LUX(reg) (MAX44009_LUX_EXP(reg) * MAX44009_LUX_MANT(reg))

#define MAX44009_THRESH_MANT(reg) ((MAX44009_LO_NIBBLE(reg) << 4) + 15)
#define MAX44009_THRESHOLD(reg)                                                \
	((1 << MAX44009_HI_NIBBLE(reg)) * MAX44009_THRESH_MANT(reg))

#define MAX44009_IRQ_NAME "max44009_event"

static const int max44009_int_time_ns_array[] = {
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

static const int max44009_scale_avail_ulux_array[] = {45};
static const char max44009_scale_avail_str[] = "0.045";

struct max44009_data {
	struct mutex lock;
	struct i2c_client *client;
	struct iio_trigger *trigger;
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
	mutex_unlock(&data->lock);
	if (ret < 0) {
		pr_err("failed to read reg 0x%0x, err: %d\n", reg, ret);
		return ret;
	}
	return ret;
}

static int max44009_write_reg(struct max44009_data *data, char reg, char buf)
{
	struct i2c_client *client = data->client;
	int ret;

	mutex_lock(&data->lock);
	ret = i2c_smbus_write_byte_data(client, reg, buf);
	mutex_unlock(&data->lock);
	if (ret < 0) {
		dev_err(&client->dev,
			"failed to write reg 0x%0x, err: %d\n",
			reg, ret);
		return ret;
	}
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
		if (ret < 0) {
			dev_err(&data->client->dev, "failed to read configuration register\n");
			return ret;
		}
		ret &= ~MAX44009_INT_TIME_MASK;
		ret |= (int_time << MAX44009_INT_TIME_SHIFT);
		ret |= MAX44009_MANUAL_MODE_MASK;

		ret = max44009_write_reg(data, MAX44009_REG_CFG, ret);
		if (ret < 0) {
			dev_err(&client->dev->err, "failed to write configuration register\n");
			return ret;
		}

		return 0;
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

static int max44009_read_lux_raw(struct max44009_data *data)
{
	int ret;
	struct i2c_msg xfer[4];
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

	// Use i2c_transfer instead of smbus read because i2c_transfer
	// does NOT use a stop bit between address write and data read.
	// Using a stop bit causes disjoint upper/lower byte reads and
	// reduces accuracy
	mutex_lock(&data->lock);
	ret = i2c_transfer(data->client->adapter, xfer, 4);
	mutex_unlock(&data->lock);
	if (ret != 4)
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

	mantissa = thresh;
	exp = 0;
	while (mantissa > 0xff) {
		mantissa >>= 1;
		exp++;
	};
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
	int ret;

	reg = max44009_get_thr_reg(dir);
	if (reg < 0)
		return reg;

	thresh = max44009_thresh_byte_from_int(val);
	if (thresh < 0)
		return thresh;

	ret = max44009_write_reg(data, reg, thresh);
	if (ret < 0) {
		dev_err(&data->client->dev, "write register %d failed\n", reg);
		return ret;
	}
	return ret;
}

static int max44009_write_event_value(struct iio_dev *indio_dev,
				      const struct iio_chan_spec *chan,
				      enum iio_event_type type,
				      enum iio_event_direction dir,
				      enum iio_event_info info, int val,
				      int val2)
{
	switch (info) {
	case IIO_EV_INFO_VALUE:
		if (val2 != 0)
			return -EINVAL;

		if (chan->type != IIO_LIGHT)
			return -EINVAL;

		return max44009_write_thresh(indio_dev, dir, val);
	default:
		return -EINVAL;
	}

	return -EINVAL;
}

static int max44009_read_event_value(struct iio_dev *indio_dev,
				     const struct iio_chan_spec *chan,
				     enum iio_event_type type,
				     enum iio_event_direction dir,
				     enum iio_event_info info, int *val,
				     int *val2)
{
	int thresh, reg;
	struct max44009_data *data = iio_priv(indio_dev);

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	reg = max44009_get_thr_reg(dir);
	if (reg < 0)
		return reg;

	thresh = max44009_read_reg(data, reg);
	if (thresh < 0) {
		pr_err("max44009_read_reg() failed\n");
		return thresh;
	}

	*val = MAX44009_THRESHOLD(thresh);

	return IIO_VAL_INT;
}

static int max44009_write_event_config(struct iio_dev *indio_dev,
				       const struct iio_chan_spec *chan,
				       enum iio_event_type type,
				       enum iio_event_direction dir,
				       int state)
{
	struct max44009_data *data;
	int ret;

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	data = iio_priv(indio_dev);

	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, state);
	if (ret < 0) {
		pr_err("failed to write int enable register: %d\n", ret);
		return ret;
	}

	return 0;
}

static int max44009_read_event_config(struct iio_dev *indio_dev,
				      const struct iio_chan_spec *chan,
				      enum iio_event_type type,
				      enum iio_event_direction dir)
{
	struct max44009_data *data;
	int ret;

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	data = iio_priv(indio_dev);
	ret = max44009_read_reg(data, MAX44009_REG_ENABLE);
	if (ret < 0) {
		pr_err("failed to read int enable register: %d\n", ret);
		return ret;
	}

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

static int max44009_set_trigger_state(struct iio_trigger *trigger,
				      bool enable)
{
	struct iio_dev *indio_dev = iio_trigger_get_drvdata(trigger);
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, enable);
	if (ret < 0)
		pr_err("%s failed\n", __func__);

	return ret;
}

static const struct iio_trigger_ops max44009_trigger_ops = {
	.set_trigger_state = max44009_set_trigger_state,
};

static irqreturn_t max44009_trigger_handler(int irq, void *p)
{
	struct iio_dev *indio_dev = p;
	struct max44009_data *data = iio_priv(indio_dev);
	int lux, upper, lower;
	int ret;
	enum iio_event_direction direction;

	/* 32-bit for lux and 64-bit for timestamp */
	u32 buf[3] = {0};

	ret = max44009_read_reg(data, MAX44009_REG_STATUS);
	if (ret < 0) {
		dev_err(&data->client->dev, "failed to read interrupt status, err %d\n",
		    ret);
	}
	if (!ret)
		return IRQ_NONE;

	ret = max44009_read_reg(data, MAX44009_REG_ENABLE);
	if (ret < 0) {
		dev_err(&data->client->dev,
		    "failed to read interrupt enable register, err %d\n", ret);
	}
	if (!ret)
		return IRQ_NONE;

	/* Clear interrupt by disabling interrupt (see datasheet) */
	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, 0);
	if (ret < 0)
		dev_err(&data->client->dev,
			"failed clear interrupt, err %d\n",
			ret);

	lux = max44009_read_lux_raw(data);
	if (lux < 0)
		dev_err(&data->client->dev, "failed read lux, err %d\n", lux);

	/* Compare lux against thresholds */
	upper = max44009_read_reg(data, MAX44009_REG_UPPER_THR);
	if (upper < 0) {
		dev_err(&data->client->dev,
		    "failed to read upper thresh register, err %d\n", upper);
	}
	upper = MAX44009_THRESHOLD(upper);

	lower = max44009_read_reg(data, MAX44009_REG_LOWER_THR);
	if (lower < 0) {
		dev_err(&data->client->dev,
		    "failed to read lower thresh register, err %d\n", lower);
	}
	lower = MAX44009_THRESHOLD(lower);

	/* Exit handler if lux not out-of-bounds */
	if (lux < upper && lux > lower) {
		/* Re-enable interrupt */
		ret = max44009_write_reg(data, MAX44009_REG_ENABLE, 1);
		if (ret < 0) {
			dev_err(&data->client->dev,
				"failed to re-enable interrupt, err %d\n",
				ret);
		}
		return IRQ_NONE;
	}

	/* Push event for correct thresh direction */
	if (lux >= upper)
		direction = IIO_EV_DIR_RISING;
	else if (lux <= lower)
		direction = IIO_EV_DIR_FALLING;
	else
		return -EINVAL;

	/* Load buffer and notify trigger */
	buf[0] = lux;
	iio_push_to_buffers_with_timestamp(indio_dev, &buf, data->timestamp);
	iio_trigger_notify_done(data->trigger);

	iio_push_event(
	indio_dev,
	IIO_UNMOD_EVENT_CODE(IIO_LIGHT, 0, IIO_EV_TYPE_THRESH, direction),
	data->timestamp);

	/* Re-enable interrupt */
	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, 1);
	if (ret < 0)
		dev_err(&data->client->dev,
			"failed to re-enable interrupt, err %d\n",
			ret);

	return IRQ_HANDLED;
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
	mutex_init(&data->lock);
	indio_dev->dev.parent = &client->dev;
	indio_dev->info = &max44009_info;
	indio_dev->modes = INDIO_DIRECT_MODE;
	indio_dev->name = MAX44009_DRV_NAME;
	indio_dev->channels = max44009_channels;
	indio_dev->num_channels = ARRAY_SIZE(max44009_channels);

	/* Clear stale interrupt bit */
	ret = max44009_read_reg(data, MAX44009_REG_STATUS);
	if (ret < 0) {
		pr_err("failed to read ret register: %d\n", ret);
		return ret;
	}

	if (client->irq > 0) {
		ret = devm_request_threaded_irq(
		&client->dev, client->irq, max44009_irq_handler,
		max44009_trigger_handler, IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
		MAX44009_IRQ_NAME, indio_dev);

		if (ret < 0) {
			dev_err(&client->dev,
				"devm_request_threaded_irq() failed, irq %d, err: %d)\n",
				client->irq, ret);
			return ret;
		}

		ret = devm_iio_triggered_buffer_setup(&client->dev, indio_dev,
						      max44009_irq_handler,
						      max44009_trigger_handler,
						      NULL);
		if (ret < 0) {
			dev_err(&client->dev, "iio triggered buffer setup failed\n");
			return ret;
		}

		data->trigger = devm_iio_trigger_alloc(indio_dev->dev.parent,
						       "%s-dev%d",
						       indio_dev->name,
						       indio_dev->id);
		data->trigger->dev.parent = indio_dev->dev.parent;
		data->trigger->ops = &max44009_trigger_ops;
		iio_trigger_set_drvdata(data->trigger, indio_dev);

		ret = devm_iio_trigger_register(&client->dev, data->trigger);
		if (ret < 0) {
			pr_err("devm_iio_trigger_register() failed\n");
			return ret;
		}
	}

	return devm_iio_device_register(&client->dev, indio_dev);
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
	{ .compatible = "max,max44009" },
	{ }
};
MODULE_DEVICE_TABLE(of, max44009_of_match);

MODULE_AUTHOR("Robert Eshleman <bobbyeshleman@gmail.com>");
MODULE_LICENSE("GPL v2");
