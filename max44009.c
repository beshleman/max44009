// SPDX-License-Identifier: GPL-2.0
/*
 * max44009.c - Support for MAX44009 Ambient Light Sensor
 *
 * Copyright (c) 2019 Robert Eshleman <bobbyeshleman@gmail.com>
 *
 * Datasheet: https://datasheets.maximintegrated.com/en/ds/MAX44009.pdf
 *
 * TODO: Support continuous mode and re-configuring from manual mode to
 * 	 automatic mode.
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

#define MAX44009_INT_TIME_MASK GENMASK(2, 0)

#define MAX44009_MANUAL_MODE_MASK BIT(6)

/* The maximum raw rising threshold for the max44009 */
#define MAX44009_MAXIMUM_THRESHOLD 8355840

#define MAX44009_THRESH_EXP_MASK (0xf << 4)
#define MAX44009_THRESH_MANT_LSHIFT 4
#define MAX44009_THRESH_MANT_MASK 0xf
#define MAX44009_RISING_THR_MINIMUM 15

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

struct max44009_data {
	struct i2c_client *client;
	struct mutex lock;
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
		.info_mask_separate = BIT(IIO_CHAN_INFO_RAW) |
				      BIT(IIO_CHAN_INFO_INT_TIME) |
				      BIT(IIO_CHAN_INFO_SCALE),
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

static int max44009_write_reg(struct max44009_data *data, char reg, char buf)
{
	struct i2c_client *client = data->client;
	int ret;

	ret = i2c_smbus_write_byte_data(client, reg, buf);
	if (ret < 0)
		dev_err(&client->dev,
			"failed to write reg 0x%0x, err: %d\n",
			reg, ret);
	return ret;
}

static int max44009_read_int_time(struct max44009_data *data)
{

	int ret = i2c_smbus_read_byte_data(data->client, MAX44009_REG_CFG);

	if (ret < 0)
		return ret;

	return max44009_int_time_ns_array[ret & MAX44009_INT_TIME_MASK];
}

static int max44009_write_int_time(struct max44009_data *data, int val, int val2)
{
	struct i2c_client *client = data->client;
	int ret, int_time, config;
	s64 ns;

	ns = val * NSEC_PER_SEC + val2;
	int_time = find_closest_descending(
			ns,
			max44009_int_time_ns_array,
			ARRAY_SIZE(max44009_int_time_ns_array));

	ret = i2c_smbus_read_byte_data(client, MAX44009_REG_CFG);
	if (ret < 0)
		return ret;

	config = ret;
	config &= int_time | ~MAX44009_INT_TIME_MASK;

	/* To set the integration time, the device must also be in manual mode. */
	config |= MAX44009_MANUAL_MODE_MASK;

	return i2c_smbus_write_byte_data(client, MAX44009_REG_CFG, config);
}

static int max44009_write_raw(struct iio_dev *indio_dev,
			      struct iio_chan_spec const *chan, int val,
			      int val2, long mask)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	if (mask == IIO_CHAN_INFO_INT_TIME && chan->type == IIO_LIGHT) {
		mutex_lock(&data->lock);
		ret = max44009_write_int_time(data, val, val2);
		mutex_unlock(&data->lock);
		return ret;
	}
	return -EINVAL;
}

static int max44009_write_raw_get_fmt(struct iio_dev *indio_dev,
				      struct iio_chan_spec const *chan,
				      long mask)
{
	return IIO_VAL_INT_PLUS_NANO;
}

static int max44009_lux_raw(u8 hi, u8 lo)
{
	int mantissa;
	int exponent;

	/*
	 * The mantissa consists of the low nibble of the Lux High Byte
	 * and the low nibble of the Lux Low Byte.
	 */
	mantissa = (hi & 0xf) << 4;
	mantissa |= lo & 0xf;

	/* The exponent byte is just the upper nibble of the Lux High Byte */
	exponent = (hi >> 4) & 0xf;

	/* 
	 * The exponent value is base 2 to the power of the raw exponent byte.
	 */
	exponent = 1 << exponent;

	return exponent * mantissa;
}

#define MAX44009_READ_LUX_XFER_LEN (4)

static int max44009_read_lux_raw(struct max44009_data *data)
{
	int ret;
	u8 hireg = MAX44009_REG_LUX_HI;
	u8 loreg = MAX44009_REG_LUX_HI;
	u8 lo = 0;
	u8 hi = 0;

	struct i2c_msg msgs[] = {
		{
			.addr = data->client->addr,
			.flags = 0,
			.len = sizeof(hireg),
			.buf = &hireg,
		},
		{
			.addr = data->client->addr,
			.flags = I2C_M_RD,
			.len = sizeof(hi),
			.buf = &hi,
		},
		{
			.addr = data->client->addr,
			.flags = 0,
			.len = sizeof(loreg),
			.buf = &loreg,
		},
		{
			.addr = data->client->addr,
			.flags = I2C_M_RD,
			.len = sizeof(lo),
			.buf = &lo,
		}
	};

	/*
	 * Use i2c_transfer instead of smbus read because i2c_transfer
	 * does NOT use a stop bit between address write and data read.
	 * Using a stop bit causes disjoint upper/lower byte reads and
	 * reduces accuracy
	 */
	ret = i2c_transfer(data->client->adapter, msgs, MAX44009_READ_LUX_XFER_LEN);
	if (ret != MAX44009_READ_LUX_XFER_LEN)
		return -EIO;

	return max44009_lux_raw(hi, lo);
}

static int max44009_read_raw(struct iio_dev *indio_dev,
			     struct iio_chan_spec const *chan, int *val,
			     int *val2, long mask)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		switch (chan->type) {
		case IIO_LIGHT:
			ret = max44009_read_lux_raw(data);
			if (ret < 0)
				return ret;

			*val = ret;
			*val2 = 0;
			return IIO_VAL_INT;
		default:
			return -EINVAL;
		}
	case IIO_CHAN_INFO_INT_TIME:
		switch (chan->type) {
		case IIO_LIGHT:
			ret = max44009_read_int_time(data);
			if (ret < 0)
				return ret;

			*val2 = ret;
			*val = 0;
			return IIO_VAL_INT_PLUS_NANO;
		default:
			return -EINVAL;
		}
	case IIO_CHAN_INFO_SCALE:
		switch (chan->type) {
		case IIO_LIGHT:
			*val = 45;
			*val2 = 1000;
			return IIO_VAL_FRACTIONAL;
			
		default:
			return -EINVAL;
		}
	default:
		return -EINVAL;
	}
}

static IIO_CONST_ATTR(illuminance_integration_time_available,
		      max44009_int_time_str);

static struct attribute *max44009_attributes[] = {
	&iio_const_attr_illuminance_integration_time_available.dev_attr.attr,
	NULL,
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

static int max44009_write_event_value(struct iio_dev *indio_dev,
				      const struct iio_chan_spec *chan,
				      enum iio_event_type type,
				      enum iio_event_direction dir,
				      enum iio_event_info info,
				      int val, int val2)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int reg, thresh;

	if (info != IIO_EV_INFO_VALUE || chan->type != IIO_LIGHT || val2 != 0)
		return -EINVAL;

	thresh = max44009_thresh_byte_from_int(val);
	if (thresh < 0)
		return thresh;

	reg = max44009_get_thr_reg(dir);
	if (reg < 0)
		return reg;

	return max44009_write_reg(data, reg, thresh);
}

static int max44009_read_thresh(struct iio_dev *indio_dev, enum iio_event_direction dir)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int threshbyte, reg;
	int mantissa, exponent;

	reg = max44009_get_thr_reg(dir);
	if (reg < 0)
		return reg;

	threshbyte = i2c_smbus_read_byte_data(data->client, reg);
	if (threshbyte < 0)
		return threshbyte;

	mantissa = threshbyte & MAX44009_THRESH_MANT_MASK;
	mantissa <<= MAX44009_THRESH_MANT_LSHIFT;

	/* 
	 * To get the upper thresh, always adds the minimum upper thresh value
	 * to the shifted byte value, see the datasheet.
	 */
	if (dir == IIO_EV_DIR_RISING)
		mantissa += MAX44009_RISING_THR_MINIMUM;

	/* Exponent is base 2 to the power of the thresh exponent byte value */
	exponent = 1 << (threshbyte & MAX44009_THRESH_EXP_MASK);

	return exponent * mantissa;
}

static int max44009_read_event_value(struct iio_dev *indio_dev,
				     const struct iio_chan_spec *chan,
				     enum iio_event_type type,
				     enum iio_event_direction dir,
				     enum iio_event_info info,
				     int *val, int *val2)
{
	int ret;

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	ret = max44009_read_thresh(indio_dev, dir);
	if (ret < 0)
		return ret;

	*val = ret;

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
	 * the threshold limit.
	 */
	return max44009_write_reg(data, MAX44009_REG_THR_TIMER, 0);
}

static int max44009_read_event_config(struct iio_dev *indio_dev,
				      const struct iio_chan_spec *chan,
				      enum iio_event_type type,
				      enum iio_event_direction dir)
{
	struct max44009_data *data = iio_priv(indio_dev);

	if (chan->type != IIO_LIGHT || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	return i2c_smbus_read_byte_data(data->client, MAX44009_REG_ENABLE);
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

static irqreturn_t max44009_threaded_irq_handler(int irq, void *p)
{
	struct iio_dev *indio_dev = p;
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	iio_push_event(indio_dev,
		       IIO_UNMOD_EVENT_CODE(IIO_LIGHT, 0,
					    IIO_EV_TYPE_THRESH, IIO_EV_DIR_EITHER),
		       iio_get_time_ns(indio_dev));

	ret = i2c_smbus_read_byte_data(data->client, MAX44009_REG_STATUS);
	if (ret < 0)
		dev_err(&data->client->dev, "failed to clear interrupt\n");

	return IRQ_HANDLED;
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

	/* Clear any stale interrupt bit */
	ret = i2c_smbus_read_byte_data(client, MAX44009_REG_CFG);
	if (ret < 0)
		return ret;

	if (client->irq > 0) {
		ret = devm_request_threaded_irq(&client->dev, client->irq,
						NULL,
						max44009_threaded_irq_handler,
						IRQF_TRIGGER_FALLING |
						IRQF_ONESHOT,
						"max44009_event",
						indio_dev);
		if (ret < 0)
			return ret;
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
	{ .compatible = "maxim,max44009" },
	{ }
};
MODULE_DEVICE_TABLE(of, max44009_of_match);

MODULE_AUTHOR("Robert Eshleman <bobbyeshleman@gmail.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("MAX44009 ambient light sensor driver");
