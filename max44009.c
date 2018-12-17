/*
 * max44009.c - Support for MAX44009 Ambient Light Sensor
 *
 * Copyright (c) 2018 Robert Eshleman <bobbyeshleman@gmail.com>
 *
 * Datasheet: https://datasheets.maximintegrated.com/en/ds/MAX44009.pdf
 *
 * TODO: Support ALS threshold interrupts, threshold configuration,
 *	 manual mode, continuous mode
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/regmap.h>
#include <linux/util_macros.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/iio/buffer.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/iio/triggered_buffer.h>
#include <linux/bits.h>

#define MAX44009_DRV_NAME		"max44009"

/* Registers in datasheet order */
#define MAX44009_REG_STATUS		0x0
#define MAX44009_REG_ENABLE		0x1
#define MAX44009_REG_CFG		0x2
#define MAX44009_REG_LUX_HI		0x3
#define MAX44009_REG_LUX_LO		0x4
#define MAX44009_REG_UPPER_THR		0x5
#define MAX44009_REG_LOWER_THR		0x6
#define MAX44009_REG_THR_TIMER		0x7

/* REG_CFG Bits */
#define MAX44009_CFG_CONT	        BIT(7)
#define MAX44009_CFG_MANUAL             BIT(6)
#define MAX44009_CFG_CDR                BIT(3)
#define MAX44009_CFG_TIM                0x7

#define MAX44009_LUX_SCALE 45

#define EXP(val) (((unsigned int) val) >> 4)
#define MANTISSA(val) ((((unsigned int) val) & 0xf) << 4)

#define MAX44009_LUX_EXP(hi) (1 << EXP(hi))
#define MAX44009_LUX_MANT(hi, lo) (MANTISSA(hi) | (lo & 0x0f))
#define MAX44009_LUX(hi, lo) (MAX44009_LUX_EXP(hi) * MAX44009_LUX_MANT(hi, lo))

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

static const int max44009_scale_avail_ulux_array[] = { MAX_LUX_SCALE };
static const char max44009_scale_avail_str[] = "0.045";

struct max44009_data {
	struct mutex lock;
	struct i2c_client *client;
};

static const struct iio_chan_spec max44009_channels[] = {
	{
		.type = IIO_LIGHT,
		.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),
		.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE) |
					    BIT(IIO_CHAN_INFO_INT_TIME),
		.scan_index = 0,
		.scan_type = {
			.sign		= 'u',
			.realbits	= 12,
			.storagebits	= 16,
		}
	},
};

static int max44009_read_reg(struct max44009_data *data, char reg, char *buf)
{
	struct i2c_client *client = data->client;
	int ret;

	ret = i2c_master_send(client, &reg, 1);
	if (ret) {
		dev_err(&client->dev, "failed to write reg 0x%0x, err: %d\n", reg,
			ret);
		return ret;
	}

	ret = i2c_master_recv(client, buf, 1)
	if (ret) {
		dev_err(&client->dev, "failed to read reg 0x%0x, err: %d\n", reg,
			ret);
	}
	return ret;
}

static int max44009_read_hi_thr(struct max44009_data *data)
{
	char buf = 0;
	unsigned int exp; 
	unsigned int mantissa;

	int ret = max44009_read_reg(data, MAX44009_REG_UPPER_THR, &buf); 
	if (ret < 0)
		return ret;

	exp = EXP(buf);
	mantissa = MANTISSA(buf);

	return (1 << exp) * mantissa;
}

static int max44009_write_hi_thr(struct max44009_data *data, int val)
{
#if 0
	return regmap_write_bits(data->regmap, MAX44009_REG_CFG_RX,
				 MAX44009_CFG_RX_ALSTIM_MASK,
				 val << MAX44009_CFG_RX_ALSTIM_SHIFT);
#else
	return 0;
#endif
}

static int max44009_read_cfg(struct max44009_data *data, char *buf)
{
	return max44009_read_reg(data, MAX44009_REG_CFG, buf);
}

static int max44009_read_int_time(struct max44009_data *data)
{
	char buf = 0;
	int ret = max44009_read_cfg(data, &buf);
	if (ret < 0)
		return ret;

	return max44009_int_time_ns_array[buf & 0x7];
}

static int max44009_read_lo_thr(struct max44009_data *data)
{
	unsigned int exp;
	unsigned int mantissa;
	char buf = 0;

	int ret = max44009_read_reg(data, MAX44009_LO_THR, &buf);
	if (ret < 0)
		return ret;

	exp = EXP(buf);
	mantissa = MANTISSA(buf);

	return (1 << exp) * mantissa;
}

static int max44009_write_lo_thr(struct max44009_data *data, int val)
{
#if 0
	return regmap_write_bits(data->regmap, MAX44009_REG_CFG_RX,
				 MAX44009_CFG_RX_ALSPGA_MASK,
				 val << MAX44009_CFG_RX_ALSPGA_SHIFT);
#else
	return 0;
#endif
}

static int max44009_read_raw(struct iio_dev *indio_dev,
			     struct iio_chan_spec const *chan,
			     int *val, int *val2, long mask)
{
	struct max44009_data *data = iio_priv(indio_dev);
	char regval = 0;
	int ret;

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		switch (chan->type) {
		case IIO_LIGHT:
			mutex_lock(&data->lock);
			ret = max44009_read_lux(data->client, val);
			mutex_unlock(&data->lock);
			if (ret)
				return ret;
			return IIO_VAL_INT;
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

	case IIO_CHAN_INFO_INT_TIME: {
		mutex_lock(&data->lock);
		ret = max44009_read_int_time(data, val2);
		mutex_unlock(&data->lock);
		if (ret)
			return ret;

		*val = 0;
		return IIO_VAL_INT_PLUS_NANO;
	}

	default:
		return -EINVAL;
	}
}

static int max44009_write_raw(struct iio_dev *indio_dev,
			      struct iio_chan_spec const *chan,
			      int val, int val2, long mask)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

#if 0
	if (mask == IIO_CHAN_INFO_INT_TIME && chan->type == IIO_LIGHT) {
		s64 valns = val * NSEC_PER_SEC + val2;
		int alstim = find_closest_descending(valns,
				max44009_int_time_ns_array,
				ARRAY_SIZE(max44009_int_time_ns_array));
		mutex_lock(&data->lock);
		ret = max44009_write_hi_thr(data, alstim);
		mutex_unlock(&data->lock);
		return ret;
	} else if (mask == IIO_CHAN_INFO_SCALE && chan->type == IIO_LIGHT) {
		s64 valus = val * USEC_PER_SEC + val2;
		int alspga = find_closest(valus,
				max44009_scale_avail_ulux_array,
				ARRAY_SIZE(max44009_scale_avail_ulux_array));
		mutex_lock(&data->lock);
		ret = max44009_write_lo_thr(data, alspga);
		mutex_unlock(&data->lock);
		return ret;
	}


	return -EINVAL;
#endif
	return 0;
}

static int max44009_write_raw_get_fmt(struct iio_dev *indio_dev,
				      struct iio_chan_spec const *chan,
				      long mask)
{
	if (mask == IIO_CHAN_INFO_INT_TIME && chan->type == IIO_LIGHT)
		return IIO_VAL_INT_PLUS_NANO;
	else if (mask == IIO_CHAN_INFO_SCALE && chan->type == IIO_LIGHT)
		return IIO_VAL_INT_PLUS_MICRO;
	else
		return IIO_VAL_INT;
}

static IIO_CONST_ATTR(illuminance_integration_time_available, max44009_int_time_str);
static IIO_CONST_ATTR(illuminance_scale_available, max44009_scale_avail_str);

static struct attribute *max44009_attributes[] = {
	&iio_const_attr_illuminance_integration_time_available.dev_attr.attr,
	&iio_const_attr_illuminance_scale_available.dev_attr.attr,
	NULL
};

static const struct attribute_group max44009_attribute_group = {
	.attrs = max44009_attributes,
};

static const struct iio_info max44009_info = {
	.read_raw		= max44009_read_raw,
	.write_raw		= max44009_write_raw,
	.write_raw_get_fmt	= max44009_write_raw_get_fmt,
	.attrs			= &max44009_attribute_group,
};

static irqreturn_t max44009_trigger_handler(int irq, void *p)
{
#if 0
	struct iio_poll_func *pf = p;
	struct iio_dev *indio_dev = pf->indio_dev;
	struct max44009_data *data = iio_priv(indio_dev);
	u16 buf[8]; /* 2x u16 + padding + 8 bytes timestamp */
	int index = 0;
	unsigned int regval;
	int ret;

	mutex_lock(&data->lock);
	if (test_bit(MAX44009_SCAN_INDEX_ALS, indio_dev->active_scan_mask)) {
		ret = max44009_read_alsval(data);
		if (ret < 0)
			goto out_unlock;
		buf[index++] = ret;
	}
	if (test_bit(MAX44009_SCAN_INDEX_PRX, indio_dev->active_scan_mask)) {
		ret = regmap_read(data->regmap, MAX44009_REG_PRX_DATA, &regval);
		if (ret < 0)
			goto out_unlock;
		buf[index] = regval;
	}
	mutex_unlock(&data->lock);

	iio_push_to_buffers_with_timestamp(indio_dev, buf,
					   iio_get_time_ns(indio_dev));
	iio_trigger_notify_done(indio_dev->trig);
	return IRQ_HANDLED;

out_unlock:
	mutex_unlock(&data->lock);
	iio_trigger_notify_done(indio_dev->trig);
	return IRQ_HANDLED;
#endif
	return IRQ_HANDLED;
}



static int max44009_read_lux(struct i2c_client *client,
			     int *lux)
{
	int ret;
	struct i2c_msg xfer[4];
	u8 luxhireg[1] = { MAX44009_REG_LUX_HI };
	u8 luxloreg[1] = { MAX44009_REG_LUX_LO };
	u8 lo = 0;
	u8 hi = 0;
	
	xfer[0].addr = client->addr;
	xfer[0].flags = 0;
	xfer[0].len = 1
	xfer[0].buf = luxhireg;

	xfer[1].addr = client->addr;
	xfer[1].flags = I2C_M_RD;
	xfer[1].len = 1
	xfer[1].buf = &hi;
	
	xfer[2].addr = client->addr;
	xfer[2].flags = 0;
	xfer[2].len = 1
	xfer[2].buf = luxloreg;

	xfer[3].addr = client->addr;
	xfer[3].flags = I2C_M_RD;
	xfer[3].len = 1
	xfer[3].buf = &lo;

	ret = i2c_transfer(&client->adapter, xfer, 4);
	if (!ret)
		*lux = MAX44009_LUX(luxbuf[0], luxbuf[1]);

	return ret;
}

static int max44009_probe(struct i2c_client *client,
			  const struct i2c_device_id *id)
{
	struct max44009_data *data;
	struct iio_dev *indio_dev;
	int ret, reg;
	int lux = 0;

	indio_dev = devm_iio_device_alloc(&client->dev, sizeof(*data));
	if (!indio_dev)
		return -ENOMEM;
	data = iio_priv(indio_dev);
	data->client = client;
	i2c_set_clientdata(client, indio_dev);
	mutex_init(&data->lock);
	indio_dev->dev.parent = &client->dev;
	indio_dev->info = &max44009_info;
	indio_dev->name = MAX44009_DRV_NAME;
	indio_dev->channels = max44009_channels;
	indio_dev->num_channels = ARRAY_SIZE(max44009_channels);

	/* Read lux level */
	mutex_lock(&data->lock);
	ret = max44009_read_lux(client, &lux);
	mutex_unlock(&data->lock);
	if (ret < 0) {
		dev_err(&client->dev, "failed to read lux: %d\n",
			ret);
		return ret;
	}
	dev_dbg(&client->dev, "lux: %d\n", lux);

#if 0
	/* Reset ALS scaling bits */
	ret = regmap_write(data->regmap, MAX44009_REG_CFG_RX,
			   MAX44009_REG_CFG_RX_DEFAULT);
	if (ret < 0) {
		dev_err(&client->dev, "failed to write default CFG_RX: %d\n",
			ret);
		return ret;
	}

	/* Reset CFG bits to ALS_PRX mode which allows easy reading of both values. */
	reg = MAX44009_CFG_TRIM | MAX44009_CFG_MODE_ALS_PRX;
	ret = regmap_write(data->regmap, MAX44009_REG_CFG_MAIN, reg);
	if (ret < 0) {
		dev_err(&client->dev, "failed to write init config: %d\n", ret);
		return ret;
	}

	/* Read status at least once to clear any stale interrupt bits. */
	ret = regmap_read(data->regmap, MAX44009_REG_STATUS, &reg);
	if (ret < 0) {
		dev_err(&client->dev, "failed to read init status: %d\n", ret);
		return ret;
	}

	ret = iio_triggered_buffer_setup(indio_dev, NULL, max44009_trigger_handler, NULL);
	if (ret < 0) {
		dev_err(&client->dev, "iio triggered buffer setup failed\n");
		return ret;
	}
#endif
	return iio_device_register(indio_dev);
}

static int max44009_remove(struct i2c_client *client)
{
	struct iio_dev *indio_dev = i2c_get_clientdata(client);

	iio_device_unregister(indio_dev);
#if 0
	iio_triggered_buffer_cleanup(indio_dev);
#endif

	return 0;
}

static const struct i2c_device_id max44009_id[] = {
	{"max44009", 0},
	{ }
};
MODULE_DEVICE_TABLE(i2c, max44009_id);

static struct i2c_driver max44009_driver = {
	.driver = {
		.name	= MAX44009_DRV_NAME,
	},
	.probe		= max44009_probe,
	.remove		= max44009_remove,
	.id_table	= max44009_id,
};
module_i2c_driver(max44009_driver);

MODULE_AUTHOR("Robert Eshleman <bobbyeshleman@gmail.com>");
MODULE_DESCRIPTION("MAX44009 Ambient Light Sensor");
MODULE_LICENSE("GPL v2");
