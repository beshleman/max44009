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
 * TODO: Support ALS threshold interrupts, manual mode, continuous mode
 *
 * Default I2C address: 0x4a
 *
 */

#define TEST 1

#include <linux/module.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/regmap.h>
#include <linux/util_macros.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/iio/buffer.h>
#include <linux/iio/trigger.h>
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

/* CFG register masks */
#define MAX44009_CFG_CONT_MASK		     BIT(7)
#define MAX44009_CFG_MANUAL_MASK             BIT(6)
#define MAX44009_CFG_CDR_MASK                BIT(3)
#define MAX44009_CFG_TIM_MASK                (BIT(2) | BIT(2) | BIT(1))

/* CFG register shifts */
#define MAX44009_CFG_TIM_SHIFT 0

/* The maxmimum raw threshold for the max44009 */
#define MAX44009_MAXIMUM_THRESHOLD 8355840

#define MAX44009_LUX_SCALE 45

#define EXP(val) (((unsigned int) val) >> 4)
#define MANTISSA(val) ((((unsigned int) val) & 0xf) << 4)

#define MAX44009_HI_NIBBLE(luxreg) ((unsigned int) (((luxreg) >> 4) & 0xf))
#define MAX44009_LO_NIBBLE(luxreg) ((unsigned int) ((luxreg) & 0xf))

#define MAX44009_LUX_EXP(luxreg) (1 << EXP(MAX44009_HI_NIBBLE(luxreg)))
#define MAX44009_LUX_MANT(luxreg) (MANTISSA(MAX44009_HI_NIBBLE(luxreg)) | (MAX44009_LO_NIBBLE(luxreg)))

#define MAX44009_LUX(luxreg) \
	(MAX44009_LUX_EXP(luxreg) * \
	 MAX44009_LUX_MANT(luxreg))

#define MAX44009_THRESH_MANT(reg) ((MAX44009_LO_NIBBLE(reg) << 4) + 15)
#define MAX44009_THRESHOLD(reg) ((1 << MAX44009_HI_NIBBLE(reg)) * MAX44009_THRESH_MANT(reg))

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

static const int max44009_scale_avail_ulux_array[] = { MAX44009_LUX_SCALE };
static const char max44009_scale_avail_str[] = "0.045";

struct max44009_data {
	struct mutex lock;
	struct i2c_client *client;
	struct iio_trigger *trigger;
};

static const struct iio_event_spec max44009_event_spec[] = {
        {
                .type = IIO_EV_TYPE_THRESH,
                .dir = IIO_EV_DIR_RISING,
                .mask_separate = BIT(IIO_EV_INFO_VALUE),
        }, {
                .type = IIO_EV_TYPE_THRESH,
                .dir = IIO_EV_DIR_FALLING,
                .mask_separate = BIT(IIO_EV_INFO_VALUE),
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
			.realbits = 12,
			.storagebits = 16,
			.endianness = IIO_BE,
		},
		.event_spec = max44009_event_spec,
		.num_event_specs = ARRAY_SIZE(max44009_event_spec),
	},
};

static int max44009_read_reg(struct max44009_data *data, char reg)
{
	struct i2c_client *client = data->client;
	int ret;

	mutex_lock(&data->lock);
	ret = i2c_smbus_read_byte_data(client, reg);
	mutex_unlock(&data->lock);
	if (ret < 0) {
		dev_err(&client->dev, "failed to read reg 0x%0x, err: %d\n", reg,
			ret);
		return ret;
	}
	return ret;
}

static int max44009_write_reg(struct max44009_data *data, char reg, char buf)
{
	struct i2c_client *client = data->client;
	int ret;
	printk(KERN_ERR "wrote %d to reg %d\n", buf, reg);
	mutex_lock(&data->lock);
	ret = i2c_smbus_write_byte_data(client, reg, buf);
	mutex_unlock(&data->lock);
	if (ret < 0) {
		dev_err(&client->dev, "failed to write reg 0x%0x, err: %d\n", reg,
			ret);
		return ret;
	}
	printk(KERN_ERR "wrote %d to reg %d\n", buf, reg);
	return ret;
}

static int max44009_read_cfg(struct max44009_data *data, char *buf)
{
	return max44009_read_reg(data, MAX44009_REG_CFG);
}

static int max44009_read_int_time(struct max44009_data *data)
{
	char buf = 0;
	int ret = max44009_read_cfg(data, &buf);
	if (ret < 0)
		return ret;

	return max44009_int_time_ns_array[buf & 0x7];
}

static int max44009_write_raw(struct iio_dev *indio_dev,
			      struct iio_chan_spec const *chan,
			      int val, int val2, long mask)
{
	int ret, int_time;
	s64 ns;
	struct max44009_data *data = iio_priv(indio_dev);
	if (mask == IIO_CHAN_INFO_INT_TIME && chan->type == IIO_LIGHT) {
		ns = val * NSEC_PER_SEC + val2;
		int_time = find_closest_descending(ns,
				max44009_int_time_ns_array,
				ARRAY_SIZE(max44009_int_time_ns_array));
		
		ret = max44009_read_reg(data, MAX44009_REG_CFG);
		if (ret < 0) {
			dev_err(&data->client->dev, "failed to read configuration register\n");
			return ret;
		}

		ret = ret;

		/* Return if TIM is already the desired time */
		if (int_time == (ret & MAX44009_CFG_TIM_MASK)) {
			return IIO_VAL_INT;
		}

		/* Clear TIM field */
		ret &= ~MAX44009_CFG_TIM_MASK;

		/* Update with new integration time */
		ret |= (int_time <<  MAX44009_CFG_TIM_SHIFT);

		ret = max44009_write_reg(data, MAX44009_REG_CFG, ret);
		if (ret < 0) {
			dev_err(&data->client->dev, "failed to write configuration register\n");
			return ret;
		}

		return IIO_VAL_INT;
	}

	return -EINVAL;
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

static int max44009_read_lux_raw(struct max44009_data *data)
{
	int ret;
	struct i2c_msg xfer[4];
	u8 luxhireg[1] = { MAX44009_REG_LUX_HI };
	u8 luxloreg[1] = { MAX44009_REG_LUX_LO };
	u8 lo = 0;
	u8 hi = 0;
	
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

	/* Use i2c_transfer instead of smbus read because i2c_transfer
	 * does NOT use a stop bit between address write and data read.
	 * Using a stop bit causes disjoint upper/lower byte reads and
	 * reduces accuracy */
	mutex_lock(&data->lock);
	ret = i2c_transfer(data->client->adapter, xfer, 4);
	mutex_unlock(&data->lock);
	if (ret != 4)
		return -EIO;

#if TEST
	ret = max44009_read_reg(data, MAX44009_REG_STATUS);
	if (ret < 0) {
		dev_err(&data->client->dev, "max44009_read_reg() failed\n");
	}

	printk(KERN_ERR "REG_STATUS=%d\n", ret);
#endif


	return MAX44009_LUX(((hi & 0xff) << 4) | (lo & 0xf));
}

static int max44009_read_raw(struct iio_dev *indio_dev,
			     struct iio_chan_spec const *chan,
			     int *val, int *val2, long mask)
{
	struct max44009_data *data = iio_priv(indio_dev);
	int ret;

	printk(KERN_ERR "<%s>\n", __FUNCTION__);

	switch (mask) {
	case IIO_CHAN_INFO_RAW: {
		switch (chan->type) {
		case IIO_LIGHT: {
			*val = 0;
			*val2 = 0;
			ret = max44009_read_lux_raw(data);

			if (ret < 0)
				return ret;

			*val = ret;

			return IIO_VAL_INT;
		}
		default: {
			return -EINVAL;
		}
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

/**
 * max44009_thresh_byte_from_int - Returns the byte representation of an
 * integer threshold
 *
 * @thresh: The threshold as an int
 */
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
                               enum iio_event_direction dir,
                               int val)
{
        struct max44009_data *data = iio_priv(indio_dev);
	int thresh;
	int reg;
        int ret;

	reg = max44009_get_thr_reg(dir);
	if (reg < 0) {
		return reg;
	}
	
	thresh = max44009_thresh_byte_from_int(val);
	if (thresh < 0) {
		return thresh;
	}

	ret = max44009_write_reg(data, reg, thresh);
	if(ret < 0) {
		dev_err(&data->client->dev, "write register %d failed\n", reg);
		return ret;
	}
	return ret;
}

static int max44009_write_event_value(struct iio_dev *indio_dev,
                              const struct iio_chan_spec *chan,
                              enum iio_event_type type,
                              enum iio_event_direction dir,
                              enum iio_event_info info,
                              int val, int val2)
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

static int max44009_write_event_config(struct iio_dev *indio_dev,
                                     const struct iio_chan_spec *chan,
                                     enum iio_event_type type,
                                     enum iio_event_direction dir, int state)
{
        //struct max44009_data *data = iio_priv(indio_dev);
	printk(KERN_ERR "state=%d\n", state);

        switch (chan->type) {
        case IIO_INTENSITY:
                return 0;
        default:
                return -EINVAL;
        }

        return -EINVAL;
}

static int max44009_read_event_value(struct iio_dev *indio_dev,
        const struct iio_chan_spec *chan, enum iio_event_type type,
        enum iio_event_direction dir, enum iio_event_info info, int *val,
        int *val2)
{
	int thresh, reg;
        struct max44009_data *data = iio_priv(indio_dev);

	reg = max44009_get_thr_reg(dir);
	if (reg < 0) {
		return reg;
	}

	thresh = max44009_read_reg(data, reg);
	if (thresh < 0) {
		dev_err(&data->client->dev, "max44009_read_reg() failed\n");
		return thresh;
	}

	*val = MAX44009_THRESHOLD(thresh);

        return IIO_VAL_INT;
}

static int max44009_read_event_config(struct iio_dev *indio_dev,
        const struct iio_chan_spec *chan, enum iio_event_type type,
        enum iio_event_direction dir)
{
        struct max44009_data *data = iio_priv(indio_dev);
        int ret;
	printk(KERN_ERR "<%s>\n", __FUNCTION__);

        switch (dir) {
        case IIO_EV_DIR_RISING:
                mutex_lock(&data->lock);
                mutex_unlock(&data->lock);
                break;
        case IIO_EV_DIR_FALLING:
                mutex_lock(&data->lock);
                mutex_unlock(&data->lock);
                break;
        default:
                ret = -EINVAL;
                break;
        }

        return ret;
}


static const struct iio_info max44009_info = {
	.read_raw		= max44009_read_raw,
	.write_raw		= max44009_write_raw,
	.write_raw_get_fmt	= max44009_write_raw_get_fmt,
	.read_event_value       = max44009_read_event_value,
	.read_event_config      = max44009_read_event_config,
	.write_event_value      = max44009_write_event_value,
	.write_event_config     = max44009_write_event_config,
	.attrs			= &max44009_attribute_group,
};

static irqreturn_t max44009_trigger_handler(int irq, void *p)
{
	struct iio_poll_func *pf = p;
	struct iio_dev *indio_dev = pf->indio_dev;
	struct max44009_data *data = iio_priv(indio_dev);
	u16 buf[8];
	int ret;

	ret = max44009_read_lux_raw(data);

	if (ret < 0)
		return ret;
	
	buf[0] = ret;

	iio_push_to_buffers_with_timestamp(indio_dev, &buf, iio_get_time_ns(indio_dev));
	iio_trigger_notify_done(indio_dev->trig);
	return IRQ_HANDLED;
}

static int max44009_set_trigger_state(struct iio_trigger *trigger,
        bool enable)
{
        struct iio_dev *indio_dev = iio_trigger_get_drvdata(trigger);
        struct max44009_data *data = iio_priv(indio_dev);
        int ret;

	printk(KERN_ERR "<%s>\n", __FUNCTION__);

	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, enable);
	if(ret < 0)
                dev_err(&data->client->dev, "%s failed\n", __FUNCTION__);

        return ret;
}

static const struct iio_trigger_ops max44009_trigger_ops = {
        .set_trigger_state = max44009_set_trigger_state,
};

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
	data->client = client;
	i2c_set_clientdata(client, indio_dev);
	mutex_init(&data->lock);
	indio_dev->dev.parent = &client->dev;
	indio_dev->info = &max44009_info;
	indio_dev->name = MAX44009_DRV_NAME;
	indio_dev->channels = max44009_channels;
	indio_dev->num_channels = ARRAY_SIZE(max44009_channels);

	/* Clear stale interrupt bit */
	ret = max44009_read_reg(data, MAX44009_REG_STATUS);
	if (ret < 0) {
		dev_err(&client->dev, "failed to read ret register: %d\n", ret);
		return ret;
	}

	/* Enable interrupt */
	ret = max44009_write_reg(data, MAX44009_REG_ENABLE, 1);
	if (ret < 0) {
		dev_err(&client->dev, "failed to write int enable register: %d\n", ret);
		return ret;
	}


#if TEST
	/* Verify that the interrupt was enabled */
	ret = max44009_read_reg(data, MAX44009_REG_ENABLE);
	if (ret < 0) {
		dev_err(&client->dev, "failed to read int enable register: %d\n", ret);
		return ret;
	}

	printk(KERN_ERR "REG ENABLE = %d\n", ret);
#endif

	/* Set the threshold timer to 100ms */
	ret = max44009_write_reg(data, MAX44009_REG_THR_TIMER, 1);
	if (ret < 0) {
		dev_err(&client->dev, "failed to write threshold timer register: %d\n", ret);
		return ret;
	}

#if TEST
	/* Verify that the threshold timer wase set */
	ret = max44009_read_reg(data, MAX44009_REG_THR_TIMER);
	if (ret < 0) {
		dev_err(&client->dev, "failed to read int enable register: %d\n", ret);
		return ret;
	}

	printk(KERN_ERR "thresh timer = %d\n", ret);
#endif

	ret = iio_triggered_buffer_setup(indio_dev, NULL, max44009_trigger_handler, NULL);
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

	ret = devm_iio_trigger_register(indio_dev->dev.parent,
					   data->trigger);
	if (ret < 0) {
		dev_err(&client->dev, "devm_iio_trigger_register() failed\n");
		return ret;
	}

	return iio_device_register(indio_dev);
}

#if 0
static irqreturn_t vcnl4035_drdy_irq_thread(int irq, void *private)
{
        struct iio_dev *indio_dev = private;
        struct vcnl4035_data *data = iio_priv(indio_dev);

        if (vcnl4035_is_triggered(data)) {
                iio_push_event(indio_dev, IIO_UNMOD_EVENT_CODE(IIO_LIGHT,
                                                        0,
                                                        IIO_EV_TYPE_THRESH,
                                                        IIO_EV_DIR_EITHER),
                                iio_get_time_ns(indio_dev));
                iio_trigger_poll_chained(data->drdy_trigger0);
                return IRQ_HANDLED;
        }

        return IRQ_NONE;
}
#endif

static int max44009_remove(struct i2c_client *client)
{
	struct iio_dev *indio_dev = i2c_get_clientdata(client);
	iio_device_unregister(indio_dev);
	iio_triggered_buffer_cleanup(indio_dev);

	printk(KERN_ERR "removing....\n");
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

static const struct of_device_id max44009_of_match[] = {
	{ .compatible = "max,max44009" },
	{ }
};
MODULE_DEVICE_TABLE(of, max44009_of_match);

MODULE_AUTHOR("Robert Eshleman <bobbyeshleman@gmail.com>");
MODULE_LICENSE("GPL v2");
