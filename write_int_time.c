#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>

/**
 * read_sysfs_string() - read a string from file
 * @filename: name of file to read from
 * @basedir: the sysfs directory in which the file is to be found
 * @str: output the read string
 *
 * Returns a value >= 0 on success, otherwise a negative error code.
 **/
int read_sysfs_string(const char *filename, char *str)
{
	int ret = 0;
	FILE  *sysfsfp;

	sysfsfp = fopen(filename, "r");
	if (!sysfsfp) {
		ret = -errno;
		goto error_free;
	}

	errno = 0;
	if (fscanf(sysfsfp, "%s\n", str) != 1) {
		ret = errno ? -errno : -ENODATA;
		if (fclose(sysfsfp))
			perror("read_sysfs_string(): Failed to close dir");

		goto error_free;
	}

	if (fclose(sysfsfp))
		ret = -errno;

error_free:
	return ret;
}

static int write_sysfs_float(const char *filename, float val)
{
	int ret = 0;
	FILE *sysfsfp;
	int test;
	char *temp = malloc(strlen(filename) + 2);

	if (!temp)
		return -ENOMEM;

	sysfsfp = fopen(filename, "w");
	if (!sysfsfp) {
		ret = -errno;
		fprintf(stderr, "failed to open %s\n", filename);
		goto error_free;
	}

	ret = fprintf(sysfsfp, "%f", val);
	if (ret < 0) {
		if (fclose(sysfsfp))
			perror("_write_sysfs_int(): Failed to close dir");

		goto error_free;
	}

	if (fclose(sysfsfp)) {
		ret = -errno;
		goto error_free;
	}


error_free:
	free(temp);
}

static int write_sysfs_string(const char *filename, const char *val)
{
	int ret = 0;
	FILE *sysfsfp;
	int test;
	char *temp = malloc(strlen(filename) + 2);

	if (!temp)
		return -ENOMEM;

	sysfsfp = fopen(filename, "w");
	if (!sysfsfp) {
		ret = -errno;
		fprintf(stderr, "failed to open %s\n", filename);
		goto error_free;
	}

#if 1
	ret = fprintf(sysfsfp, "%s", val);
	if (ret < 0) {
		if (fclose(sysfsfp))
			perror("_write_sysfs_int(): Failed to close dir");

		goto error_free;
	}
#endif

	if (fclose(sysfsfp)) {
		ret = -errno;
		goto error_free;
	}


error_free:
	free(temp);
}


static int write_sysfs_int(const char *filename, int val)
{
	int ret = 0;
	FILE *sysfsfp;
	int test;
	char *temp = malloc(strlen(filename) + 2);

	if (!temp)
		return -ENOMEM;

	sysfsfp = fopen(filename, "w");
	if (!sysfsfp) {
		ret = -errno;
		fprintf(stderr, "failed to open %s\n", filename);
		goto error_free;
	}

	ret = fprintf(sysfsfp, "%d", val);
	if (ret < 0) {
		if (fclose(sysfsfp))
			perror("_write_sysfs_int(): Failed to close dir");

		goto error_free;
	}

	if (fclose(sysfsfp)) {
		ret = -errno;
		goto error_free;
	}


error_free:
	free(temp);
}


int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("No time passed as arg\n");
		return -1;
	}
	char int_time_filename[] = "/sys/bus/iio/devices/iio:device0/in_illuminance_integration_time";
	char buf[128] = {'\0'};
	
	char *int_time = argv[1];
	int ret;

	ret = read_sysfs_string(int_time_filename, buf);
	if (ret < 0) {
		printf("read sysfs failed\n");
		return ret;
	}
	printf("before: int_time=%s\n", buf);
	printf("target time: %s\n", int_time);

	ret = write_sysfs_string(int_time_filename, int_time);
	if (ret < 0)
		printf("write sys fs int failed\n");

	ret = read_sysfs_string(int_time_filename, buf);
	if (ret < 0) {
		printf("read sysfs failed\n");
		return ret;
	}
	printf("after: int_time=%s\n", buf);

	return ret;
}
