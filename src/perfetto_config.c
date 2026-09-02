// SPDX-License-Identifier: MulanPSL-2.0

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "perfetto_config.h"

#define MAX_CUSTOM_CONFIG_BYTES (4U * 1024U * 1024U)

enum scan_state {
	SCAN_NORMAL,
	SCAN_STRING,
	SCAN_LINE_COMMENT,
	SCAN_BLOCK_COMMENT,
};

static int write_all(int fd, const void *data, size_t size)
{
	const unsigned char *cursor = data;

	while (size) {
		ssize_t written = write(fd, cursor, size);

		if (written > 0) {
			cursor += written;
			size -= written;
			continue;
		}
		if (written < 0 && errno == EINTR)
			continue;
		return errno ? -errno : -EIO;
	}
	return 0;
}

static int read_config(const char *path, char **text, size_t *size)
{
	struct stat status;
	char *buffer;
	size_t offset = 0;
	int fd, err = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &status)) {
		err = -errno;
		goto out;
	}
	if (!S_ISREG(status.st_mode)) {
		err = -EINVAL;
		goto out;
	}
	if (status.st_size <= 0) {
		err = -ENODATA;
		goto out;
	}
	if ((uint64_t)status.st_size > MAX_CUSTOM_CONFIG_BYTES) {
		err = -EFBIG;
		goto out;
	}
	buffer = malloc((size_t)status.st_size + 1);
	if (!buffer) {
		err = -ENOMEM;
		goto out;
	}
	while (offset < (size_t)status.st_size) {
		ssize_t count = read(fd, buffer + offset,
				     (size_t)status.st_size - offset);

		if (count > 0) {
			offset += count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		err = count < 0 ? -errno : -EIO;
		free(buffer);
		goto out;
	}
	buffer[offset] = '\0';
	*text = buffer;
	*size = offset;
out:
	close(fd);
	return err;
}

static bool identifier_start(char character)
{
	return isalpha((unsigned char)character) || character == '_';
}

static bool identifier_character(char character)
{
	return isalnum((unsigned char)character) || character == '_';
}

static size_t duration_field_end(const char *text, size_t size, size_t start)
{
	size_t cursor = start + strlen("duration_ms");
	bool has_digit = false;

	while (cursor < size && isspace((unsigned char)text[cursor]))
		cursor++;
	if (cursor >= size || text[cursor] != ':')
		return 0;
	cursor++;
	while (cursor < size && isspace((unsigned char)text[cursor]))
		cursor++;
	if (cursor < size && (text[cursor] == '+' || text[cursor] == '-'))
		cursor++;
	if (cursor + 1 < size && text[cursor] == '0' &&
	    (text[cursor + 1] == 'x' || text[cursor + 1] == 'X')) {
		cursor += 2;
		while (cursor < size && isxdigit((unsigned char)text[cursor])) {
			has_digit = true;
			cursor++;
		}
	} else {
		while (cursor < size && isdigit((unsigned char)text[cursor])) {
			has_digit = true;
			cursor++;
		}
	}
	if (!has_digit || (cursor < size && identifier_character(text[cursor])))
		return 0;
	while (cursor < size &&
	       (text[cursor] == ' ' || text[cursor] == '\t' ||
		text[cursor] == '\r'))
		cursor++;
	if (cursor < size && (text[cursor] == ';' || text[cursor] == ','))
		cursor++;
	while (cursor < size &&
	       (text[cursor] == ' ' || text[cursor] == '\t' ||
		text[cursor] == '\r'))
		cursor++;
	return cursor;
}

static int write_without_top_level_duration(int fd, const char *text,
					    size_t size)
{
	enum scan_state state = SCAN_NORMAL;
	char quote = '\0';
	size_t cursor = 0, index = 0;
	unsigned int depth = 0;
	bool escaped = false;
	int err;

	while (index < size) {
		char character = text[index];

		if (state == SCAN_STRING) {
			if (escaped)
				escaped = false;
			else if (character == '\\')
				escaped = true;
			else if (character == quote)
				state = SCAN_NORMAL;
			index++;
			continue;
		}
		if (state == SCAN_LINE_COMMENT) {
			if (character == '\n')
				state = SCAN_NORMAL;
			index++;
			continue;
		}
		if (state == SCAN_BLOCK_COMMENT) {
			if (character == '*' && index + 1 < size &&
			    text[index + 1] == '/') {
				state = SCAN_NORMAL;
				index += 2;
			} else {
				index++;
			}
			continue;
		}

		if (character == '"' || character == '\'') {
			state = SCAN_STRING;
			quote = character;
			index++;
			continue;
		}
		if (character == '#') {
			state = SCAN_LINE_COMMENT;
			index++;
			continue;
		}
		if (character == '/' && index + 1 < size) {
			if (text[index + 1] == '/') {
				state = SCAN_LINE_COMMENT;
				index += 2;
				continue;
			}
			if (text[index + 1] == '*') {
				state = SCAN_BLOCK_COMMENT;
				index += 2;
				continue;
			}
		}
		if (character == '{' || character == '<') {
			depth++;
			index++;
			continue;
		}
		if (character == '}' || character == '>') {
			if (depth)
				depth--;
			index++;
			continue;
		}
		if (!depth && identifier_start(character)) {
			size_t identifier_end = index + 1;
			size_t field_end;

			while (identifier_end < size &&
			       identifier_character(text[identifier_end]))
				identifier_end++;
			if (identifier_end - index == strlen("duration_ms") &&
			    !memcmp(text + index, "duration_ms",
				    strlen("duration_ms")) &&
			    (field_end = duration_field_end(text, size, index))) {
				err = write_all(fd, text + cursor, index - cursor);
				if (err)
					return err;
				cursor = field_end;
				index = field_end;
				continue;
			}
			index = identifier_end;
			continue;
		}
		index++;
	}
	return write_all(fd, text + cursor, size - cursor);
}

int perfetto_config_write_custom(int output_fd, const char *input_path,
				 uint32_t duration_s, bool ring_buffer)
{
	char duration_line[64];
	char *text = NULL;
	size_t size = 0;
	int length, err;

	if (output_fd < 0 || !input_path || !duration_s)
		return -EINVAL;
	err = read_config(input_path, &text, &size);
	if (err)
		return err;
	if (!text || !size) {
		free(text);
		return -ENODATA;
	}
	err = write_without_top_level_duration(output_fd, text, size);
	if (err || ring_buffer)
		goto out;
	if (text[size - 1] != '\n') {
		err = write_all(output_fd, "\n", 1);
		if (err)
			goto out;
	}
	length = snprintf(duration_line, sizeof(duration_line),
			  "duration_ms: %llu\n",
			  ((unsigned long long)duration_s + 1) * 1000);
	if (length < 0 || length >= (int)sizeof(duration_line)) {
		err = -EOVERFLOW;
		goto out;
	}
	err = write_all(output_fd, duration_line, (size_t)length);
out:
	free(text);
	return err;
}
