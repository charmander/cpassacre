#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <termios.h>
#include "keccak/KeccakSponge.h"

struct password_base {
	size_t option_count;
	const char* options;
	struct password_base* next;
};

struct password_scheme {
	int error;
	unsigned int iterations;
	struct password_base* last_base;
};

struct password_character {
	char value;
	struct password_character* next;
};

int password_scheme_add(struct password_scheme* scheme, size_t count, const char* character_set) {
	for (size_t i = 0; i < count; i++) {
		struct password_base* new_base = malloc(sizeof(struct password_base));

		if (new_base == NULL) {
			return 1;
		}

		size_t option_count = strlen(character_set);

		if (option_count == 0) {
			free(new_base);
			fputs("A character set cannot be empty.\n", stderr);
			return 1;
		}

		new_base->option_count = option_count;
		new_base->options = character_set;
		new_base->next = scheme->last_base;

		scheme->last_base = new_base;
	}

	return 0;
}

#include "config.h"

size_t bytes_required_for(const struct password_base* last_base) {
	float bytes = 0.0f;

	while (last_base != NULL) {
		bytes += log2f(last_base->option_count) / 8.0f;
		last_base = last_base->next;
	}

	return (size_t)ceil(bytes);
}

unsigned char* upper_bound_for(const struct password_base* last_base, size_t bytes_required) {
	unsigned char* result = malloc(bytes_required);

	if (result == NULL) {
		return NULL;
	}

	memset(result, 0, bytes_required);
	result[bytes_required - 1] = 1;

	while (last_base != NULL) {
		int carry = 0;

		for (ssize_t i = bytes_required - 1; i >= 0; i--) {
			int r = result[i] * last_base->option_count + carry;
			result[i] = r % 256;
			carry = r / 256;
		}

		if (carry != 0) {
			fputs("Incorrect byte count. Something has gone terribly wrong.\n", stderr);
			return NULL;
		}

		last_base = last_base->next;
	}

	return result;
}

// Divide bytes (stored big-endian) by divisor and return the remainder.
int long_divide(unsigned char* bytes, int divisor, size_t byte_count) {
	int carry = 0;

	for (size_t i = 0; i < byte_count; i++) {
		int b = 256 * carry + bytes[i];

		bytes[i] = b / divisor;
		carry = b % divisor;
	}

	return carry;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		fputs("Usage: cpassacre <site name>\n", stderr);
		return 1;
	}

	char* sitename = argv[1];

	struct password_scheme scheme = scheme_for(sitename);

	if (scheme.error) {
		fputs("Failed to get scheme.\n", stderr);
		return 1;
	}

	size_t output_bytes_required = bytes_required_for(scheme.last_base);

	if (output_bytes_required > 1024) {
		fputs("The maximum password entropy is 8192 bits.\n", stderr);
	}

	spongeState state;

	if (InitSponge(&state, 64, 1536) != 0) {
		fputs("Failed to initialize sponge.\n", stderr);
		return 1;
	}

	struct termios original_termios, modified_termios;
	int termattr_result = tcgetattr(STDIN_FILENO, &original_termios);

	if (termattr_result == 0) {
		modified_termios = original_termios;
		modified_termios.c_lflag &= ~ECHO;
		termattr_result = tcsetattr(STDIN_FILENO, TCSAFLUSH, &modified_termios);
	}

	fputs("Password: ", stderr);

	unsigned char input[1024];

	int read_failed = (fgets((char*)input, sizeof input, stdin) == NULL);

	if (termattr_result == 0) {
		putc('\n', stderr);
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios);
	}

	if (read_failed) {
		if (!feof(stdin)) {
			fputs("Failed to read password.\n", stderr);
			return 1;
		}

		input[0] = '\0';
	}

	size_t input_length = strlen((char*)input);

	if (input[input_length - 1] == '\n') {
		input_length--;
	} else if (input_length > 1022) {
		/* Avoid silent truncation at 1023 characters */
		fputs("The maximum password length is 1022 characters.\n", stderr);
		return 1;
	}

	input[input_length] = ':';

	if (Absorb(&state, input, (input_length + 1) * 8) != 0 ||
			Absorb(&state, (unsigned char*)sitename, strlen(sitename) * 8) != 0) {
		fputs("Failed to absorb into sponge.\n", stderr);
		return 1;
	}

	memset(input, 0, sizeof input);

	for (unsigned int i = 0; i < scheme.iterations; i++) {
		if (Absorb(&state, input, sizeof input * 8) != 0) {
			fputs("Failed to absorb into sponge.\n", stderr);
			return 1;
		}
	}

	struct password_base* last_base = scheme.last_base;
	unsigned char* upper_bound = upper_bound_for(last_base, output_bytes_required);

	if (upper_bound == NULL) {
		fputs("Failed to allocate memory for upper bound.\n", stderr);
		return 1;
	}

	do {
		if (Squeeze(&state, input, output_bytes_required * 8) != 0) {
			fputs("Failed to squeeze out of sponge.\n", stderr);
			return 1;
		}
	} while (memcmp(input, upper_bound, output_bytes_required) >= 0);

	free(upper_bound);

	struct password_character result_tail = {
		.next = NULL
	};

	struct password_character* result_head = &result_tail;
	struct password_character* result_next;

	while (last_base != NULL) {
		int c = long_divide(input, last_base->option_count, output_bytes_required);

		result_next = malloc(sizeof(struct password_character));
		if (result_next == NULL) {
			fputs("Failed to allocate memory.\n", stderr);
			return 1;
		}

		result_next->value = last_base->options[c];
		result_next->next = result_head;
		result_head = result_next;

		struct password_base* next = last_base->next;
		free(last_base);
		last_base = next;
	}

	while ((result_next = result_head->next)) {
		putchar(result_head->value);
		free(result_head);
		result_head = result_next;
	}

	putchar('\n');

	return 0;
}
