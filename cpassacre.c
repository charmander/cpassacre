#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <termios.h>
#include "keccak/KeccakSponge.h"

struct password_base {
	struct password_base* next;
	const char* options;
	unsigned int option_count;
};

struct password_scheme {
	struct password_base* last_base;
	size_t length;
	int error;
	unsigned int iterations;
};

static int password_scheme_add(struct password_scheme* const scheme, size_t const count, char const* const character_set) {
	for (size_t i = 0; i < count; i++) {
		struct password_base* const new_base = malloc(sizeof(struct password_base));

		if (new_base == NULL) {
			return 1;
		}

		size_t const option_count = strlen(character_set);

		if (option_count == 0) {
			free(new_base);
			fputs("A character set cannot be empty.\n", stderr);
			return 1;
		}

		if (option_count > 256) {
			free(new_base);
			fputs("A character set cannot contain more than 256 characters.\n", stderr);
			return 1;
		}

		new_base->option_count = (unsigned int)option_count;
		new_base->options = character_set;
		new_base->next = scheme->last_base;

		scheme->last_base = new_base;
	}

	scheme->length += count;

	return 0;
}

static char* password_read(char* const s, size_t const size) {
	struct termios original_termios;
	int termattr_result = tcgetattr(STDIN_FILENO, &original_termios);

	if (termattr_result == 0) {
		struct termios modified_termios = original_termios;
		modified_termios.c_lflag &= ~(unsigned int)ECHO;
		termattr_result = tcsetattr(STDIN_FILENO, TCSAFLUSH, &modified_termios);
	}

	fputs("Password: ", stderr);

	char* const result = fgets(s, (int)size, stdin);

	if (termattr_result == 0) {
		putc('\n', stderr);
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios);
	}

	return result;
}

#include "config.h"

static size_t bytes_required_for(struct password_base const* last_base) {
	float bytes = 0.0f;

	while (last_base != NULL) {
		bytes += log2f(last_base->option_count) / 8.0f;
		last_base = last_base->next;
	}

	return (size_t)(ceilf(bytes));
}

static unsigned char* upper_bound_for(struct password_base const* last_base, size_t const bytes_required) {
	unsigned char* const result = malloc(bytes_required);

	if (result == NULL) {
		return NULL;
	}

	memset(result, 0, bytes_required);
	result[bytes_required - 1] = 1;

	while (last_base != NULL) {
		unsigned int carry = 0;

		for (size_t i = bytes_required; i-- > 0;) {
			unsigned int const r = result[i] * last_base->option_count + carry;
			result[i] = (unsigned char)(r % 256);
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

static unsigned int long_divide(unsigned char* const bytes, unsigned int const divisor, size_t const byte_count) {
	unsigned int carry = 0;

	for (size_t i = 0; i < byte_count; i++) {
		unsigned int const b = 256 * carry + bytes[i];

		bytes[i] = (unsigned char)(b / divisor);
		carry = b % divisor;
	}

	return carry;
}

int main(int const argc, char const* const argv[]) {
	if (argc != 2) {
		fputs("Usage: cpassacre <site name>\n", stderr);
		return EXIT_FAILURE;
	}

	char const* const sitename = argv[1];

	struct password_scheme const scheme = scheme_for(sitename);

	if (scheme.error) {
		fputs("Failed to get scheme.\n", stderr);
		return EXIT_FAILURE;
	}

	size_t const output_bytes_required = bytes_required_for(scheme.last_base);

	if (output_bytes_required > 1024) {
		fputs("The maximum password entropy is 8192 bits.\n", stderr);
		return EXIT_FAILURE;
	}

	spongeState state;

	if (InitSponge(&state, 64, 1536) != 0) {
		fputs("Failed to initialize sponge.\n", stderr);
		return EXIT_FAILURE;
	}

	unsigned char input[1024];

	if (password_read((char*)input, sizeof input) == NULL) {
		if (!feof(stdin)) {
			fputs("Failed to read password.\n", stderr);
			return EXIT_FAILURE;
		}

		input[0] = '\0';
	}

	size_t input_length = strlen((char*)input);

	if (input[input_length - 1] == '\n') {
		input_length--;
	} else if (input_length > 1022) {
		/* Avoid silent truncation at 1023 characters */
		fputs("The maximum password length is 1022 characters.\n", stderr);
		return EXIT_FAILURE;
	}

	input[input_length] = ':';

	if (Absorb(&state, input, (input_length + 1) * 8) != 0 ||
			Absorb(&state, (unsigned char const*)sitename, strlen(sitename) * 8) != 0) {
		fputs("Failed to absorb into sponge.\n", stderr);
		return EXIT_FAILURE;
	}

	memset(input, 0, sizeof input);

	for (unsigned int i = 0; i < scheme.iterations; i++) {
		if (Absorb(&state, input, sizeof input * 8) != 0) {
			fputs("Failed to absorb into sponge.\n", stderr);
			return EXIT_FAILURE;
		}
	}

	struct password_base* last_base = scheme.last_base;

	{
		unsigned char* const upper_bound = upper_bound_for(last_base, output_bytes_required);

		if (upper_bound == NULL) {
			fputs("Failed to allocate memory for upper bound.\n", stderr);
			return EXIT_FAILURE;
		}

		do {
			if (Squeeze(&state, input, output_bytes_required * 8) != 0) {
				fputs("Failed to squeeze out of sponge.\n", stderr);
				return EXIT_FAILURE;
			}
		} while (memcmp(input, upper_bound, output_bytes_required) >= 0);

		free(upper_bound);
	}

	char* const result = malloc(scheme.length + 1);

	if (result == NULL) {
		fputs("Failed to allocate memory.\n", stderr);
		return EXIT_FAILURE;
	}

	char* current = result + scheme.length;
	*current = '\0';

	while (last_base != NULL) {
		unsigned int const c = long_divide(input, last_base->option_count, output_bytes_required);
		*--current = last_base->options[c];

		struct password_base* const next = last_base->next;
		free(last_base);
		last_base = next;
	}

	puts(result);

	free(result);
	return EXIT_SUCCESS;
}
