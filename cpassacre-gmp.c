#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <gmp.h>
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

		new_base->option_count = strlen(character_set);
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

mpz_t* upper_bound_for(const struct password_base* last_base) {
	mpz_t* result = malloc(sizeof(mpz_t));

	if (result == NULL) {
		return NULL;
	}

	mpz_init(*result);
	mpz_set_ui(*result, 1);

	while (last_base != NULL) {
		mpz_mul_ui(*result, *result, last_base->option_count);
		last_base = last_base->next;
	}

	return result;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage:  %s <site name>\n", argv[0]);
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

	mpz_t* upper_bound = upper_bound_for(scheme.last_base);

	if (upper_bound == NULL) {
		fputs("Failed to create GMP integer.\n", stderr);
		return 1;
	}

	mpz_t current_value;
	mpz_init(current_value);

	do {
		if (Squeeze(&state, input, output_bytes_required * 8) != 0) {
			fputs("Failed to squeeze out of sponge.\n", stderr);
			return 1;
		}

		mpz_import(current_value, output_bytes_required, 1, 1, 0, 0, input);
	} while (mpz_cmp(current_value, *upper_bound) > 0);

	mpz_clear(*upper_bound);
	free(upper_bound);

	struct password_base* last_base = scheme.last_base;
	mpz_t digit;
	mpz_init(digit);

	struct password_character result_tail = {
		.next = NULL
	};

	struct password_character* result_head = &result_tail;
	struct password_character* result_next;

	while (mpz_sgn(current_value) != 0) {
		mpz_fdiv_qr_ui(current_value, digit, current_value, last_base->option_count);

		result_next = malloc(sizeof(struct password_character));

		if (result_next == NULL) {
			fputs("Failed to allocate memory.\n", stderr);
			return 1;
		}

		result_next->value = last_base->options[mpz_get_ui(digit)];
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

	mpz_clear(current_value);
	mpz_clear(digit);

	return 0;
}
