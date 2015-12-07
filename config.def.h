#define CS_DIGIT "0123456789"
#define CS_LOWERCASE "abcdefghijklmnopqrstuvwxyz"
#define CS_UPPERCASE "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CS_SYMBOLS "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
#define CS_LETTER CS_LOWERCASE CS_UPPERCASE
#define CS_ALPHANUMERIC CS_DIGIT CS_LETTER
#define CS_PRINTABLE CS_ALPHANUMERIC CS_SYMBOLS

#define SCHEME_ADD(count, character_set) if (password_scheme_add(&scheme, count, character_set) != 0) { scheme.error = 1; return scheme; }

static struct password_scheme scheme_for(const char* const sitename) {
	struct password_scheme scheme;
	memset(&scheme, 0, sizeof scheme);
	(void)sitename;

	scheme.iterations = 10000;

	/*
	if (strcmp(sitename, "example") == 0) {
		scheme.iterations += 5; // Equivalent of increment
	} else if (strcmp(sitename, "foo") == 0) {
		SCHEME_ADD(16, CS_ALPHANUMERIC)
		return scheme;
	}
	*/

	SCHEME_ADD(32, CS_PRINTABLE)
	return scheme;
}
