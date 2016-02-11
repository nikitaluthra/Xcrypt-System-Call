#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include "xcipher.h"

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

static const char usage[] = "usage: %s -p password [-e/-d] inputfile outputfile\n";
static const char *optString = "p:edh";

/**
 * generate_key
 * @password: password from which key has to be generated
 *
 * A key is generated from password entered by user. It is directly stored in enc_key array in user_args_t struct instance
 *
 * Returns 0 on success; non-zero otherwise
 */
int generate_key(char *password)
{
	int iterations = 10000;
	int err;

	err = PKCS5_PBKDF2_HMAC_SHA1(password,
			       strlen(password),
			       NULL,
			       0,
			       iterations, 16,  user_args.enc_key);

	user_args.keylen = 16;
	return err;
}

/**
 * init_structure
 * Initializes user_args_t structure instance
 */
void init_structure(void)
{
	user_args.flags = -1;
	user_args.user_output_file = NULL;
	user_args.user_input_file = NULL;
}

/**
 * has_non_ascii_char
 * @str: string to check if it has non-ASCII character/s
 *
 * Determines if str has any non-ASCII character
 *
 * Returns 1 if any non-ASCII character found; else returns 0
 */
int has_non_ascii_char(const char *str)
{
	int i;
	for (i = 0; str[i]; i++)
		if (!isascii(str[i]))
			return 1;
	return 0;
}

/**
 * basic_validations
 * @password: password given by user
 * @argc: no of arguments passed on commandline
 * @p: pointer to array on which commandline arguments are stored
 *
 * Performs basic validations on user arguments
 *
 * Returns EXIT_FAILURE if any validation fails; zero otherwise
 */
int basic_validations(char *password, int argc, const char *p)
{
	int err;

	if (password == NULL) {
		fprintf(stderr,  usage,  p);
		goto ERR;
	}
	if (strlen(password) < 6) {
		fprintf(stderr,  "%s:password should have atleast 6 characters\n", p);
		goto ERR;
	}
	if (has_non_ascii_char(password)) {
		fprintf(stderr,  "%s:non-ascii character detected in password. Password should've valid ASCII character\n", p);
		goto ERR;
	}
	if (user_args.flags == -1) {
		fprintf(stderr,  "%s: missing -e/-d option\n",  p);
		fprintf(stderr,  usage,  p);
		goto ERR;
	}
	if ((optind+2) > argc || (argc-optind > 2)) {

		if (argc-optind == 1)
			fprintf(stderr,  "%s: missing output file\n", p);
		if (argc-optind == 0)
			fprintf(stderr,  "%s: missing input and output files\n", p);
		if (argc-optind > 2)
			fprintf(stderr,  "%s: only 1 inputfile and 1 outputfile allowed\n", p);
		fprintf(stderr,  usage,  p);
		goto ERR;
	}

	return EXIT_SUCCESS;
ERR:
	return EXIT_FAILURE;
}

/**
 * file_validations
 *
 * Performs validations related to the file entered by the user
 *
 * Returns EXIT_FAILURE if any validation fails; 0 otherwise
 */
int file_validations(void)
{
	int err;
	struct stat sb_in, sb_out;

	if (has_non_ascii_char(user_args.user_input_file)) {
		fprintf(stderr,  "non-ascii character detected in input file. input file should've valid ASCII character\n");
		goto ERR;
	}

	if (has_non_ascii_char(user_args.user_output_file)) {
		fprintf(stderr,  "non-ascii character detected in input file. input file should've valid ASCII character\n");
		goto ERR;
	}

	if (stat(user_args.user_input_file,  &sb_in) == -1) {
		fprintf(stderr, "input file could not be opened\n");
		goto ERR;
	}

	if (!S_ISREG(sb_in.st_mode)) {
		fprintf(stderr, "input file is not regular\n");
		err = -EINVAL;
		goto ERR;
	}

	if (!(sb_in.st_mode & S_IRUSR)) {
		fprintf(stderr, "no read permission for inp file\n");
		goto ERR;
	}

	if (stat(user_args.user_output_file,  &sb_out) != -1) {

		if (!S_ISREG(sb_out.st_mode)) {
			fprintf(stderr, "output file is not regular\n");
			goto ERR;
		}

		if (sb_in.st_ino == sb_out.st_ino) {
			fprintf(stderr, "input and output files have same inode\n");
			goto ERR;
		}

		if (!(sb_out.st_mode & S_IWUSR)) {
			fprintf(stderr, "output file does not have write access\n");
			goto ERR;
		}
	}
	return EXIT_SUCCESS;

ERR:
	return EXIT_FAILURE;
}

int main(int argc,  char **argv)
{
	int c = 0,  err,   rc = 0,  e_flag = 0, p_flag = 0, d_flag = 0;
	char *password = NULL;

	init_structure();

	while ((c = getopt(argc,  argv, optString)) != -1) {

		switch (c) {
		case 'p':
			if (p_flag == 0) {
				password = optarg;
				p_flag = 1;
			} else {
				fprintf(stderr,  "%s: You cannot use -p option more than once\n",  argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		case ':':
			fprintf(stderr,  "%s: -p  option requires argument\n",  argv[0]);
			break;
		case 'e':
			if (user_args.flags == -1 && e_flag == 0) {
				user_args.flags = 1;
				e_flag = 1;
			} else {
				if (e_flag == 1) {
					fprintf(stderr,  "%s: You can -e option only once\n",  argv[0]);
					fprintf(stderr, usage, argv[0]);
					exit(EXIT_FAILURE);
				}
				if (user_args.flags == 0)
					fprintf(stderr,  "%s: You can use only -e or -d option\n", argv[0]);
				fprintf(stderr, usage, argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		case 'd':
			if (user_args.flags == -1 && d_flag == 0) {
				user_args.flags = 1;
				d_flag = 1;
			} else {
				if (d_flag == 1) {
					fprintf(stderr,  "%s: You can -d option only once\n",  argv[0]);
					fprintf(stderr, usage, argv[0]);
					exit(EXIT_FAILURE);
				}
				if (user_args.flags == 1)
					fprintf(stderr,  "%s: You can use only -e or -d option\n", argv[0]);
				fprintf(stderr, usage, argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			fprintf(stderr, usage, argv[0]);
			exit(EXIT_FAILURE);
		case '?':
			fprintf(stderr,  usage,  argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	err = basic_validations(password, argc, argv[0]);
	if (err)
		return err;
	user_args.user_input_file = argv[optind++];
	user_args.user_output_file = argv[optind];
	err = file_validations();
	if (err)
		return err;
	if (!generate_key(password)) {
		fprintf(stderr,  "%s: failed to generate password\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	rc = syscall(__NR_xcrypt,  (void *)&user_args);
	if (rc == 0) {
		printf("syscall returned %d\n",  rc);
	} else {
		perror("Error");
		printf("syscall returned %d (errno=%d)\n", rc, errno);
	}
	exit(rc);
}
