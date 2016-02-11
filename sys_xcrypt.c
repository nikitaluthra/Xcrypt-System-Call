#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include "xcipher.h"

#define BUF_SIZE PAGE_SIZE

asmlinkage extern long (*sysptr)(void *arg);

struct file_struct {
	char create_out_file;
	umode_t out_file_mode;
	struct file *filp_in;
	struct file *filp_out;
	struct file *filp_temp;
	struct filename *in_file;
	struct filename *out_file;
};

/**
 * init_values
 * @f: pointer to file_struct struct to be initialized
 */
void init_values(struct file_struct *f)
{
	f->in_file = NULL;
	f->out_file = NULL;
	f->out_file_mode = 0;
	f->create_out_file = 'n';
}

/**
 * validate_in_out_file
 * @f: pointer to file_struct struct which contains information about files
 *
 * Validates the input and output file
 *
 * Returns zero on success; non-zero on error.
 */
int validate_in_out_file(struct file_struct *f)
{
	int err = 0, len;
	struct kstat stat_in, stat_out;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_stat(f->in_file->name, &stat_in);
	set_fs(old_fs);
	if (err) {
		printk(KERN_ALERT"error in vfs_stat for %s\n",  f->in_file->name);
		goto ERR;
	}
	if (!(S_ISREG(stat_in.mode))) {
		printk(KERN_ALERT"input file is not regular\n");
		err = -EINVAL;
		goto ERR;
	}
	if (!(stat_in.mode & S_IRUSR)) {
		printk(KERN_ALERT"no read permission for input file");
		err = -EACCES;
		goto ERR;
	}
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_stat(f->out_file->name, &stat_out);
	set_fs(old_fs);
	if (!err) {
		if (!S_ISREG(stat_out.mode)) {
			printk(KERN_ALERT"output file is not regular!");
			err = -EINVAL;
			goto ERR;
		}
		if (stat_in.ino == stat_out.ino) {
			printk(KERN_ALERT"same inode error!");
			err = -EINVAL;
			goto ERR;
		}
		if (!(stat_out.mode & S_IWUSR)) {
			printk(KERN_ALERT"no write access to op");
			err = -EACCES;
			goto ERR;
		}
		f->out_file_mode = stat_out.mode;
		printk(KERN_ALERT"=========file mode = %o\n",   f->out_file_mode);
		goto ERR;
	}
	len = strlen(f->out_file->name);
	if (f->out_file->name[len-1] == '/') {
		err = -EISDIR;
		goto ERR;
	}
	f->create_out_file = 'y';
	err = 0;
ERR:
	return err;
}

/**
 * read_from_file
 * @filp_in: pointer to input file from which data must be read
 * @buf: The buffer to read data into
 * @len: Length in bytes of data to be read into buf
 *
 * Reads len bytes of data from in buffer. Expects input file to be opened. Responsibility of closing the input file lies with the caller
 * who requested the handle
 *
 * Returns number of bytes read
 */
int read_from_file(struct file *filp_in, char *buf, int len)
{
	int bytes_read;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	bytes_read = vfs_read(filp_in, buf, len, &(filp_in->f_pos));
	set_fs(old_fs);
	return bytes_read;
}
/**
 * write_from_file
 * @filp_out: pointer to out file to which data must be written
 * @buf: The buffer to read data into
 * @len: Length in bytes of data to be read into buf
 *
 * Writes len bytes of data from buffer to the file pointed by filp_out. Expects filp_out to be opened. Responsibility of closing it lies
 * with the caller who requested the handle to filp_out
 *
 * Returns number of bytes written to the file
 */
int write_to_file(struct file *filp_out, char *buf, int len)
{
	int bytes_written;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	bytes_written = vfs_write(filp_out, buf, len, &(filp_out->f_pos));
	set_fs(old_fs);
	return bytes_written;
}

/* get_key_hash
 *
 * @enc_key: key of which the md5 hash has to be generated
 *
 * Returns the md5 hash of the key. Responsibility of freeing the hashed key lies with the caller who requested the hashed key.
 */
unsigned char *get_key_hash(unsigned char *enc_key)
{
	/* imp, plaintext should be array else getting sefault so copy key in array here */
	struct scatterlist sg;
	struct hash_desc desc;
	int i, err;
	unsigned char *hashed_key;
	unsigned char plaintext[AES_KEY_SIZE];

	for (i = 0; i < AES_KEY_SIZE; i++)
		plaintext[i] = enc_key[i];
	hashed_key = kmalloc(sizeof(char)*AES_KEY_SIZE, GFP_KERNEL);
	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(desc.tfm)) {
		err = PTR_ERR(desc.tfm);
		printk(KERN_ALERT"error in allocating hash");
		goto ERR;
	}
	desc.flags = 0;
	sg_init_one(&sg, plaintext, AES_KEY_SIZE);
	err = crypto_hash_init(&desc);
	if (err) {
		printk(KERN_ALERT"error in initializing crypto hash\n");
		goto ERR;
	}
	err = crypto_hash_update(&desc, &sg, AES_KEY_SIZE);
	if (err) {
		printk(KERN_ALERT"error in updating crypto hash\n");
		goto ERR;
	}
	printk(KERN_ALERT"cry[to hash updated\n");
	err = crypto_hash_final(&desc, hashed_key);
	if (err) {
		printk(KERN_ALERT"error in finalizing crypto hash\n");
		goto ERR;
	}
	crypto_free_hash(desc.tfm);
	return hashed_key;
ERR:
	if (desc.tfm)
		crypto_free_hash(desc.tfm);
	return ERR_PTR(err);
}

/**
 * handle_enc_dec
 * @f: pointer to file_struct struct which has all the information about input, temporary and output files
 * @buf: data which has to be encrypted or decrypted
 * @n_bytes: number of bytes to be encrypted or decrypted
 * @key: key used for encryption or decryption
 * @flags: encrypt or decrypt to indicate the desired operation
 *
 * Encrypts or decrypts the data as per the flags parameter. Resultant encrypted or decrypted data is stored in buf.This data is written
 * to temporary file. For encryption, the encrypted data is written to temporary file. For decryption, the decrypted data is written to
 * temporary file.
 *
 * Returns zero on success; non-zero otherwise;
 */
int handle_enc_dec(struct file_struct *f, unsigned char *buf, int n_bytes, char *key, int flags)
{

	int err = 0, i, temp;
	struct crypto_blkcipher *blkcipher = NULL;
	unsigned char aes_key[AES_KEY_SIZE];

	unsigned char iv[AES_KEY_SIZE] = "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";

	struct scatterlist sg;
	struct blkcipher_desc desc;

	if (n_bytes%AES_KEY_SIZE != 0) {
		printk(KERN_ALERT"size not multiple of 16 for encryption\n");
		err = -EINVAL;
		goto ERR;
	}
	for (i = 0 ; i < AES_KEY_SIZE ; i++)
		aes_key[i] = key[i];
	blkcipher = crypto_alloc_blkcipher("cbc(aes)",  0, 0);
	if (IS_ERR(blkcipher)) {
		printk(KERN_ALERT"could not allocate blkcipher handle for %s\n", "cbsaes");
		err = PTR_ERR(blkcipher);
		goto ERR;
	}

	if (crypto_blkcipher_setkey(blkcipher, aes_key, AES_KEY_SIZE)) {
		printk(KERN_ALERT"key could not be set\n");
		err = -EAGAIN;
		goto ERR;
	}

	crypto_blkcipher_set_iv(blkcipher, iv, AES_KEY_SIZE);

	desc.flags = 0;
	desc.tfm = blkcipher;
	sg_init_one(&sg, buf, n_bytes);
	printk(KERN_ALERT"sg iinited\n");
	/* encrypt data in place */
	if (flags == 1) {
		crypto_blkcipher_encrypt(&desc, &sg, &sg, n_bytes);

		printk(KERN_ALERT"encryption done\n");
	} else {
		crypto_blkcipher_decrypt(&desc, &sg, &sg, n_bytes);
		printk(KERN_ALERT"Decryption done\n");
	}

	printk(KERN_ALERT"printing enc/dec data\n");
	printk(KERN_ALERT"Cipher operation completed\n");

	temp = write_to_file(f->filp_temp, buf, n_bytes);

	if (blkcipher)
		crypto_free_blkcipher(blkcipher);

	err = 0;

ERR:
	return err;
}

/**
 * get_file_handle
 * @f: pointer to struct which contains information about input,temporary and output files
 * @file_name: file name to be opened
 * @flags: access mode of file (e.g O_RDONLY,O_WRONLY) and file creation flags (O_CREAT etc)
 * @mode: mode of file incase it has to be created. Is used when O_CREAT is specified in flags
 *
 * Opens the file as per flags and mode given. Responsibility of closing the file lies with the caller who invoked this function
 *
 * Returns zero on success; non-zero otherwise
 */
int get_file_handle(struct file **f, const char *file_name, int flags, umode_t mode)
{
	printk(KERN_ALERT"file %s  will be opened with mode %o\n", file_name, mode);
	*f  = filp_open(file_name, flags, mode);
	if (!(*f) || IS_ERR(*f)) {
		printk(KERN_ALERT"Files %s does not exist\n", file_name);
		return PTR_ERR(*f);
	}
	printk(KERN_ALERT"opened file %s\n", file_name);
	return 0;
}

/**
 * encrypt
 * @f: pointer to struct which contains information about input,temporary and output files
 * @key_hash: MD5 of key created from password given by user
 * @user_args: pointer to struct user_args_t which contains arguments given by user in user-space
 *
 * Encrypts the data in multiples of block size of aes (16 bytes). Adds padding if necessary.
 *
 * Returns 0 on success; non-zero otherwise
 */
int encrypt(struct file_struct *f, unsigned char *key_hash, struct user_args_t *user_args)
{
	int err, temp;
	unsigned int last_bytes, enc_in_loop, padding_size, inp_file_size;
	unsigned char buf[BUF_SIZE];
	int bytes_read;
	unsigned char pad[AES_KEY_SIZE], c[1];

	inp_file_size = f->filp_in->f_inode->i_size;
	printk(KERN_ALERT"inp fle size = %u\n", inp_file_size);
	last_bytes = inp_file_size > BUF_SIZE ? inp_file_size % BUF_SIZE : 0;
	printk(KERN_ALERT"last bytes you'll read = %u\n", last_bytes);
	enc_in_loop = inp_file_size / BUF_SIZE;

	padding_size = ((inp_file_size + 15) & -AES_KEY_SIZE) - inp_file_size;

	if (inp_file_size == 0)
		padding_size = 0x10;
	memset(pad, padding_size, padding_size);

	printk(KERN_ALERT"padding required = %u\n", padding_size);


	printk(KERN_ALERT"out of hashing\n");

	c[0] = padding_size;
	f->filp_temp->f_pos = 0;

	temp = write_to_file(f->filp_temp, c, 1);
	temp = write_to_file(f->filp_temp, &key_hash[0], AES_KEY_SIZE);
	bytes_read = 0;
	f->filp_in->f_pos = 0;

	if (inp_file_size < BUF_SIZE) {
		printk(KERN_ALERT" inp size <= page size so read it all\n");
		bytes_read = read_from_file(f->filp_in, buf, BUF_SIZE);
		printk(KERN_ALERT"in first if, just read %u bytes\n", bytes_read);
	} else {
		while (enc_in_loop) {

			bytes_read = read_from_file(f->filp_in, buf, BUF_SIZE);
			err = handle_enc_dec(f, buf, BUF_SIZE, user_args->enc_key, user_args->flags);
			--enc_in_loop;
			if (err) {
				printk(KERN_ALERT"error in encryption\n");
				goto ERR;
			}

		}

	}

	if (inp_file_size != 0 && inp_file_size % BUF_SIZE == 0) {
		err = 0;
		printk(KERN_ALERT"file size is multiple of buf_size!\n");
		goto ERR;
	}

	if (last_bytes) {

		bytes_read = read_from_file(f->filp_in, buf, last_bytes);
		printk(KERN_ALERT"read remaining %u bytes\n", bytes_read);

	}

	if (padding_size)
		memcpy(buf+bytes_read, pad, padding_size);

	printk(KERN_ALERT"finished padding : ");

	printk(KERN_ALERT"Sending %d bytes to be encrypted\n", bytes_read+padding_size);

	err = handle_enc_dec(f, buf, bytes_read+padding_size, user_args->enc_key, user_args->flags);
	if (err) {
		printk(KERN_ALERT"error in encryption\n");
		goto ERR;
	}

	printk(KERN_ALERT"temp bytes writted %d\n", temp);
	err = 0;


ERR:
	return err;
}

/**
 * decrypt
 * @f: pointer to struct which contains information about input,temporary and output files
 * @key_hash: MD5 of key created from password given by user
 * @user_args: pointer to struct user_args_t which contains arguments given by user in user-space
 *
 * Decrypts the data in multiples of block size of aes (16 bytes). Truncates the data if padding was added.
 *
 * Returns 0 on success; non-zero otherwise
 */
int decrypt(struct file_struct *f, unsigned char *key_hash, struct user_args_t *user_args)
{
	int err, i;
	unsigned int bytes_to_decrypt, last_bytes, dec_in_loop, padding_size, inp_file_size;
	unsigned char buf[BUF_SIZE];
	int bytes_read;

	bytes_read = read_from_file(f->filp_in, buf, 17);
	printk(KERN_ALERT"decryption bytes read = %u\n", bytes_read);

	for (i = 0 ; i < AES_KEY_SIZE ; i++) {
		if (key_hash[i] != buf[i+1]) {

			printk(KERN_ALERT"invalid password to decrypt\n");
			err = -EACCES;
			goto ERR;
		}
	}

	padding_size = (int) buf[0];
	printk(KERN_ALERT"padding size = %d\n", padding_size);
	f->filp_temp->f_pos = 0;
	inp_file_size = f->filp_in->f_inode->i_size - 17;
	printk(KERN_ALERT"inp file size = %u\n", inp_file_size);
	dec_in_loop = inp_file_size/BUF_SIZE;
	last_bytes = inp_file_size > BUF_SIZE ? inp_file_size % BUF_SIZE : 0;
	memset(buf, 0, BUF_SIZE);


	if (inp_file_size < BUF_SIZE) {

		bytes_read = read_from_file(f->filp_in, buf, inp_file_size);
		bytes_to_decrypt = inp_file_size;
		err = handle_enc_dec(f, buf, bytes_to_decrypt, user_args->enc_key, user_args->flags);
		vfs_truncate(&(f->filp_temp->f_path), inp_file_size-padding_size);
		goto ERR;
	} else {

		while (dec_in_loop) {

			bytes_read = read_from_file(f->filp_in, buf, BUF_SIZE);
			err = handle_enc_dec(f, buf, BUF_SIZE, user_args->enc_key, user_args->flags);
			--dec_in_loop;
			if (err) {
				printk(KERN_ALERT"error in encryption\n");
				goto ERR;
			}

		}


	}

	if (inp_file_size != 0 && inp_file_size % BUF_SIZE == 0) {
		err = 0;
		vfs_truncate(&(f->filp_temp->f_path), inp_file_size-padding_size);
		goto ERR;
	}
	if (last_bytes) {

		bytes_read = read_from_file(f->filp_in, buf, last_bytes);
		printk(KERN_ALERT"read remaining %u bytes\n", bytes_read);

	}
	printk(KERN_ALERT" decryption last %u bytes\n", last_bytes);
	err = handle_enc_dec(f, buf, last_bytes, user_args->enc_key, user_args->flags);
	if (err) {
		printk(KERN_ALERT"error in decryption\n");
		goto ERR;
	}
	vfs_truncate(&(f->filp_temp->f_path), inp_file_size-padding_size);
ERR:
	return err;


}

/**
 * main_enc_dec
 * @f: pointer to struct which contains information about input,temporary and output files
 * @user_args: pointer to struct user_args_t which contains arguments given by user in user-space
 *
 * Initiates basic validation checks to be performed before starting encryption/decryption. Gets the required file handles. Post encryption
 * or decryption, renames and unlinks the file as required.
 *
 * Returns 0 on success;non-zero otherwise
 */
int main_enc_dec(struct file_struct *f, struct user_args_t *user_args)
{
	int err, tmp_err;

	char *key_hash;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct dentry *trap = NULL;

	err = validate_in_out_file(f);
	f->filp_in = f->filp_out = f->filp_temp = NULL;
	if (err) {
		printk(KERN_ALERT"error in validate in out");
		goto ERR;
	}

	key_hash = get_key_hash(user_args->enc_key);
	if (IS_ERR(key_hash)) {
		err = PTR_ERR(key_hash);
		goto ERR;
	}

	err = get_file_handle(&(f->filp_in), f->in_file->name, O_RDONLY, 0);
	if (err)
		goto ERR_KEY;

	if (!(f->filp_in->f_op->read)) {
		printk(KERN_ALERT"read operation not supported\n");
		err = -EPERM;
		goto ERR_IN;
	}

	printk(KERN_ALERT"read file permission\n");

	if (f->create_out_file == 'y') {
		printk(KERN_ALERT"file with default permission\n");
		err = get_file_handle(&(f->filp_temp), "/tmp/my_temp_file", O_WRONLY|O_CREAT|O_TRUNC, 0666-current_umask());
	} else {
		printk(KERN_ALERT"creating file with outfile mode\n");
		err = get_file_handle(&(f->filp_temp), "/tmp/my_temp_file", O_WRONLY|O_CREAT|O_TRUNC, f->out_file_mode);
	}

	if (err)
		goto ERR_IN;

	printk(KERN_ALERT"file permission for temp file=\n");
	printk(KERN_ALERT"\n");

	if (user_args->flags == 1)
		err = encrypt(f, &key_hash[0], user_args);
	else
		err = decrypt(f, &key_hash[0], user_args);


	if (err) {
		tmp_err = err;
		err = vfs_unlink(d_inode(f->filp_temp->f_path.dentry->d_parent), f->filp_temp->f_path.dentry, NULL);
		if (err)
			printk(KERN_ALERT"Error in unlink\n");
		err = tmp_err;
		goto ERR_IN;
	}
	printk(KERN_ALERT"enc/dec done so now doing a rename\n");

	if (f->create_out_file == 'y')
		err = get_file_handle(&(f->filp_out), f->out_file->name, O_WRONLY|O_CREAT|O_TRUNC, 0666-current_umask());
	else
		err = get_file_handle(&(f->filp_out), f->out_file->name, O_WRONLY, 0);

	if (err)
		goto ERR_OUT;

	if (!(f->filp_out->f_op->write)) {
		printk(KERN_ALERT"write operation not supported\n");
		err = -EPERM;
		goto ERR;
	}
	lower_old_dentry = f->filp_temp->f_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dentry = f->filp_out->f_path.dentry;
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			d_inode(lower_new_dir_dentry), lower_new_dentry,
			NULL, 0);
	if (err) {
		printk(KERN_ALERT"error in rename\n");
		tmp_err = err;

		err = vfs_unlink(d_inode(f->filp_temp->f_path.dentry->d_parent), f->filp_temp->f_path.dentry, NULL);
		if (err)
			printk(KERN_ALERT"Error in unlink\n");

		if (f->create_out_file == 'y') {
			err = vfs_unlink(d_inode(f->filp_temp->f_path.dentry->d_parent), f->filp_temp->f_path.dentry, NULL);
			if (err)
				printk(KERN_ALERT"Error in unlink\n");
		}
		err = tmp_err;

	}
	printk(KERN_ALERT"rename done!\n");

	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	if (f->filp_temp)
		filp_close(f->filp_temp, NULL);

ERR_OUT:
	if (f->filp_out)
		filp_close(f->filp_out, NULL);
ERR_IN:
	if (f->filp_in)
		filp_close(f->filp_in, NULL);
ERR_KEY:
	kfree(key_hash);
ERR:
	return err;

}

/**
 * validate_user_args
 * @user_args: pointer to struct user_args_t which contains arguments given by user in user-space
 *
 * Validates parameters given by the user
 *
 * Returns 0 on success;non-zero otherwise
 */
int validate_user_args(struct user_args_t *user_args)
{
	int err = -EINVAL;

	printk(KERN_ALERT"key len = %d\n", user_args->keylen);
	if (user_args->keylen != AES_KEY_SIZE) {
		printk(KERN_ALERT"Keylen should be 16\n");
		goto ERR;
	}

	if (!user_args->user_input_file) {
		printk(KERN_ALERT"input file cannot be empty\n");
		goto ERR;
	}

	if (!user_args->user_output_file) {
		printk(KERN_ALERT"output file cannot be empty\n");
		goto ERR;
	}
	err = 0;

ERR:
	return err;


}

asmlinkage long xcrypt(void *arg)
{
	struct file_struct file_info;
	struct user_args_t *user_args;
	int err = 0;

	init_values(&file_info);

	if (arg == NULL) {
		printk(KERN_ALERT"NULL arg received in syscall\n");
		err = -EINVAL;
		goto ERR;
	}

	user_args = kmalloc(sizeof(struct user_args_t), GFP_KERNEL);
	if (!user_args) {
		printk(KERN_ALERT"Couldn't allocate memory for user struct\n");
		err = -ENOMEM;
		goto ERR;
	}

	printk(KERN_ALERT"flag = %d and keylen = %d\n", user_args->flags, user_args->keylen);
	printk(KERN_ALERT"all validations passed\n");
	if (copy_from_user(user_args, arg, sizeof(struct user_args_t))) {
		printk(KERN_ALERT"error in copy from user\n");
		err = -EFAULT;
		goto ERR_FREE;
	}

	err = validate_user_args(user_args);
	if (err)
		goto ERR_FREE;
	file_info.in_file = getname(user_args->user_input_file);
	if (IS_ERR(file_info.in_file)) {
		printk(KERN_ALERT"error in file input getname\n");
		err = PTR_ERR(file_info.in_file);
		goto ERR_FREE;
	}
	printk(KERN_ALERT"getnamed inp file is %s\n",  file_info.in_file->name);

	file_info.out_file = getname(user_args->user_output_file);
	if (IS_ERR(file_info.out_file)) {
		printk(KERN_ALERT"error in file output getname\n");
		err = PTR_ERR(file_info.out_file);
		goto ERR_FREE;
	}


	printk(KERN_ALERT"getnamed out file is %s\n", file_info.out_file->name);
	printk(KERN_ALERT"flag = %d and keylen = %d\n", user_args->flags, user_args->keylen);

	err = main_enc_dec(&file_info, user_args);
	if (err) {
		printk(KERN_ALERT"got error from main_enc_dec\n");
		goto ERR_FREE;
	}
	err = 0;
ERR_FREE:
	kfree(user_args);
ERR:
	printk(KERN_ALERT"Returning %d\n", err);
	return err;
}

static int __init init_sys_xcrypt(void)
{
	printk(KERN_ALERT"installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
earstatic void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk(KERN_ALERT"removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
