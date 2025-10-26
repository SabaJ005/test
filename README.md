// encdev.c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ioctl.h>

#include "encdev_ioctl.h"

#define DEVICE_NAME "encdev"
MODULE_LICENSE("GPL");

static int major_number;
static char* kernel_buffer = NULL;
static size_t buffer_size = 0;
static bool is_enabled = true;

static char default_key[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
static size_t default_key_len = sizeof(default_key);

static char* current_key = NULL;
static size_t current_key_len = 0;

static int     encdev_open(struct inode *, struct file *);
static int     encdev_release(struct inode *, struct file *);
static ssize_t encdev_read(struct file *, char *, size_t, loff_t *);
static ssize_t encdev_write(struct file *, const char *, size_t, loff_t *);
static long    encdev_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations fops = {
   .open = encdev_open,
   .read = encdev_read,
   .write = encdev_write,
   .release = encdev_release,
   .unlocked_ioctl = encdev_ioctl,
};

static void do_reset(void) {
    printk(KERN_INFO "EncDev: Resetting module state.\n");
    if (kernel_buffer) {
        kfree(kernel_buffer);
        kernel_buffer = NULL;
        buffer_size = 0;
    }
    if (current_key) {
        kfree(current_key);
    }
    current_key = kmalloc(default_key_len, GFP_KERNEL);
    if (current_key) {
        memcpy(current_key, default_key, default_key_len);
        current_key_len = default_key_len;
    } else {
        printk(KERN_ALERT "EncDev: Failed to allocate memory for default key on reset.\n");
        current_key_len = 0;
    }
}

static int __init encdev_init(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "EncDev: failed to register a major number\n");
        return major_number;
    }
    
    current_key = kmalloc(default_key_len, GFP_KERNEL);
    if (!current_key) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return -ENOMEM;
    }
    memcpy(current_key, default_key, default_key_len);
    current_key_len = default_key_len;

    printk(KERN_INFO "EncDev: module loaded with major number %d\n", major_number);
    return 0;
}

static void __exit encdev_exit(void) {
    if (kernel_buffer) kfree(kernel_buffer);
    if (current_key) kfree(current_key);
    
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "EncDev: module unloaded.\n");
}

static int encdev_open(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "EncDev: Device opened.\n");
   return 0;
}

static int encdev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "EncDev: Device closed.\n");
   return 0;
}

static ssize_t encdev_write(struct file *filep, const char *user_buffer, size_t len, loff_t *offset){
    int i;
    if (!is_enabled) {
        printk(KERN_WARNING "EncDev: Write attempt while disabled.\n");
        return -EPERM;
    }
    if (kernel_buffer) kfree(kernel_buffer);
    kernel_buffer = kmalloc(len, GFP_KERNEL);
    if (!kernel_buffer) return -ENOMEM;
    buffer_size = len;
    if (copy_from_user(kernel_buffer, user_buffer, len)) {
        kfree(kernel_buffer);
        return -EFAULT;
    }
    for (i = 0; i < len; i++) {
        kernel_buffer[i] ^= current_key[i % current_key_len];
    }
    return len;
}

static ssize_t encdev_read(struct file *filep, char *user_buffer, size_t len, loff_t *offset) {
    if (!is_enabled) {
        printk(KERN_WARNING "EncDev: Read attempt while disabled.\n");
        return -EPERM;
    }
    if (buffer_size == 0) return 0;
    size_t bytes_to_read = (len < buffer_size) ? len : buffer_size;
    if (copy_to_user(user_buffer, kernel_buffer, bytes_to_read)) {
        return -EFAULT;
    }
    return bytes_to_read;
}

static long encdev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case ENCDEV_ENABLE:
            is_enabled = true;
            printk(KERN_INFO "EncDev: Module ENABLED.\n");
            return 0;
        case ENCDEV_DISABLE:
            is_enabled = false;
            printk(KERN_INFO "EncDev: Module DISABLED.\n");
            return 0;
    }

    if (!is_enabled) {
        printk(KERN_WARNING "EncDev: IOCTL command blocked (module disabled).\n");
        return -EPERM;
    }switch (cmd) {
        case ENCDEV_RESET:
            do_reset();
            printk(KERN_INFO "EncDev: Module RESET.\n");
            break;
        case ENCDEV_SETKEY: {
            encdev_key_data_t key_data;
            char* new_key;
            if (copy_from_user(&key_data, (encdev_key_data_t *)arg, sizeof(key_data))) {
                return -EFAULT;
            }
            if (key_data.len < MIN_KEY_LEN || key_data.len > MAX_KEY_LEN) {
                printk(KERN_WARNING "EncDev: SetKey failed, invalid key length (%zu).\n", key_data.len);
                return -EINVAL;
            }
            new_key = kmalloc(key_data.len, GFP_KERNEL);
            if (!new_key) return -ENOMEM;
            memcpy(new_key, key_data.key, key_data.len);
            if (current_key) kfree(current_key);
            current_key = new_key;
            current_key_len = key_data.len;
            printk(KERN_INFO "EncDev: New key set with length %zu.\n", current_key_len);
            break;
        }
        default:
            return -ENOTTY;
    }
    return 0;
}
